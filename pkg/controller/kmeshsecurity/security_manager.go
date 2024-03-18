/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kmeshsecurity

import (
	"sync"
	"time"

	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/workloadapi"
	"kmesh.net/kmesh/pkg/logger"
)
	
var certs_maps sync.Map
var log = logger.NewLoggerField("kmeshsecurity")

type SecretManagerClient struct {
	caClient *CitadelClient

	// configOptions includes all configurable params for the cache.
	configOptions *security.Options

	// storing certificates
	secretcache *sync.Map

	caRootPath string
}
 
var ScClient SecretManagerClient

const (
	rootCertPath       = "/var/run/secrets/istio/root-cert.pem"
)
   
// Automatically check and refresh when the validity period expires
func (sc *SecretManagerClient) delayedTask(delaytime time.Time, workloadCache *workloadapi.Workload ) {
	var new_certs *security.SecretItem
	var err error
	log.Infof("------------------delayedTask--------------------\n");
	
	for {
		<-time.After(time.Until(delaytime.Add(-30 * time.Second)))

		if _, ok := sc.secretcache.Load(workloadCache.Uid); !ok {
			return
		} else {
			new_certs, err = sc.caClient.fetch_cert(workloadCache);
			if err != nil {
				return 
			}
		}
		// Check if the key exists in the workload, if it does, refresh it, otherwise abandon it. 
		// If multi-threading refresh errors occur in this round, the certificate will be deleted 
		// in the next round of workload checks
		_, ok := sc.secretcache.Load(workloadCache.Uid);
		if ok {
			sc.secretcache.Store(workloadCache.Uid, *new_certs)
			delaytime = new_certs.ExpireTime;
		}
	}
}
 
// NewSecretManagerClient creates a new SecretManagerClient.
func NewSecretManagerClient() (*SecretManagerClient, error) {

	tlsOpts = &TLSOptions{
		RootCert:      rootCertPath,
	}

	options:= NewSecurityOptions()
	caClient, err := NewCitadelClient(options, tlsOpts)
	if err != nil {
		return nil, err
	}

	ret := &SecretManagerClient{
		caClient:      caClient,
		configOptions: options,
		caRootPath:  options.CARootPath,
		secretcache: &certs_maps,
	}
	ScClient = *ret
	return ret, nil
}
 
func GetSecretManagerClient() *SecretManagerClient {
	return &ScClient
}
	
// Initialize the certificate for the first time
func (sc *SecretManagerClient) Update_certs(workloadCache *workloadapi.Workload) {
	var new_certs *security.SecretItem
	var err error

	if certs, ok := sc.secretcache.Load(workloadCache.Uid); ok {
		if certs == nil {
			return
		}
		_certs := certs.(security.SecretItem);

		if _certs.ExpireTime.After(time.Now()) {
			return
		} else {
			new_certs, err = sc.caClient.fetch_cert(workloadCache);
			if err != nil {
				log.Errorf("fetche_cert error: %v", err)
				return
			}
		}

	} else {
		new_certs, err = sc.caClient.fetch_cert(workloadCache);
		if err != nil {
			log.Errorf("fetche_cert error: %v", err)
			return
		}
	}

	if new_certs != nil{
		sc.secretcache.Store(workloadCache.Uid, *new_certs)
		delaytime := new_certs.ExpireTime;
		go sc.delayedTask(delaytime, workloadCache);
	}

}
	
func (sc *SecretManagerClient) Delete_certs(workloadUid string) {
	if _, ok := sc.secretcache.Load(workloadUid); ok {
		sc.secretcache.Delete(workloadUid)
	}
}