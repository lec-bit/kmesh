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
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/workloadapi"
	"kmesh.net/kmesh/pkg/logger"
)
	
var certs_maps sync.Map

var log = logger.NewLoggerField("kmeshsecurity")

var CACertFilePath = ""
 
type SecretManagerClient struct {
	caClient *CitadelClient

	// configOptions includes all configurable params for the cache.
	configOptions *security.Options

	// storing certificates
	secretcache *sync.Map

	// Dynamically configured Trust Bundle
	configTrustBundle []byte

	caRootPath string
}
 
var ScClient SecretManagerClient
// concatCerts concatenates PEM certificates, making sure each one starts on a new line
func concatCerts(certsPEM []string) []byte {
	if len(certsPEM) == 0 {
		return []byte{}
	}
	var certChain bytes.Buffer
	for i, c := range certsPEM {
		certChain.WriteString(c)
		if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			certChain.WriteString("\n")
		}
	}
	return certChain.Bytes()
}
	
type ProxyArgs struct {
	DNSDomain          string
	StsPort            int
	TokenManagerPlugin string

	MeshConfigFile string

	// proxy config flags (named identically)
	ServiceCluster         string
	ProxyLogLevel          string
	ProxyComponentLogLevel string
	Concurrency            int
	TemplateFile           string
	OutlierLogPath         string

	PodName      string
	PodNamespace string

	// enableProfiling enables profiling via web interface host:port/debug/pprof/
	EnableProfiling bool
}
   
const (
	DefaultPurgeInterval         = 1 * time.Hour
	DefaultModuleExpiry          = 24 * time.Hour
	DefaultHTTPRequestTimeout    = 15 * time.Second
	DefaultHTTPRequestMaxRetries = 5
)
   
const (
	// MaxRetryInterval retry interval time when reconnect
	MaxRetryInterval = time.Second * 30

	// MaxRetryCount retry max count when reconnect
	MaxRetryCount = 3

	jwtPath            = "/var/run/secrets/tokens/istio-token"
	rootCertPath       = "/var/run/secrets/istio/root-cert.pem"

	KubeAppProberEnvName = "ISTIO_KUBE_APP_PROBERS"

	ConfigPathDir = "./etc/istio/proxy"
	
)
   
// cacheLogPrefix returns a unified log prefix.
func cacheLogPrefix(resourceName string) string {
	lPrefix := fmt.Sprintf("resource:%s", resourceName)
	return lPrefix
}
  
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