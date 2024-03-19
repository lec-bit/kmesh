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

	"container/heap"

	"istio.io/istio/pkg/security"
	"kmesh.net/kmesh/pkg/logger"
)
	
type Certs struct {
	uid string
	exp time.Time
}

type PriorityQueue []*Certs

func (pq PriorityQueue) Len() int { return len(pq) }

// 我们希望到期时间越早的证书具有更高的优先级
func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].exp.Before(pq[j].exp)
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*Certs)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

var certs_maps sync.Map
var log = logger.NewLoggerField("kmeshsecurity")

type SecretManagerClient struct {
	caClient *CitadelClient

	// configOptions includes all configurable params for the cache.
	configOptions *security.Options

	// storing certificates
	secretcache *sync.Map

	caRootPath string

	pending	PriorityQueue
}
 
var ScClient SecretManagerClient

const (
	rootCertPath       = "/var/run/secrets/istio/root-cert.pem"
)
   
// Automatically check and refresh when the validity period expires
func (sc *SecretManagerClient) delayedTask() {
	var new_certs *security.SecretItem
	var err error
	var expireTime time.Time
	log.Infof("------------------delayedTask--------------------\n");
	
	for {
		expireTime = time.Now().Add(600 * time.Second)
		if (len(sc.pending) > 0) {
			next_tmp := heap.Pop(&sc.pending).(*Certs)
			expireTime = next_tmp.exp
			heap.Push(&sc.pending, next_tmp)
		}
		select{
		case <-time.After(time.Until(expireTime.Add(-300 * time.Second))):
			next := heap.Pop(&sc.pending).(*Certs)
			if _, ok := sc.secretcache.Load(next.uid); !ok {
				continue
			} else {
				new_certs, err = sc.caClient.fetch_cert(next.uid);
				if err != nil {
					<-time.After(10*time.Second)
					new_certs, err = sc.caClient.fetch_cert(next.uid);
				}
			}
			// Check if the key exists in the workload, if it does, refresh it, otherwise abandon it. 
			// If multi-threading refresh errors occur in this round, the certificate will be deleted 
			// in the next round of workload checks
			_, ok := sc.secretcache.Load(next.uid);
			if ok {
				sc.secretcache.Store(next.uid, *new_certs)
				heap.Push(&sc.pending, &Certs{exp: new_certs.ExpireTime, uid: next.uid})
			}
		case <-time.After(300 * time.Second):
			continue
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
	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	ret := &SecretManagerClient{
		caClient:      caClient,
		configOptions: options,
		caRootPath:  options.CARootPath,
		secretcache: &certs_maps,
		pending:	pq,
	}
	ScClient = *ret
	go ScClient.delayedTask()
	return ret, nil
}
 
func GetSecretManagerClient() *SecretManagerClient {
	return &ScClient
}
	

var update_cert_channel = make(chan string)

func (sc *SecretManagerClient) Update_certs(workloadUid string) {
	update_cert_channel <- workloadUid
}

// Initialize the certificate for the first time
func (sc *SecretManagerClient) update_certs_routine() {
	var new_certs *security.SecretItem
	var err error
	for workloadUid := range update_cert_channel {
		if certs, ok := sc.secretcache.Load(workloadUid); ok {
			if certs == nil {
				continue
			}
			_certs := certs.(security.SecretItem);

			if _certs.ExpireTime.After(time.Now()) {
				continue
			} else {
				new_certs, err = sc.caClient.fetch_cert(workloadUid);
				if err != nil {
					log.Errorf("fetche_cert error: %v", err)
					continue
				}
			}

		} else {
			new_certs, err = sc.caClient.fetch_cert(workloadUid);
			if err != nil {
				log.Errorf("fetche_cert error: %v", err)
				continue
			}
		}

		// Save the new certificate in the map and add a record to the priority queue 
		// of the auto-refresh task when it expires
		if new_certs != nil{
			sc.secretcache.Store(workloadUid, *new_certs)
			heap.Push(&sc.pending, &Certs{exp: new_certs.ExpireTime, uid: workloadUid})
		}
	}
}
	

func (sc *SecretManagerClient) Delete_certs(workloadUid string) {
	if _, ok := sc.secretcache.Load(workloadUid); ok {
		sc.secretcache.Delete(workloadUid)
	}
}