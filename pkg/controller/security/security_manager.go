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

package security

import (
	"sync"
	"sync/atomic"
	"time"

	"container/heap"

	istiosecurity "istio.io/istio/pkg/security"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/logger"
)
	
type certExp struct {
	Identity string
	exp time.Time
	index	int
}

type certsCache struct {
	cert *istiosecurity.SecretItem
	refCnt int32
	refIp map[uint64]bool
}

type secretManagerCache struct {
	caClient *CaClient

	// configOptions includes all configurable params for the cache.
	configOptions *istiosecurity.Options

	// storing certificates
	certsCache *sync.Map

	//caRootPath string
	pending	*PriorityQueue
}

var log = logger.NewLoggerField("security")	

type PriorityQueue struct {
    queue []*certExp 
    mu    sync.Mutex
}

func NewPriorityQueue() *PriorityQueue {
    return &PriorityQueue{
        queue: make([]*certExp , 0),
		mu:    sync.Mutex{},
    }
}

func (pq *PriorityQueue) Push(x interface{}) {
	n := len(pq.queue)
	item := x.(*certExp)
	item.index = n
   	pq.queue = append(pq.queue, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := pq.queue
    n := len(old)
    x := old[n-1]
    old[n-1] = nil  // avoid memory leak
	x.index = -1
    pq.queue = old[0 : n-1]
    return x
}

func (pq *PriorityQueue) Len() int {
    return len(pq.queue)
}

func (pq *PriorityQueue) Less(i, j int) bool {
    return pq.queue[i].exp.Before(pq.queue[j].exp)
}

func (pq *PriorityQueue) Swap(i, j int) {
    pq.queue[i], pq.queue[j] = pq.queue[j], pq.queue[i]
}

func (pq *PriorityQueue) addItem(certExp *certExp) {
	pq.mu.Lock()
    defer pq.mu.Unlock()
	heap.Push(pq,certExp)
}

func (pq *PriorityQueue) delete(Identity string) *certExp {
	pq.mu.Lock()
    defer pq.mu.Unlock()
    for i := 0; i < len(pq.queue); i++ {
        if pq.queue[i].Identity == Identity {
            return heap.Remove(pq, i).(*certExp)
        }
    }
    return nil
}

func (pq *PriorityQueue) lookTop() *certExp {
	pq.mu.Lock()
    defer pq.mu.Unlock()
	return pq.queue[0]
}

// NewsecretManager creates a new secretManager.
func NewsecretManager(bpfWorkloadObj *bpf.BpfKmeshWorkload) (*secretManagerCache, error) {
	var certCache sync.Map

	tlsOpts = &TLSOptions{
		RootCert:      constants.RootCertPath,
	}

	options:= NewSecurityOptions()
	caClient, err := NewCaClient(options, tlsOpts)
	if err != nil {
		return nil, err
	}
	
	pq := NewPriorityQueue()
	heap.Init(pq)

	secretManager := secretManagerCache{
		caClient:      caClient,
		configOptions: options,
		certsCache: &certCache,
		pending:	pq,
	}
	go secretManager.refreshExpiringCerts()
	go secretManager.updateCerts(bpfWorkloadObj)
	return &secretManager, nil
}
	
// Automatically check and refresh when the validity period expires
// Store the Identity in the priority queue according to the expiration time.
// Check the highest priority element in the queue every 5 minutes. 
// If it is about to expire, pop up the element and reapply for the certificate.
func (s *secretManagerCache) refreshExpiringCerts() {
	for {
		if (s.pending.Len() == 0) {
			time.Sleep(1*time.Second)
			continue
		}
		top := s.pending.lookTop()
		select{
		case <-time.After(time.Until(top.exp.Add(-10 * time.Minute))):
			next := s.pending.delete(top.Identity)
			newCert, err := s.caClient.fetchCert(next.Identity)
			if err != nil {
				log.Errorf("%v refresh fetchCert error : %v", next.Identity, err)
				return 
			}
			// Check if the key exists in the map
			// If refCnt == 0, then this certificate is about to be deleted, so do not perform a refresh.
			certCache, ok := s.certsCache.Load(next.Identity)
			if ok && certCache.(*certsCache).refCnt != 0 {
				certCache.(*certsCache).cert = newCert
				certExp := certExp{exp: newCert.ExpireTime, Identity: next.Identity}
				s.pending.addItem(&certExp)
				log.Infof("cert %v refresh, exp:%v\n", next.Identity, newCert.ExpireTime)
			}
		case <-time.After(5 * time.Minute):
			log.Debug("5 minute after")
			continue
		}
	}
}

func (s *secretManagerCache) getcertCache(Identity string) *certsCache {
	var certcache *certsCache
	cache, ok := s.certsCache.Load(Identity)
	if ok {
		certcache = cache.(*certsCache)
	}else {
		log.Debugf("can't find certsCache by %v \n", Identity)
	}
	return certcache
}

func (s *secretManagerCache) updateCerts(bpfWorkloadObj *bpf.BpfKmeshWorkload) {

	for data := range workload.SecurityDataChannel {
		Identity, ip, op := data.Identity, data.Ip, data.Operation

		switch op{
		case "applyCert":
			go s.addCerts(Identity, ip, bpfWorkloadObj)
		case "deleteCert":
			go s.deleteCerts(Identity, ip)
		}
	}
}

// Initialize the certificate for the first time
func (s *secretManagerCache) addCerts(Identity string, ip uint64, bpfWorkloadObj *bpf.BpfKmeshWorkload) {
	var newCert *istiosecurity.SecretItem
	var err error

	// Consider only the default IP address 
	// keep it consistent with the IP address recorded in the managed pod.
	value := uint32(0)
	log.Debugf("lookup ip: %v", ip)
	err = bpfWorkloadObj.SockOps.KmeshSockopsWorkloadMaps.KmeshManage.Lookup(&ip, &value)
	if (err != nil){
		log.Debugf("workload is not managed")
		return
	}

	var certCache = certsCache{
		refCnt :1,
		refIp: make(map[uint64]bool),
	}

	if certCache, ok := s.certsCache.LoadOrStore(Identity, &certCache); ok {
		certCache := certCache.(*certsCache)
		// In this case, it is due to a pod restart, and the tasks in the pending priority queue need to be replenished.
		if (certCache.refCnt == 0 && s.pending.delete(Identity) == nil) {
			log.Debugf("certCache.refCnt == 0")
			certExp := certExp{exp:certCache.cert.ExpireTime, Identity: Identity}
			s.pending.addItem(&certExp)
		}

		atomic.AddInt32(&certCache.refCnt, 1)
		certCache.refIp[ip] = true
		log.Debugf("Identity: %v    refCnt++ : %v\n", Identity, certCache.refCnt)
		return
	} else {
		newCert, err = s.caClient.fetchCert(Identity);
		if err != nil {
			log.Errorf("%v fetcheCert error: %v", Identity, err)
			return
		}
	}

	// Save the new certificate in the map and add a record to the priority queue 
	// of the auto-refresh task when it expires
	if newCert != nil{
		certExp := certExp{exp: newCert.ExpireTime, Identity: Identity}
		cache, _ := s.certsCache.Load(Identity)
		certCache := cache.(*certsCache)
		certCache.refIp[ip] = true
		s.pending.addItem(&certExp)
		log.Infof("add %v cert, exp: %v\n", Identity, newCert.ExpireTime)
	}
}

// Set the removed to true for the items in the pending priority queue.
// Delete the certificate and status map corresponding to the Identity.
func (s *secretManagerCache) deleteCerts(Identity string, ip uint64) {
	certCache := s.getcertCache(Identity)
	if certCache == nil{
		return
	}

	if _, ok := certCache.refIp[ip]; !ok {
		return
	}

	delete(certCache.refIp, ip)
	atomic.AddInt32(&certCache.refCnt, -1)
	log.Debugf("Identity: %v    refCnt-- : %v\n", Identity, certCache.refCnt)

	if (certCache.refCnt <= 0) {
		// In order to handle the situation where there is only one pod in the SA, 
		// and the pod restarts, we will delay the deletion by 15 seconds.
		time.Sleep(15 * time.Second)
		if (certCache.refCnt <= 0) {
			s.certsCache.Delete(Identity)
			s.pending.delete(Identity)
		}
	}
}

