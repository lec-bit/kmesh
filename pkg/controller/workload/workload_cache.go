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

package workload

import (
	"encoding/binary"
	"sync"

	workloadapi "istio.io/istio/pkg/workloadapi";
)
 
 var (
	 workloadCache = workloadStore{
		 byUid: cacheByUid{
			 cache: make(map[string]*workloadapi.Workload),
		 },
		 byAddr: cacheByAddr{
			 cache: make(map[NetworkAddress]*workloadapi.Workload),
		 },
	 }
 )
 
 type workloadStore struct {
	 byUid  cacheByUid
	 byAddr cacheByAddr
 }
 
 type NetworkAddress struct {
	 Network string
	 Address uint32
 }
 
 type cacheByUid struct {
	 cache map[string]*workloadapi.Workload
	 mutex sync.RWMutex
 }
 
 type cacheByAddr struct {
	 cache map[NetworkAddress]*workloadapi.Workload
	 mutex sync.RWMutex
 }
 
 func GetCacheByUid(uid string) *workloadapi.Workload {
	 workloadCache.byUid.mutex.RLock()
	 defer workloadCache.byUid.mutex.RUnlock()
	 return workloadCache.byUid.cache[uid]
 }
 
 func GetCacheByAddr(networkAddress NetworkAddress) *workloadapi.Workload {
	 workloadCache.byAddr.mutex.RLock()
	 defer workloadCache.byAddr.mutex.RUnlock()
	 return workloadCache.byAddr.cache[networkAddress]
 }
 
 func storeCacheByUid(uid string, workload *workloadapi.Workload) {
	 workloadCache.byUid.mutex.Lock()
	 defer workloadCache.byUid.mutex.Unlock()
	 workloadCache.byUid.cache[uid] = workload
 }
 
 func storeCacheByAddr(networkAddress NetworkAddress, workload *workloadapi.Workload) {
	 workloadCache.byAddr.mutex.Lock()
	 defer workloadCache.byAddr.mutex.Unlock()
	 workloadCache.byAddr.cache[networkAddress] = workload
 }
 
 func deleteCacheByUid(uid string) {
	 workloadCache.byUid.mutex.Lock()
	 defer workloadCache.byUid.mutex.Unlock()
	 delete(workloadCache.byUid.cache, uid)
 }
 
 func deleteCacheByAddr(networkAddress NetworkAddress) {
	 workloadCache.byAddr.mutex.Lock()
	 defer workloadCache.byAddr.mutex.Unlock()
	 delete(workloadCache.byAddr.cache, networkAddress)
 }
 
 func composeNetworkAddress(network string, addr uint32) NetworkAddress {
	 networkAddress := NetworkAddress{
		 Network: network,
		 Address: addr,
	 }
 
	 return networkAddress
 }
 
 func workloadDataToCache(workload *workloadapi.Workload) {
	 uid := workload.Uid
	 _, exist := workloadCache.byUid.cache[uid]
	 if !exist {
		 storeCacheByUid(uid, workload)
	 }
 
	 for _, ip := range workload.Addresses {
		 addr := binary.LittleEndian.Uint32(ip)
		 networkAddress := composeNetworkAddress(workload.Network, addr)
		 _, exist := workloadCache.byAddr.cache[networkAddress]
		 if !exist {
			 storeCacheByAddr(networkAddress, workload)
		 }
	 }
 }
 
 func deleteWorkloadCache(uid string) {
	 workloadByUid, exist := workloadCache.byUid.cache[uid]
	 if exist {
		 for _, ip := range workloadByUid.Addresses {
			 addr := binary.LittleEndian.Uint32(ip)
			 networkAddress := composeNetworkAddress(workloadByUid.Network, addr)
			 _, exist := workloadCache.byAddr.cache[networkAddress]
			 if exist {
				 deleteCacheByAddr(networkAddress)
			 }
		 }
 
		 deleteCacheByUid(uid)
	 }
 }