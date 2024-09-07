/*
 * Copyright 2023 The Kmesh Authors.
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

 * Author: LemmyHuang
 * Create: 2022-02-15
 */

package cache_v2

import (
	"encoding/base64"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"

	"google.golang.org/protobuf/proto"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	pb "kmesh.net/kmesh/api/v2/grpcdata"
	listener_v2 "kmesh.net/kmesh/api/v2/listener"
	"kmesh.net/kmesh/pkg/grpcdata"
	"kmesh.net/kmesh/pkg/logger"
)

var RWListener sync.RWMutex

var log = logger.NewLoggerField("cache/v2")

type ListenerCache struct {
	mutex            sync.RWMutex
	apiListenerCache apiListenerCache
	resourceHash     map[string]uint64
}

func NewListenerCache() ListenerCache {
	return ListenerCache{
		apiListenerCache: NewApiListenerCache(),
		resourceHash:     make(map[string]uint64),
	}
}

type apiListenerCache map[string]*listener_v2.Listener

func NewApiListenerCache() apiListenerCache {
	return make(apiListenerCache)
}

func (cache *ListenerCache) GetApiListener(key string) *listener_v2.Listener {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.apiListenerCache[key]
}

func (cache *ListenerCache) GetResourceNames() sets.Set[string] {
	out := sets.New[string]()
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	for key := range cache.apiListenerCache {
		out.Insert(key)
	}
	return out
}

func (cache *ListenerCache) SetApiListener(key string, value *listener_v2.Listener) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.apiListenerCache[key] = value
}

func (cache *ListenerCache) UpdateApiListenerStatus(key string, status core_v2.ApiStatus) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	if cluster := cache.apiListenerCache[key]; cluster != nil {
		cluster.ApiStatus = status
	}
}

func (cache *ListenerCache) DeleteApiListener(key string) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	delete(cache.apiListenerCache, key)
	delete(cache.resourceHash, key)
}

func (cache *ListenerCache) GetLdsHash(key string) uint64 {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.resourceHash[key]
}

func (cache *ListenerCache) AddOrUpdateLdsHash(key string, value uint64) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.resourceHash[key] = value
}

func (cache *ListenerCache) Flush() {
	var err error
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	for name, listener := range cache.apiListenerCache {
		switch listener.GetApiStatus() {
		case core_v2.ApiStatus_UPDATE:
			keyByte, err := proto.Marshal(listener.GetAddress())
			if err != nil {
				log.Errorf("Marshal listener.GetAddress failed, err is:%v", err)
				continue
			}
			key := base64.StdEncoding.EncodeToString(keyByte)
			valueMsg, err := proto.Marshal(listener)
			if err != nil {
				log.Errorf("Marshal listener failed :%v", err)
				continue
			}
			err, _ = grpcdata.SendMsg(grpcdata.ConnClient, key, valueMsg, &pb.XdsOpt{XdsNmae: pb.XdsNmae_Listener, Opt: pb.Opteration_UPDATE})
			if err != nil {
				log.Errorf("grpcdata.SendMsg listener failed :%v", err)
				continue
			}
			// err = maps_v2.ListenerUpdate(listener.GetAddress(), listener)
			if err == nil {
				// reset api status after successfully updated
				listener.ApiStatus = core_v2.ApiStatus_NONE
			}
		case core_v2.ApiStatus_DELETE:
			keyByte, err := proto.Marshal(listener.GetAddress())
			if err != nil {
				log.Errorf("Marshal listener.GetAddress failed, err is:%v", err)
				continue
			}
			key := string(keyByte)
			err, _ = grpcdata.SendMsg(grpcdata.ConnClient, key, nil, &pb.XdsOpt{XdsNmae: pb.XdsNmae_Listener, Opt: pb.Opteration_DELETE})
			// err = maps_v2.ListenerDelete(listener.GetAddress())
			if err == nil {
				delete(cache.apiListenerCache, name)
				delete(cache.resourceHash, name)
			}
		}
		if err != nil {
			log.Errorf("listener %s %s flush failed: %v", name, listener.ApiStatus, err)
		}
	}
}

func (cache *ListenerCache) DumpBpf() []*listener_v2.Listener {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	listeners := make([]*listener_v2.Listener, 0, len(cache.apiListenerCache))
	for name, listener := range cache.apiListenerCache {
		tmp := &listener_v2.Listener{}
		keyByte, err := proto.Marshal(listener.GetAddress())
		if err != nil {
			log.Errorf("Marshal listener.GetAddress failed, err is:%v", err)
			continue
		}
		key := string(keyByte)
		err, tmpMsg := grpcdata.SendMsg(grpcdata.ConnClient, key, nil, &pb.XdsOpt{XdsNmae: pb.XdsNmae_Listener, Opt: pb.Opteration_LOOKUP})

		// if err := maps_v2.ListenerLookup(listener.GetAddress(), tmp); err != nil {
		if err != nil {
			log.Errorf("ListenerLookup failed, %s", name)
			continue
		}
		err = proto.Unmarshal(tmpMsg, tmp)
		if err != nil {
			log.Errorf("ListenerLookup failed, %s", name)
			continue
		}

		tmp.ApiStatus = listener.ApiStatus
		listeners = append(listeners, tmp)
	}

	return listeners
}

func (cache *ListenerCache) Dump() []*listener_v2.Listener {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	listeners := make([]*listener_v2.Listener, 0, len(cache.apiListenerCache))
	for _, listener := range cache.apiListenerCache {
		listeners = append(listeners, listener)
	}
	return listeners
}
