/*
 * Copyright The Kmesh Authors.
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

package adstelemetry

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/pkg/controller/ads/cache"
)

type MetricL7Controller struct {
	EnableAccesslog      atomic.Bool
	EnableMonitoring     atomic.Bool
	EnableWorkloadMetric atomic.Bool
	adsMetricCache       map[adsMetricLabels]*adsMetricInfo
	NameByAddr           map[string]string
	mutex                sync.RWMutex
}

type l7Direction int

const (
	l7Egress l7Direction = iota
	l7Ingress
	l7DirectUnknown
)

type connectionDataV7 struct {
	Iov    [1024]byte
	IovLen uint64
}

func detectMessageType(data []byte) string {
	if bytes.HasPrefix(data, []byte("HTTP/")) {
		return "response"
	}
	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		if bytes.HasPrefix(data, []byte(method)) {
			return "request"
		}
	}
	return "unknown"
}

func parseHTTPHeader(data []byte) (*http.Request, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return nil, err
	}
	return req, nil
}

type KeyValue struct {
	Key   string
	Value string
}

func extractHeaders(header http.Header) []KeyValue {
	var headers []KeyValue
	for key, values := range header {

		value := ""
		for _, v := range values {
			if value != "" {
				value += ", "
			}
			value += v
		}
		headers = append(headers, KeyValue{Key: key, Value: value})
	}
	return headers
}

func NewL7Metric(AdsCache *cache.AdsCache, enableMonitoring bool, managerCache map[string]string) *MetricL7Controller {
	m := &MetricL7Controller{
		adsMetricCache: map[adsMetricLabels]*adsMetricInfo{},
		NameByAddr:     managerCache,
	}
	m.EnableMonitoring.Store(enableMonitoring)
	m.EnableAccesslog.Store(false)
	m.EnableWorkloadMetric.Store(false)
	return m
}

func (m *MetricL7Controller) Run(ctx context.Context, MapOfHttpProbe *ebpf.Map) {
	if m == nil {
		return
	}
	log.Printf("MetricController RUN")
	var err error
	osStartTime, err = getOSBootTime()
	if err != nil {
		log.Errorf("get latest os boot time for accesslog failed: %v", err)
	}

	reader, err := ringbuf.NewReader(MapOfHttpProbe)
	if err != nil {
		log.Errorf("open metric notify ringbuf map FAILED, err: %v", err)
		return
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Errorf("ringbuf reader Close FAILED, err: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			log.Printf("MetricController LOAD")
			if !m.EnableMonitoring.Load() {
				continue
			}
			log.Printf("MetricController ENABLED")
			rec := ringbuf.Record{}
			if err := reader.ReadInto(&rec); err != nil {
				log.Errorf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}
			if len(rec.RawSample) != int(unsafe.Sizeof(connectionDataV7{})) {
				log.Errorf("wrong length %v of a msg, should be %v", len(rec.RawSample), int(unsafe.Sizeof(connectionDataV7{})))
				continue
			}
			rawData := rec.RawSample
			info := (*connectionDataV7)(unsafe.Pointer(&rawData[0]))

			if detectMessageType(info.Iov[:]) == "request" {
				httpHeader, err := parseHTTPHeader(info.Iov[:])
				if err != nil {
					log.Fatalf("parseHTTPHeader failed, err: %v", err)
				}

				proto := httpHeader.Proto
				path := httpHeader.URL.Path
				log.Printf("proto:%s\n path:%s", proto, path)
				headers := extractHeaders(httpHeader.Header)
				for _, h := range headers {
					log.Printf("%s: %s\n", h.Key, h.Value)
				}
			}
		}
	}
}
