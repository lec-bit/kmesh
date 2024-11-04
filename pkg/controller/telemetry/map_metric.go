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

package telemetry

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

const (
	mapMetricFlushInterval = 15 * time.Second
)

type MapMetricController struct {
}

type MapInfo struct {
	mapName    string
	entryCount uint32
}

type mapMetricLabels struct {
	mapName  string
	nodeName string
}

type totalMapMetricLabels struct {
	nodeName string
}

func NewMapMetric() *MapMetricController {
	return &MapMetricController{}
}

func (m *MapMetricController) Run(ctx context.Context) {
	if m == nil {
		return
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(mapMetricFlushInterval)
				m.updatePrometheusMetric()
			}
		}
	}()
}

func (m *MapMetricController) buildMapMetric(data *MapInfo) mapMetricLabels {
	labels := mapMetricLabels{}
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown"
	}
	labels.nodeName = nodeName
	labels.mapName = data.mapName
	return labels
}

func (m *MapMetricController) buildTotalMapMetric() totalMapMetricLabels {
	labels := totalMapMetricLabels{}
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown"
	}

	labels.nodeName = nodeName
	return labels
}

func isKmeshMap(mapName string) bool {
	return strings.HasPrefix(mapName, "kmesh_")
}
func (m *MapMetricController) updatePrometheusMetric() {
	var startID ebpf.MapID
	count := 0

	for {
		mapID, mapInfo, info, err := getNextMapInfo(startID)
		if err != nil {
			break
		}
		startID = mapID
		if info.Name == "" {
			mapInfo.Close()
			count++
			continue
		}

		if !isKmeshMap(info.Name) {
			mapInfo.Close()
			continue
		}

		entryCount := uint32(0)
		if info.Type == ebpf.Hash {
			entryCount, _ = getMapEntryCountFallback(mapInfo)
		}
		mapData := buildMapEntrycountMetric(info, entryCount)
		metricLabels := m.buildMapMetric(&mapData)
		commonLabels := struct2map(metricLabels)
		mapEntryCount.With(commonLabels).Set(float64(entryCount))
		count++
		mapInfo.Close()
	}
	totalMetricLabels := m.buildTotalMapMetric()
	totalMapLabels := struct2map(totalMetricLabels)
	mapCountInNode.With(totalMapLabels).Set(float64(count))
}

func getNextMapInfo(startID ebpf.MapID) (ebpf.MapID, *ebpf.Map, *ebpf.MapInfo, error) {
	mapID, err := ebpf.MapGetNextID(startID)
	if err != nil {
		return 0, nil, nil, err
	}

	mapInfo, err := ebpf.NewMapFromID(mapID)
	if err != nil {
		log.Infof("Failed to open map ID %d: %v", mapID, err)
		return mapID, nil, nil, err
	}

	info, err := mapInfo.Info()
	if err != nil {
		log.Infof("Failed to get map info for ID %d: %v", mapID, err)
		return mapID, mapInfo, nil, err
	}

	return mapID, mapInfo, info, nil
}

func buildMapEntrycountMetric(info *ebpf.MapInfo, entryCount uint32) MapInfo {
	return MapInfo{
		mapName:    info.Name,
		entryCount: entryCount,
	}
}
func getMapEntryCountFallback(m *ebpf.Map) (uint32, error) {
	var entryCount uint32
	iterator := m.Iterate()
	var key, value []byte
	for iterator.Next(&key, &value) {
		entryCount++
	}
	if err := iterator.Err(); err != nil {
		return 0, fmt.Errorf("failed during map iteration: %v", err)
	}
	return entryCount, nil
}
