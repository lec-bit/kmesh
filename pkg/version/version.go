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
 * Create: 2024-5-23
 */
package version

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf"
	"istio.io/pkg/log"
)

const (
	NewStart = iota
	Restart
	Update
)

var (
	gitVersion   = "v0.0.0-master"
	gitCommit    = "unknown" // sha1 from git, output of $(git rev-parse HEAD)
	gitTreeState = "unknown" // state of git tree, either "clean" or "dirty"

	buildDate = "unknown" // build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')

	StartStatus = NewStart
)

//var m ebpf.Map
// Info contains versioning information.
type Info struct {
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

// String returns a Go-syntax representation of the Info.
func (info Info) String() string {
	return fmt.Sprintf("%#v", info)
}

// Get returns the overall codebase version. It's for detecting
// what code a binary was built from.
func Get() Info {
	return Info{
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func NewVersionMap() *ebpf.Map{
	m := RecoverMap()
	if m != nil {
		KmeshStartStatus(m)
		return m
	}

	mapSpec := &ebpf.MapSpec {
		Name:	"kmesh_version",
		Type:	ebpf.Array,
		KeySize: 4,
		ValueSize: 16,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(mapSpec)
	if err != nil {
		log.Errorf("Create version map failed, err is %v", err)
	}

	err = m.Pin("/sys/fs/bpf/kmesh_version")
	if err != nil {
		log.Errorf("failed to pin map: %v", err)
	}

	Put(m)
	StartStatus = NewStart
	return m
}

func Put(versionMap *ebpf.Map) {
	key := uint32(0)
	var value [16]byte
	copy(value[:], gitVersion)
	if err := versionMap.Put(&key, &value); err != nil {
		log.Errorf("Add Version Map failed, err is %v", err)
	}
}

func GetMap(m *ebpf.Map, key uint32) (value string) {
	var valueBytes [16]byte
	err := m.Lookup(&key, &valueBytes)
	if err != nil {
		log.Errorf("lookup failed: %v", err)
		return ""
	}
	value = string(valueBytes[:])
	return value
}

func KmeshStartStatus(versionMap *ebpf.Map) {
	value := GetMap(versionMap, 0)
	log.Infof("value :   %v", value)
	log.Infof("gitVersion :   %v", gitVersion)
	if gitVersion == value {
		StartStatus = Restart
	}
	StartStatus = Update
}

func RecoverMap() *ebpf.Map{
	opts := &ebpf.LoadPinOptions{
		ReadOnly:  false,
		WriteOnly: false,
		Flags:     0, 
	}
	myMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/kmesh_version", opts)
	if err != nil {
		log.Errorf("加载BPF map失败:%v", err)
		return nil
	}
	log.Debugf("RecoverMap success")

	return myMap
}

func Close(m *ebpf.Map) {
	m.Unpin()
	m.Close()
	
	log.Infof("Close map version")
}

func GetStartStatus() int{
	return StartStatus
}
