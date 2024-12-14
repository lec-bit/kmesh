// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package bpf2go

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadKmeshTracePoint returns the embedded CollectionSpec for KmeshTracePoint.
func LoadKmeshTracePoint() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshTracePointBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshTracePoint: %w", err)
	}

	return spec, err
}

// LoadKmeshTracePointObjects loads KmeshTracePoint and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshTracePointObjects
//	*KmeshTracePointPrograms
//	*KmeshTracePointMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshTracePointObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshTracePoint()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshTracePointSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshTracePointSpecs struct {
	KmeshTracePointProgramSpecs
	KmeshTracePointMapSpecs
}

// KmeshTracePointSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshTracePointProgramSpecs struct {
	ConnectRet *ebpf.ProgramSpec `ebpf:"connect_ret"`
}

// KmeshTracePointMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshTracePointMapSpecs struct {
}

// KmeshTracePointObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshTracePointObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshTracePointObjects struct {
	KmeshTracePointPrograms
	KmeshTracePointMaps
}

func (o *KmeshTracePointObjects) Close() error {
	return _KmeshTracePointClose(
		&o.KmeshTracePointPrograms,
		&o.KmeshTracePointMaps,
	)
}

// KmeshTracePointMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshTracePointObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshTracePointMaps struct {
}

func (m *KmeshTracePointMaps) Close() error {
	return _KmeshTracePointClose()
}

// KmeshTracePointPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshTracePointObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshTracePointPrograms struct {
	ConnectRet *ebpf.Program `ebpf:"connect_ret"`
}

func (p *KmeshTracePointPrograms) Close() error {
	return _KmeshTracePointClose(
		p.ConnectRet,
	)
}

func _KmeshTracePointClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshtracepoint_bpfel.o
var _KmeshTracePointBytes []byte