// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package enhanced

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type KmeshSockopsBuf struct{ Data [40]int8 }

type KmeshSockopsLogEvent struct {
	Ret uint32
	Msg [255]int8
	_   [1]byte
}

type KmeshSockopsManagerKey struct {
	NetnsCookie uint64
	_           [8]byte
}

type KmeshSockopsSockStorageData struct {
	ConnectNs      uint64
	Direction      uint8
	ConnectSuccess uint8
	_              [6]byte
}

// LoadKmeshSockops returns the embedded CollectionSpec for KmeshSockops.
func LoadKmeshSockops() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_KmeshSockopsBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load KmeshSockops: %w", err)
	}

	return spec, err
}

// LoadKmeshSockopsObjects loads KmeshSockops and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*KmeshSockopsObjects
//	*KmeshSockopsPrograms
//	*KmeshSockopsMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadKmeshSockopsObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadKmeshSockops()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// KmeshSockopsSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSockopsSpecs struct {
	KmeshSockopsProgramSpecs
	KmeshSockopsMapSpecs
}

// KmeshSockopsSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSockopsProgramSpecs struct {
	ClusterManager     *ebpf.ProgramSpec `ebpf:"cluster_manager"`
	FilterChainManager *ebpf.ProgramSpec `ebpf:"filter_chain_manager"`
	FilterManager      *ebpf.ProgramSpec `ebpf:"filter_manager"`
	RouteConfigManager *ebpf.ProgramSpec `ebpf:"route_config_manager"`
	SockopsProg        *ebpf.ProgramSpec `ebpf:"sockops_prog"`
}

// KmeshSockopsMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type KmeshSockopsMapSpecs struct {
	BpfLogLevel         *ebpf.MapSpec `ebpf:"bpf_log_level"`
	InnerMap            *ebpf.MapSpec `ebpf:"inner_map"`
	KmeshCluster        *ebpf.MapSpec `ebpf:"kmesh_cluster"`
	KmeshEvents         *ebpf.MapSpec `ebpf:"kmesh_events"`
	KmeshListener       *ebpf.MapSpec `ebpf:"kmesh_listener"`
	KmeshManage         *ebpf.MapSpec `ebpf:"kmesh_manage"`
	KmeshTailCallCtx    *ebpf.MapSpec `ebpf:"kmesh_tail_call_ctx"`
	KmeshTailCallProg   *ebpf.MapSpec `ebpf:"kmesh_tail_call_prog"`
	MapOfClusterEps     *ebpf.MapSpec `ebpf:"map_of_cluster_eps"`
	MapOfClusterEpsData *ebpf.MapSpec `ebpf:"map_of_cluster_eps_data"`
	MapOfRouterConfig   *ebpf.MapSpec `ebpf:"map_of_router_config"`
	MapOfSockStorage    *ebpf.MapSpec `ebpf:"map_of_sock_storage"`
	OuterMap            *ebpf.MapSpec `ebpf:"outer_map"`
	TmpBuf              *ebpf.MapSpec `ebpf:"tmp_buf"`
	TmpLogBuf           *ebpf.MapSpec `ebpf:"tmp_log_buf"`
}

// KmeshSockopsObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSockopsObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSockopsObjects struct {
	KmeshSockopsPrograms
	KmeshSockopsMaps
}

func (o *KmeshSockopsObjects) Close() error {
	return _KmeshSockopsClose(
		&o.KmeshSockopsPrograms,
		&o.KmeshSockopsMaps,
	)
}

// KmeshSockopsMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSockopsObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSockopsMaps struct {
	BpfLogLevel         *ebpf.Map `ebpf:"bpf_log_level"`
	InnerMap            *ebpf.Map `ebpf:"inner_map"`
	KmeshCluster        *ebpf.Map `ebpf:"kmesh_cluster"`
	KmeshEvents         *ebpf.Map `ebpf:"kmesh_events"`
	KmeshListener       *ebpf.Map `ebpf:"kmesh_listener"`
	KmeshManage         *ebpf.Map `ebpf:"kmesh_manage"`
	KmeshTailCallCtx    *ebpf.Map `ebpf:"kmesh_tail_call_ctx"`
	KmeshTailCallProg   *ebpf.Map `ebpf:"kmesh_tail_call_prog"`
	MapOfClusterEps     *ebpf.Map `ebpf:"map_of_cluster_eps"`
	MapOfClusterEpsData *ebpf.Map `ebpf:"map_of_cluster_eps_data"`
	MapOfRouterConfig   *ebpf.Map `ebpf:"map_of_router_config"`
	MapOfSockStorage    *ebpf.Map `ebpf:"map_of_sock_storage"`
	OuterMap            *ebpf.Map `ebpf:"outer_map"`
	TmpBuf              *ebpf.Map `ebpf:"tmp_buf"`
	TmpLogBuf           *ebpf.Map `ebpf:"tmp_log_buf"`
}

func (m *KmeshSockopsMaps) Close() error {
	return _KmeshSockopsClose(
		m.BpfLogLevel,
		m.InnerMap,
		m.KmeshCluster,
		m.KmeshEvents,
		m.KmeshListener,
		m.KmeshManage,
		m.KmeshTailCallCtx,
		m.KmeshTailCallProg,
		m.MapOfClusterEps,
		m.MapOfClusterEpsData,
		m.MapOfRouterConfig,
		m.MapOfSockStorage,
		m.OuterMap,
		m.TmpBuf,
		m.TmpLogBuf,
	)
}

// KmeshSockopsPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadKmeshSockopsObjects or ebpf.CollectionSpec.LoadAndAssign.
type KmeshSockopsPrograms struct {
	ClusterManager     *ebpf.Program `ebpf:"cluster_manager"`
	FilterChainManager *ebpf.Program `ebpf:"filter_chain_manager"`
	FilterManager      *ebpf.Program `ebpf:"filter_manager"`
	RouteConfigManager *ebpf.Program `ebpf:"route_config_manager"`
	SockopsProg        *ebpf.Program `ebpf:"sockops_prog"`
}

func (p *KmeshSockopsPrograms) Close() error {
	return _KmeshSockopsClose(
		p.ClusterManager,
		p.FilterChainManager,
		p.FilterManager,
		p.RouteConfigManager,
		p.SockopsProg,
	)
}

func _KmeshSockopsClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed kmeshsockops_bpfel.o
var _KmeshSockopsBytes []byte
