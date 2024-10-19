// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.1
// source: api/cluster/circuit_breaker.proto

package cluster

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	core "kmesh-net/kmesh/api/v2/core"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CircuitBreakers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Priority           core.RoutingPriority `protobuf:"varint,1,opt,name=priority,proto3,enum=core.RoutingPriority" json:"priority,omitempty"`
	MaxConnections     uint32               `protobuf:"varint,2,opt,name=max_connections,json=maxConnections,proto3" json:"max_connections,omitempty"`
	MaxPendingRequests uint32               `protobuf:"varint,3,opt,name=max_pending_requests,json=maxPendingRequests,proto3" json:"max_pending_requests,omitempty"`
	MaxRequests        uint32               `protobuf:"varint,4,opt,name=max_requests,json=maxRequests,proto3" json:"max_requests,omitempty"`
	MaxRetries         uint32               `protobuf:"varint,5,opt,name=max_retries,json=maxRetries,proto3" json:"max_retries,omitempty"`
	MaxConnectionPools uint32               `protobuf:"varint,7,opt,name=max_connection_pools,json=maxConnectionPools,proto3" json:"max_connection_pools,omitempty"`
}

func (x *CircuitBreakers) Reset() {
	*x = CircuitBreakers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_cluster_circuit_breaker_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CircuitBreakers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CircuitBreakers) ProtoMessage() {}

func (x *CircuitBreakers) ProtoReflect() protoreflect.Message {
	mi := &file_api_cluster_circuit_breaker_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CircuitBreakers.ProtoReflect.Descriptor instead.
func (*CircuitBreakers) Descriptor() ([]byte, []int) {
	return file_api_cluster_circuit_breaker_proto_rawDescGZIP(), []int{0}
}

func (x *CircuitBreakers) GetPriority() core.RoutingPriority {
	if x != nil {
		return x.Priority
	}
	return core.RoutingPriority(0)
}

func (x *CircuitBreakers) GetMaxConnections() uint32 {
	if x != nil {
		return x.MaxConnections
	}
	return 0
}

func (x *CircuitBreakers) GetMaxPendingRequests() uint32 {
	if x != nil {
		return x.MaxPendingRequests
	}
	return 0
}

func (x *CircuitBreakers) GetMaxRequests() uint32 {
	if x != nil {
		return x.MaxRequests
	}
	return 0
}

func (x *CircuitBreakers) GetMaxRetries() uint32 {
	if x != nil {
		return x.MaxRetries
	}
	return 0
}

func (x *CircuitBreakers) GetMaxConnectionPools() uint32 {
	if x != nil {
		return x.MaxConnectionPools
	}
	return 0
}

var File_api_cluster_circuit_breaker_proto protoreflect.FileDescriptor

var file_api_cluster_circuit_breaker_proto_rawDesc = []byte{
	0x0a, 0x21, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x2f, 0x63, 0x69,
	0x72, 0x63, 0x75, 0x69, 0x74, 0x5f, 0x62, 0x72, 0x65, 0x61, 0x6b, 0x65, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x07, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x1a, 0x13, 0x61, 0x70,
	0x69, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x95, 0x02, 0x0a, 0x0f, 0x43, 0x69, 0x72, 0x63, 0x75, 0x69, 0x74, 0x42, 0x72, 0x65,
	0x61, 0x6b, 0x65, 0x72, 0x73, 0x12, 0x31, 0x0a, 0x08, 0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x52,
	0x6f, 0x75, 0x74, 0x69, 0x6e, 0x67, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x08,
	0x70, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x27, 0x0a, 0x0f, 0x6d, 0x61, 0x78, 0x5f,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0e, 0x6d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x12, 0x30, 0x0a, 0x14, 0x6d, 0x61, 0x78, 0x5f, 0x70, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67,
	0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x12, 0x6d, 0x61, 0x78, 0x50, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x6d, 0x61, 0x78, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x6d, 0x61, 0x78, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x6d, 0x61, 0x78, 0x5f, 0x72, 0x65,
	0x74, 0x72, 0x69, 0x65, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x6d, 0x61, 0x78,
	0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x73, 0x12, 0x30, 0x0a, 0x14, 0x6d, 0x61, 0x78, 0x5f, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x6f, 0x6f, 0x6c, 0x73, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x6d, 0x61, 0x78, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6f, 0x6f, 0x6c, 0x73, 0x42, 0x25, 0x5a, 0x23, 0x6b, 0x6d, 0x65,
	0x73, 0x68, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x6b, 0x6d, 0x65, 0x73, 0x68, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x3b, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_cluster_circuit_breaker_proto_rawDescOnce sync.Once
	file_api_cluster_circuit_breaker_proto_rawDescData = file_api_cluster_circuit_breaker_proto_rawDesc
)

func file_api_cluster_circuit_breaker_proto_rawDescGZIP() []byte {
	file_api_cluster_circuit_breaker_proto_rawDescOnce.Do(func() {
		file_api_cluster_circuit_breaker_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_cluster_circuit_breaker_proto_rawDescData)
	})
	return file_api_cluster_circuit_breaker_proto_rawDescData
}

var file_api_cluster_circuit_breaker_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_api_cluster_circuit_breaker_proto_goTypes = []any{
	(*CircuitBreakers)(nil),   // 0: cluster.CircuitBreakers
	(core.RoutingPriority)(0), // 1: core.RoutingPriority
}
var file_api_cluster_circuit_breaker_proto_depIdxs = []int32{
	1, // 0: cluster.CircuitBreakers.priority:type_name -> core.RoutingPriority
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_api_cluster_circuit_breaker_proto_init() }
func file_api_cluster_circuit_breaker_proto_init() {
	if File_api_cluster_circuit_breaker_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_cluster_circuit_breaker_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*CircuitBreakers); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_cluster_circuit_breaker_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_cluster_circuit_breaker_proto_goTypes,
		DependencyIndexes: file_api_cluster_circuit_breaker_proto_depIdxs,
		MessageInfos:      file_api_cluster_circuit_breaker_proto_msgTypes,
	}.Build()
	File_api_cluster_circuit_breaker_proto = out.File
	file_api_cluster_circuit_breaker_proto_rawDesc = nil
	file_api_cluster_circuit_breaker_proto_goTypes = nil
	file_api_cluster_circuit_breaker_proto_depIdxs = nil
}
