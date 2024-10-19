// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.1
// source: api/route/route.proto

package route

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	core "lec-bit/kmesh/api/v2/core"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type RouteConfiguration struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ApiStatus    core.ApiStatus `protobuf:"varint,128,opt,name=api_status,json=apiStatus,proto3,enum=core.ApiStatus" json:"api_status,omitempty"`
	Name         string         `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	VirtualHosts []*VirtualHost `protobuf:"bytes,2,rep,name=virtual_hosts,json=virtualHosts,proto3" json:"virtual_hosts,omitempty"`
}

func (x *RouteConfiguration) Reset() {
	*x = RouteConfiguration{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_route_route_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RouteConfiguration) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RouteConfiguration) ProtoMessage() {}

func (x *RouteConfiguration) ProtoReflect() protoreflect.Message {
	mi := &file_api_route_route_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RouteConfiguration.ProtoReflect.Descriptor instead.
func (*RouteConfiguration) Descriptor() ([]byte, []int) {
	return file_api_route_route_proto_rawDescGZIP(), []int{0}
}

func (x *RouteConfiguration) GetApiStatus() core.ApiStatus {
	if x != nil {
		return x.ApiStatus
	}
	return core.ApiStatus(0)
}

func (x *RouteConfiguration) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *RouteConfiguration) GetVirtualHosts() []*VirtualHost {
	if x != nil {
		return x.VirtualHosts
	}
	return nil
}

var File_api_route_route_proto protoreflect.FileDescriptor

var file_api_route_route_proto_rawDesc = []byte{
	0x0a, 0x15, 0x61, 0x70, 0x69, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x2f, 0x72, 0x6f, 0x75, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x1a, 0x20,
	0x61, 0x70, 0x69, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f,
	0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x13, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x92, 0x01, 0x0a, 0x12, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2f, 0x0a, 0x0a,
	0x61, 0x70, 0x69, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x80, 0x01, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x0f, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x41, 0x70, 0x69, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x52, 0x09, 0x61, 0x70, 0x69, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x12, 0x0a,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x37, 0x0a, 0x0d, 0x76, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x5f, 0x68, 0x6f, 0x73,
	0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x2e, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x48, 0x6f, 0x73, 0x74, 0x52, 0x0c, 0x76, 0x69,
	0x72, 0x74, 0x75, 0x61, 0x6c, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x42, 0x21, 0x5a, 0x1f, 0x6b, 0x6d,
	0x65, 0x73, 0x68, 0x2e, 0x6e, 0x65, 0x74, 0x2f, 0x6b, 0x6d, 0x65, 0x73, 0x68, 0x2f, 0x61, 0x70,
	0x69, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x3b, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_route_route_proto_rawDescOnce sync.Once
	file_api_route_route_proto_rawDescData = file_api_route_route_proto_rawDesc
)

func file_api_route_route_proto_rawDescGZIP() []byte {
	file_api_route_route_proto_rawDescOnce.Do(func() {
		file_api_route_route_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_route_route_proto_rawDescData)
	})
	return file_api_route_route_proto_rawDescData
}

var file_api_route_route_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_api_route_route_proto_goTypes = []any{
	(*RouteConfiguration)(nil), // 0: route.RouteConfiguration
	(core.ApiStatus)(0),        // 1: core.ApiStatus
	(*VirtualHost)(nil),        // 2: route.VirtualHost
}
var file_api_route_route_proto_depIdxs = []int32{
	1, // 0: route.RouteConfiguration.api_status:type_name -> core.ApiStatus
	2, // 1: route.RouteConfiguration.virtual_hosts:type_name -> route.VirtualHost
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_api_route_route_proto_init() }
func file_api_route_route_proto_init() {
	if File_api_route_route_proto != nil {
		return
	}
	file_api_route_route_components_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_api_route_route_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*RouteConfiguration); i {
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
			RawDescriptor: file_api_route_route_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_route_route_proto_goTypes,
		DependencyIndexes: file_api_route_route_proto_depIdxs,
		MessageInfos:      file_api_route_route_proto_msgTypes,
	}.Build()
	File_api_route_route_proto = out.File
	file_api_route_route_proto_rawDesc = nil
	file_api_route_route_proto_goTypes = nil
	file_api_route_route_proto_depIdxs = nil
}
