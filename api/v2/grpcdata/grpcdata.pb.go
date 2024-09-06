// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        v3.17.3
// source: api/grpcdata/grpcdata.proto

package grpcdata

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type XdsNmae int32

const (
	XdsNmae_Cluster  XdsNmae = 0
	XdsNmae_Listener XdsNmae = 1
	XdsNmae_Route    XdsNmae = 2
)

// Enum value maps for XdsNmae.
var (
	XdsNmae_name = map[int32]string{
		0: "Cluster",
		1: "Listener",
		2: "Route",
	}
	XdsNmae_value = map[string]int32{
		"Cluster":  0,
		"Listener": 1,
		"Route":    2,
	}
)

func (x XdsNmae) Enum() *XdsNmae {
	p := new(XdsNmae)
	*p = x
	return p
}

func (x XdsNmae) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (XdsNmae) Descriptor() protoreflect.EnumDescriptor {
	return file_api_grpcdata_grpcdata_proto_enumTypes[0].Descriptor()
}

func (XdsNmae) Type() protoreflect.EnumType {
	return &file_api_grpcdata_grpcdata_proto_enumTypes[0]
}

func (x XdsNmae) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use XdsNmae.Descriptor instead.
func (XdsNmae) EnumDescriptor() ([]byte, []int) {
	return file_api_grpcdata_grpcdata_proto_rawDescGZIP(), []int{0}
}

type Opteration int32

const (
	Opteration_UPDATE Opteration = 0
	Opteration_LOOKUP Opteration = 1
	Opteration_DELETE Opteration = 2
)

// Enum value maps for Opteration.
var (
	Opteration_name = map[int32]string{
		0: "UPDATE",
		1: "LOOKUP",
		2: "DELETE",
	}
	Opteration_value = map[string]int32{
		"UPDATE": 0,
		"LOOKUP": 1,
		"DELETE": 2,
	}
)

func (x Opteration) Enum() *Opteration {
	p := new(Opteration)
	*p = x
	return p
}

func (x Opteration) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Opteration) Descriptor() protoreflect.EnumDescriptor {
	return file_api_grpcdata_grpcdata_proto_enumTypes[1].Descriptor()
}

func (Opteration) Type() protoreflect.EnumType {
	return &file_api_grpcdata_grpcdata_proto_enumTypes[1]
}

func (x Opteration) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Opteration.Descriptor instead.
func (Opteration) EnumDescriptor() ([]byte, []int) {
	return file_api_grpcdata_grpcdata_proto_rawDescGZIP(), []int{1}
}

type MsgRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key    string  `protobuf:"bytes,1,opt,name=Key,proto3" json:"Key,omitempty"`
	XdsOpt *XdsOpt `protobuf:"bytes,2,opt,name=XdsOpt,proto3" json:"XdsOpt,omitempty"`
	Msg    []byte  `protobuf:"bytes,3,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (x *MsgRequest) Reset() {
	*x = MsgRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_grpcdata_grpcdata_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MsgRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgRequest) ProtoMessage() {}

func (x *MsgRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpcdata_grpcdata_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgRequest.ProtoReflect.Descriptor instead.
func (*MsgRequest) Descriptor() ([]byte, []int) {
	return file_api_grpcdata_grpcdata_proto_rawDescGZIP(), []int{0}
}

func (x *MsgRequest) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *MsgRequest) GetXdsOpt() *XdsOpt {
	if x != nil {
		return x.XdsOpt
	}
	return nil
}

func (x *MsgRequest) GetMsg() []byte {
	if x != nil {
		return x.Msg
	}
	return nil
}

type MsgResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ErrorCode int32  `protobuf:"varint,1,opt,name=error_code,json=errorCode,proto3" json:"error_code,omitempty"`
	Msg       []byte `protobuf:"bytes,2,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (x *MsgResponse) Reset() {
	*x = MsgResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_grpcdata_grpcdata_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MsgResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MsgResponse) ProtoMessage() {}

func (x *MsgResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpcdata_grpcdata_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MsgResponse.ProtoReflect.Descriptor instead.
func (*MsgResponse) Descriptor() ([]byte, []int) {
	return file_api_grpcdata_grpcdata_proto_rawDescGZIP(), []int{1}
}

func (x *MsgResponse) GetErrorCode() int32 {
	if x != nil {
		return x.ErrorCode
	}
	return 0
}

func (x *MsgResponse) GetMsg() []byte {
	if x != nil {
		return x.Msg
	}
	return nil
}

type XdsOpt struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	XdsNmae XdsNmae    `protobuf:"varint,1,opt,name=XdsNmae,proto3,enum=grpcdata.XdsNmae" json:"XdsNmae,omitempty"`
	Opt     Opteration `protobuf:"varint,2,opt,name=Opt,proto3,enum=grpcdata.Opteration" json:"Opt,omitempty"`
}

func (x *XdsOpt) Reset() {
	*x = XdsOpt{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_grpcdata_grpcdata_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *XdsOpt) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*XdsOpt) ProtoMessage() {}

func (x *XdsOpt) ProtoReflect() protoreflect.Message {
	mi := &file_api_grpcdata_grpcdata_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use XdsOpt.ProtoReflect.Descriptor instead.
func (*XdsOpt) Descriptor() ([]byte, []int) {
	return file_api_grpcdata_grpcdata_proto_rawDescGZIP(), []int{2}
}

func (x *XdsOpt) GetXdsNmae() XdsNmae {
	if x != nil {
		return x.XdsNmae
	}
	return XdsNmae_Cluster
}

func (x *XdsOpt) GetOpt() Opteration {
	if x != nil {
		return x.Opt
	}
	return Opteration_UPDATE
}

var File_api_grpcdata_grpcdata_proto protoreflect.FileDescriptor

var file_api_grpcdata_grpcdata_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x64, 0x61, 0x74, 0x61, 0x2f, 0x67,
	0x72, 0x70, 0x63, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x08, 0x67,
	0x72, 0x70, 0x63, 0x64, 0x61, 0x74, 0x61, 0x22, 0x5a, 0x0a, 0x0a, 0x4d, 0x73, 0x67, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x4b, 0x65, 0x79, 0x12, 0x28, 0x0a, 0x06, 0x58, 0x64, 0x73, 0x4f, 0x70,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x64, 0x61,
	0x74, 0x61, 0x2e, 0x58, 0x64, 0x73, 0x4f, 0x70, 0x74, 0x52, 0x06, 0x58, 0x64, 0x73, 0x4f, 0x70,
	0x74, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x6d, 0x73, 0x67, 0x22, 0x3e, 0x0a, 0x0b, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x5f, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x64,
	0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x6d, 0x73, 0x67, 0x22, 0x5d, 0x0a, 0x06, 0x58, 0x64, 0x73, 0x4f, 0x70, 0x74, 0x12, 0x2b, 0x0a,
	0x07, 0x58, 0x64, 0x73, 0x4e, 0x6d, 0x61, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x11,
	0x2e, 0x67, 0x72, 0x70, 0x63, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x58, 0x64, 0x73, 0x4e, 0x6d, 0x61,
	0x65, 0x52, 0x07, 0x58, 0x64, 0x73, 0x4e, 0x6d, 0x61, 0x65, 0x12, 0x26, 0x0a, 0x03, 0x4f, 0x70,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x14, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x64, 0x61,
	0x74, 0x61, 0x2e, 0x4f, 0x70, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x4f,
	0x70, 0x74, 0x2a, 0x2f, 0x0a, 0x07, 0x58, 0x64, 0x73, 0x4e, 0x6d, 0x61, 0x65, 0x12, 0x0b, 0x0a,
	0x07, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x10, 0x00, 0x12, 0x0c, 0x0a, 0x08, 0x4c, 0x69,
	0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x10, 0x01, 0x12, 0x09, 0x0a, 0x05, 0x52, 0x6f, 0x75, 0x74,
	0x65, 0x10, 0x02, 0x2a, 0x30, 0x0a, 0x0a, 0x4f, 0x70, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x0a, 0x0a, 0x06, 0x55, 0x50, 0x44, 0x41, 0x54, 0x45, 0x10, 0x00, 0x12, 0x0a, 0x0a,
	0x06, 0x4c, 0x4f, 0x4f, 0x4b, 0x55, 0x50, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x44, 0x45, 0x4c,
	0x45, 0x54, 0x45, 0x10, 0x02, 0x32, 0x4b, 0x0a, 0x0f, 0x6b, 0x6d, 0x65, 0x73, 0x68, 0x4d, 0x73,
	0x67, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x38, 0x0a, 0x09, 0x48, 0x61, 0x6e, 0x64,
	0x6c, 0x65, 0x4d, 0x73, 0x67, 0x12, 0x14, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x64, 0x61, 0x74, 0x61,
	0x2e, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x15, 0x2e, 0x67, 0x72,
	0x70, 0x63, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x42, 0x27, 0x5a, 0x25, 0x6b, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x6e, 0x65, 0x74, 0x2f,
	0x6b, 0x6d, 0x65, 0x73, 0x68, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x64, 0x61,
	0x74, 0x61, 0x3b, 0x67, 0x72, 0x70, 0x63, 0x64, 0x61, 0x74, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_api_grpcdata_grpcdata_proto_rawDescOnce sync.Once
	file_api_grpcdata_grpcdata_proto_rawDescData = file_api_grpcdata_grpcdata_proto_rawDesc
)

func file_api_grpcdata_grpcdata_proto_rawDescGZIP() []byte {
	file_api_grpcdata_grpcdata_proto_rawDescOnce.Do(func() {
		file_api_grpcdata_grpcdata_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_grpcdata_grpcdata_proto_rawDescData)
	})
	return file_api_grpcdata_grpcdata_proto_rawDescData
}

var file_api_grpcdata_grpcdata_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_api_grpcdata_grpcdata_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_api_grpcdata_grpcdata_proto_goTypes = []interface{}{
	(XdsNmae)(0),        // 0: grpcdata.XdsNmae
	(Opteration)(0),     // 1: grpcdata.Opteration
	(*MsgRequest)(nil),  // 2: grpcdata.MsgRequest
	(*MsgResponse)(nil), // 3: grpcdata.MsgResponse
	(*XdsOpt)(nil),      // 4: grpcdata.XdsOpt
}
var file_api_grpcdata_grpcdata_proto_depIdxs = []int32{
	4, // 0: grpcdata.MsgRequest.XdsOpt:type_name -> grpcdata.XdsOpt
	0, // 1: grpcdata.XdsOpt.XdsNmae:type_name -> grpcdata.XdsNmae
	1, // 2: grpcdata.XdsOpt.Opt:type_name -> grpcdata.Opteration
	2, // 3: grpcdata.kmeshMsgService.HandleMsg:input_type -> grpcdata.MsgRequest
	3, // 4: grpcdata.kmeshMsgService.HandleMsg:output_type -> grpcdata.MsgResponse
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_api_grpcdata_grpcdata_proto_init() }
func file_api_grpcdata_grpcdata_proto_init() {
	if File_api_grpcdata_grpcdata_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_grpcdata_grpcdata_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MsgRequest); i {
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
		file_api_grpcdata_grpcdata_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MsgResponse); i {
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
		file_api_grpcdata_grpcdata_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*XdsOpt); i {
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
			RawDescriptor: file_api_grpcdata_grpcdata_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_grpcdata_grpcdata_proto_goTypes,
		DependencyIndexes: file_api_grpcdata_grpcdata_proto_depIdxs,
		EnumInfos:         file_api_grpcdata_grpcdata_proto_enumTypes,
		MessageInfos:      file_api_grpcdata_grpcdata_proto_msgTypes,
	}.Build()
	File_api_grpcdata_grpcdata_proto = out.File
	file_api_grpcdata_grpcdata_proto_rawDesc = nil
	file_api_grpcdata_grpcdata_proto_goTypes = nil
	file_api_grpcdata_grpcdata_proto_depIdxs = nil
}
