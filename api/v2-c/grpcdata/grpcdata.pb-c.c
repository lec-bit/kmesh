/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: api/grpcdata/grpcdata.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "grpcdata/grpcdata.pb-c.h"
void   grpcdata__cluster_update_request__init
                     (Grpcdata__ClusterUpdateRequest         *message)
{
  static const Grpcdata__ClusterUpdateRequest init_value = GRPCDATA__CLUSTER_UPDATE_REQUEST__INIT;
  *message = init_value;
}
size_t grpcdata__cluster_update_request__get_packed_size
                     (const Grpcdata__ClusterUpdateRequest *message)
{
  assert(message->base.descriptor == &grpcdata__cluster_update_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t grpcdata__cluster_update_request__pack
                     (const Grpcdata__ClusterUpdateRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &grpcdata__cluster_update_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t grpcdata__cluster_update_request__pack_to_buffer
                     (const Grpcdata__ClusterUpdateRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &grpcdata__cluster_update_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Grpcdata__ClusterUpdateRequest *
       grpcdata__cluster_update_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Grpcdata__ClusterUpdateRequest *)
     protobuf_c_message_unpack (&grpcdata__cluster_update_request__descriptor,
                                allocator, len, data);
}
void   grpcdata__cluster_update_request__free_unpacked
                     (Grpcdata__ClusterUpdateRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &grpcdata__cluster_update_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   grpcdata__cluster_update_response__init
                     (Grpcdata__ClusterUpdateResponse         *message)
{
  static const Grpcdata__ClusterUpdateResponse init_value = GRPCDATA__CLUSTER_UPDATE_RESPONSE__INIT;
  *message = init_value;
}
size_t grpcdata__cluster_update_response__get_packed_size
                     (const Grpcdata__ClusterUpdateResponse *message)
{
  assert(message->base.descriptor == &grpcdata__cluster_update_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t grpcdata__cluster_update_response__pack
                     (const Grpcdata__ClusterUpdateResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &grpcdata__cluster_update_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t grpcdata__cluster_update_response__pack_to_buffer
                     (const Grpcdata__ClusterUpdateResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &grpcdata__cluster_update_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Grpcdata__ClusterUpdateResponse *
       grpcdata__cluster_update_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Grpcdata__ClusterUpdateResponse *)
     protobuf_c_message_unpack (&grpcdata__cluster_update_response__descriptor,
                                allocator, len, data);
}
void   grpcdata__cluster_update_response__free_unpacked
                     (Grpcdata__ClusterUpdateResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &grpcdata__cluster_update_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   grpcdata__response__init
                     (Grpcdata__Response         *message)
{
  static const Grpcdata__Response init_value = GRPCDATA__RESPONSE__INIT;
  *message = init_value;
}
size_t grpcdata__response__get_packed_size
                     (const Grpcdata__Response *message)
{
  assert(message->base.descriptor == &grpcdata__response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t grpcdata__response__pack
                     (const Grpcdata__Response *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &grpcdata__response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t grpcdata__response__pack_to_buffer
                     (const Grpcdata__Response *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &grpcdata__response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Grpcdata__Response *
       grpcdata__response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Grpcdata__Response *)
     protobuf_c_message_unpack (&grpcdata__response__descriptor,
                                allocator, len, data);
}
void   grpcdata__response__free_unpacked
                     (Grpcdata__Response *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &grpcdata__response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor grpcdata__cluster_update_request__field_descriptors[2] =
{
  {
    "key",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Grpcdata__ClusterUpdateRequest, key),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "value",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Grpcdata__ClusterUpdateRequest, value),
    &cluster__cluster__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned grpcdata__cluster_update_request__field_indices_by_name[] = {
  0,   /* field[0] = key */
  1,   /* field[1] = value */
};
static const ProtobufCIntRange grpcdata__cluster_update_request__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor grpcdata__cluster_update_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "grpcdata.ClusterUpdateRequest",
  "ClusterUpdateRequest",
  "Grpcdata__ClusterUpdateRequest",
  "grpcdata",
  sizeof(Grpcdata__ClusterUpdateRequest),
  2,
  grpcdata__cluster_update_request__field_descriptors,
  grpcdata__cluster_update_request__field_indices_by_name,
  1,  grpcdata__cluster_update_request__number_ranges,
  (ProtobufCMessageInit) grpcdata__cluster_update_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor grpcdata__cluster_update_response__field_descriptors[1] =
{
  {
    "error_code",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(Grpcdata__ClusterUpdateResponse, error_code),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned grpcdata__cluster_update_response__field_indices_by_name[] = {
  0,   /* field[0] = error_code */
};
static const ProtobufCIntRange grpcdata__cluster_update_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor grpcdata__cluster_update_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "grpcdata.ClusterUpdateResponse",
  "ClusterUpdateResponse",
  "Grpcdata__ClusterUpdateResponse",
  "grpcdata",
  sizeof(Grpcdata__ClusterUpdateResponse),
  1,
  grpcdata__cluster_update_response__field_descriptors,
  grpcdata__cluster_update_response__field_indices_by_name,
  1,  grpcdata__cluster_update_response__number_ranges,
  (ProtobufCMessageInit) grpcdata__cluster_update_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor grpcdata__response__field_descriptors[1] =
{
  {
    "message",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Grpcdata__Response, message),
    NULL,
    &protobuf_c_empty_string,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned grpcdata__response__field_indices_by_name[] = {
  0,   /* field[0] = message */
};
static const ProtobufCIntRange grpcdata__response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor grpcdata__response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "grpcdata.Response",
  "Response",
  "Grpcdata__Response",
  "grpcdata",
  sizeof(Grpcdata__Response),
  1,
  grpcdata__response__field_descriptors,
  grpcdata__response__field_indices_by_name,
  1,  grpcdata__response__number_ranges,
  (ProtobufCMessageInit) grpcdata__response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCEnumValue grpcdata__cluster__lb_policy__enum_values_by_number[2] =
{
  { "ROUND_ROBIN", "GRPCDATA__CLUSTER__LB_POLICY__ROUND_ROBIN", 0 },
  { "LEAST_CONNECTIONS", "GRPCDATA__CLUSTER__LB_POLICY__LEAST_CONNECTIONS", 1 },
};
static const ProtobufCIntRange grpcdata__cluster__lb_policy__value_ranges[] = {
{0, 0},{0, 2}
};
static const ProtobufCEnumValueIndex grpcdata__cluster__lb_policy__enum_values_by_name[2] =
{
  { "LEAST_CONNECTIONS", 1 },
  { "ROUND_ROBIN", 0 },
};
const ProtobufCEnumDescriptor grpcdata__cluster__lb_policy__descriptor =
{
  PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC,
  "grpcdata.Cluster_LbPolicy",
  "Cluster_LbPolicy",
  "Grpcdata__ClusterLbPolicy",
  "grpcdata",
  2,
  grpcdata__cluster__lb_policy__enum_values_by_number,
  2,
  grpcdata__cluster__lb_policy__enum_values_by_name,
  1,
  grpcdata__cluster__lb_policy__value_ranges,
  NULL,NULL,NULL,NULL   /* reserved[1234] */
};
static const ProtobufCMethodDescriptor grpcdata__cluster_service__method_descriptors[1] =
{
  { "UpdateCluster", &grpcdata__cluster_update_request__descriptor, &grpcdata__cluster_update_response__descriptor },
};
const unsigned grpcdata__cluster_service__method_indices_by_name[] = {
  0         /* UpdateCluster */
};
const ProtobufCServiceDescriptor grpcdata__cluster_service__descriptor =
{
  PROTOBUF_C__SERVICE_DESCRIPTOR_MAGIC,
  "grpcdata.ClusterService",
  "ClusterService",
  "Grpcdata__ClusterService",
  "grpcdata",
  1,
  grpcdata__cluster_service__method_descriptors,
  grpcdata__cluster_service__method_indices_by_name
};
void grpcdata__cluster_service__update_cluster(ProtobufCService *service,
                                               const Grpcdata__ClusterUpdateRequest *input,
                                               Grpcdata__ClusterUpdateResponse_Closure closure,
                                               void *closure_data)
{
  assert(service->descriptor == &grpcdata__cluster_service__descriptor);
  service->invoke(service, 0, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void grpcdata__cluster_service__init (Grpcdata__ClusterService_Service *service,
                                      Grpcdata__ClusterService_ServiceDestroy destroy)
{
  protobuf_c_service_generated_init (&service->base,
                                     &grpcdata__cluster_service__descriptor,
                                     (ProtobufCServiceDestroy) destroy);
}
