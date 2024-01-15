// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.21.12
// source: implant.proto

package implant

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AgentCommand int32

const (
	AgentCommand_AGENT_COMMAND_UNSPECIFIED       AgentCommand = 0
	AgentCommand_AGENT_COMMAND_CHECKIN           AgentCommand = 1
	AgentCommand_AGENT_COMMAND_SYSINFO           AgentCommand = 2
	AgentCommand_AGENT_COMMAND_EXECUTE           AgentCommand = 3
	AgentCommand_AGENT_COMMAND_EXECUTE_SHELLCODE AgentCommand = 4
	AgentCommand_AGENT_COMMAND_MESSAGE           AgentCommand = 5
	AgentCommand_AGENT_COMMAND_SHUTDOWN          AgentCommand = 6
	AgentCommand_AGENT_COMMAND_KEYX              AgentCommand = 7
	AgentCommand_AGENT_COMMAND_SET_CONFIG        AgentCommand = 8
	AgentCommand_AGENT_COMMAND_IGNORE            AgentCommand = 9
)

// Enum value maps for AgentCommand.
var (
	AgentCommand_name = map[int32]string{
		0: "AGENT_COMMAND_UNSPECIFIED",
		1: "AGENT_COMMAND_CHECKIN",
		2: "AGENT_COMMAND_SYSINFO",
		3: "AGENT_COMMAND_EXECUTE",
		4: "AGENT_COMMAND_EXECUTE_SHELLCODE",
		5: "AGENT_COMMAND_MESSAGE",
		6: "AGENT_COMMAND_SHUTDOWN",
		7: "AGENT_COMMAND_KEYX",
		8: "AGENT_COMMAND_SET_CONFIG",
		9: "AGENT_COMMAND_IGNORE",
	}
	AgentCommand_value = map[string]int32{
		"AGENT_COMMAND_UNSPECIFIED":       0,
		"AGENT_COMMAND_CHECKIN":           1,
		"AGENT_COMMAND_SYSINFO":           2,
		"AGENT_COMMAND_EXECUTE":           3,
		"AGENT_COMMAND_EXECUTE_SHELLCODE": 4,
		"AGENT_COMMAND_MESSAGE":           5,
		"AGENT_COMMAND_SHUTDOWN":          6,
		"AGENT_COMMAND_KEYX":              7,
		"AGENT_COMMAND_SET_CONFIG":        8,
		"AGENT_COMMAND_IGNORE":            9,
	}
)

func (x AgentCommand) Enum() *AgentCommand {
	p := new(AgentCommand)
	*p = x
	return p
}

func (x AgentCommand) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AgentCommand) Descriptor() protoreflect.EnumDescriptor {
	return file_implant_proto_enumTypes[0].Descriptor()
}

func (AgentCommand) Type() protoreflect.EnumType {
	return &file_implant_proto_enumTypes[0]
}

func (x AgentCommand) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AgentCommand.Descriptor instead.
func (AgentCommand) EnumDescriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{0}
}

type C2ResponseStatus int32

const (
	C2ResponseStatus_C2_STATUS_UNSPECIFIED    C2ResponseStatus = 0
	C2ResponseStatus_NEED_MORE_DATA           C2ResponseStatus = 1
	C2ResponseStatus_DATA_RECEIVED            C2ResponseStatus = 2
	C2ResponseStatus_NO_DATA                  C2ResponseStatus = 3
	C2ResponseStatus_ERROR_IMPORTING_KEY      C2ResponseStatus = 4
	C2ResponseStatus_ERROR_DERIVING_SECRET    C2ResponseStatus = 5
	C2ResponseStatus_ERROR_DECRYPTING_MESSAGE C2ResponseStatus = 6
	C2ResponseStatus_ERROR_GENERATING_KEYS    C2ResponseStatus = 7
	C2ResponseStatus_ERROR_INVALID_MESSAGE    C2ResponseStatus = 8
	C2ResponseStatus_ERROR_AGENT_UNKNOWN      C2ResponseStatus = 9
	C2ResponseStatus_ERROR_CHECKING_IN        C2ResponseStatus = 10
	C2ResponseStatus_ERROR_KEYX_NOT_ALLOWED   C2ResponseStatus = 11
	C2ResponseStatus_ERROR_INVALID_SYSINFO    C2ResponseStatus = 12
	C2ResponseStatus_ERROR_FAILED             C2ResponseStatus = 13
)

// Enum value maps for C2ResponseStatus.
var (
	C2ResponseStatus_name = map[int32]string{
		0:  "C2_STATUS_UNSPECIFIED",
		1:  "NEED_MORE_DATA",
		2:  "DATA_RECEIVED",
		3:  "NO_DATA",
		4:  "ERROR_IMPORTING_KEY",
		5:  "ERROR_DERIVING_SECRET",
		6:  "ERROR_DECRYPTING_MESSAGE",
		7:  "ERROR_GENERATING_KEYS",
		8:  "ERROR_INVALID_MESSAGE",
		9:  "ERROR_AGENT_UNKNOWN",
		10: "ERROR_CHECKING_IN",
		11: "ERROR_KEYX_NOT_ALLOWED",
		12: "ERROR_INVALID_SYSINFO",
		13: "ERROR_FAILED",
	}
	C2ResponseStatus_value = map[string]int32{
		"C2_STATUS_UNSPECIFIED":    0,
		"NEED_MORE_DATA":           1,
		"DATA_RECEIVED":            2,
		"NO_DATA":                  3,
		"ERROR_IMPORTING_KEY":      4,
		"ERROR_DERIVING_SECRET":    5,
		"ERROR_DECRYPTING_MESSAGE": 6,
		"ERROR_GENERATING_KEYS":    7,
		"ERROR_INVALID_MESSAGE":    8,
		"ERROR_AGENT_UNKNOWN":      9,
		"ERROR_CHECKING_IN":        10,
		"ERROR_KEYX_NOT_ALLOWED":   11,
		"ERROR_INVALID_SYSINFO":    12,
		"ERROR_FAILED":             13,
	}
)

func (x C2ResponseStatus) Enum() *C2ResponseStatus {
	p := new(C2ResponseStatus)
	*p = x
	return p
}

func (x C2ResponseStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (C2ResponseStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_implant_proto_enumTypes[1].Descriptor()
}

func (C2ResponseStatus) Type() protoreflect.EnumType {
	return &file_implant_proto_enumTypes[1]
}

func (x C2ResponseStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use C2ResponseStatus.Descriptor instead.
func (C2ResponseStatus) EnumDescriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{1}
}

type AgentCommandStatus int32

const (
	AgentCommandStatus_COMMAND_STATUS_UNSPECIFIED AgentCommandStatus = 0
	AgentCommandStatus_COMMAND_STATUS_SUCCESS     AgentCommandStatus = 1
	AgentCommandStatus_COMMAND_STATUS_ERROR       AgentCommandStatus = 2
)

// Enum value maps for AgentCommandStatus.
var (
	AgentCommandStatus_name = map[int32]string{
		0: "COMMAND_STATUS_UNSPECIFIED",
		1: "COMMAND_STATUS_SUCCESS",
		2: "COMMAND_STATUS_ERROR",
	}
	AgentCommandStatus_value = map[string]int32{
		"COMMAND_STATUS_UNSPECIFIED": 0,
		"COMMAND_STATUS_SUCCESS":     1,
		"COMMAND_STATUS_ERROR":       2,
	}
)

func (x AgentCommandStatus) Enum() *AgentCommandStatus {
	p := new(AgentCommandStatus)
	*p = x
	return p
}

func (x AgentCommandStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AgentCommandStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_implant_proto_enumTypes[2].Descriptor()
}

func (AgentCommandStatus) Type() protoreflect.EnumType {
	return &file_implant_proto_enumTypes[2]
}

func (x AgentCommandStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AgentCommandStatus.Descriptor instead.
func (AgentCommandStatus) EnumDescriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{2}
}

type AgentConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	C2Domain   string `protobuf:"bytes,1,opt,name=c2_domain,json=c2Domain,proto3" json:"c2_domain,omitempty"`
	C2Password string `protobuf:"bytes,2,opt,name=c2_password,json=c2Password,proto3" json:"c2_password,omitempty"`
	// google's proto wrappers allow us to check if the field exists, so we don't
	// accidentally use the default proto3 values for optional fields
	Resolver      *wrapperspb.StringValue `protobuf:"bytes,3,opt,name=resolver,proto3" json:"resolver,omitempty"`
	C2IntervalMs  *wrapperspb.UInt32Value `protobuf:"bytes,4,opt,name=c2_interval_ms,json=c2IntervalMs,proto3" json:"c2_interval_ms,omitempty"`
	UseWebChannel *wrapperspb.BoolValue   `protobuf:"bytes,5,opt,name=use_web_channel,json=useWebChannel,proto3" json:"use_web_channel,omitempty"`
	WebUrl        *wrapperspb.StringValue `protobuf:"bytes,6,opt,name=web_url,json=webUrl,proto3" json:"web_url,omitempty"`
	WebKey        *wrapperspb.StringValue `protobuf:"bytes,7,opt,name=web_key,json=webKey,proto3" json:"web_key,omitempty"`
	ThrottleSendq *wrapperspb.BoolValue   `protobuf:"bytes,8,opt,name=throttle_sendq,json=throttleSendq,proto3" json:"throttle_sendq,omitempty"`
}

func (x *AgentConfig) Reset() {
	*x = AgentConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_implant_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AgentConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AgentConfig) ProtoMessage() {}

func (x *AgentConfig) ProtoReflect() protoreflect.Message {
	mi := &file_implant_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AgentConfig.ProtoReflect.Descriptor instead.
func (*AgentConfig) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{0}
}

func (x *AgentConfig) GetC2Domain() string {
	if x != nil {
		return x.C2Domain
	}
	return ""
}

func (x *AgentConfig) GetC2Password() string {
	if x != nil {
		return x.C2Password
	}
	return ""
}

func (x *AgentConfig) GetResolver() *wrapperspb.StringValue {
	if x != nil {
		return x.Resolver
	}
	return nil
}

func (x *AgentConfig) GetC2IntervalMs() *wrapperspb.UInt32Value {
	if x != nil {
		return x.C2IntervalMs
	}
	return nil
}

func (x *AgentConfig) GetUseWebChannel() *wrapperspb.BoolValue {
	if x != nil {
		return x.UseWebChannel
	}
	return nil
}

func (x *AgentConfig) GetWebUrl() *wrapperspb.StringValue {
	if x != nil {
		return x.WebUrl
	}
	return nil
}

func (x *AgentConfig) GetWebKey() *wrapperspb.StringValue {
	if x != nil {
		return x.WebKey
	}
	return nil
}

func (x *AgentConfig) GetThrottleSendq() *wrapperspb.BoolValue {
	if x != nil {
		return x.ThrottleSendq
	}
	return nil
}

type SysInfoData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hostname string   `protobuf:"bytes,1,opt,name=hostname,proto3" json:"hostname,omitempty"`
	Ip       []string `protobuf:"bytes,2,rep,name=ip,proto3" json:"ip,omitempty"`
	User     string   `protobuf:"bytes,3,opt,name=user,proto3" json:"user,omitempty"`
	Uid      string   `protobuf:"bytes,4,opt,name=uid,proto3" json:"uid,omitempty"`
	Gid      string   `protobuf:"bytes,5,opt,name=gid,proto3" json:"gid,omitempty"`
}

func (x *SysInfoData) Reset() {
	*x = SysInfoData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_implant_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SysInfoData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SysInfoData) ProtoMessage() {}

func (x *SysInfoData) ProtoReflect() protoreflect.Message {
	mi := &file_implant_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SysInfoData.ProtoReflect.Descriptor instead.
func (*SysInfoData) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{1}
}

func (x *SysInfoData) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *SysInfoData) GetIp() []string {
	if x != nil {
		return x.Ip
	}
	return nil
}

func (x *SysInfoData) GetUser() string {
	if x != nil {
		return x.User
	}
	return ""
}

func (x *SysInfoData) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *SysInfoData) GetGid() string {
	if x != nil {
		return x.Gid
	}
	return ""
}

// c2 and agent communicate via Command messages
// Request message comes from the c2 and instructs the agent on what to do
// (command) with the input, along with any additional data, such as config in
// the event of a SET_CONFIG command
type Command struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *Command) Reset() {
	*x = Command{}
	if protoimpl.UnsafeEnabled {
		mi := &file_implant_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command) ProtoMessage() {}

func (x *Command) ProtoReflect() protoreflect.Message {
	mi := &file_implant_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Command.ProtoReflect.Descriptor instead.
func (*Command) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{2}
}

type Command_Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Command AgentCommand `protobuf:"varint,1,opt,name=command,proto3,enum=implant.AgentCommand" json:"command,omitempty"`
	Data    []byte       `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *Command_Request) Reset() {
	*x = Command_Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_implant_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command_Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command_Request) ProtoMessage() {}

func (x *Command_Request) ProtoReflect() protoreflect.Message {
	mi := &file_implant_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Command_Request.ProtoReflect.Descriptor instead.
func (*Command_Request) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{2, 0}
}

func (x *Command_Request) GetCommand() AgentCommand {
	if x != nil {
		return x.Command
	}
	return AgentCommand_AGENT_COMMAND_UNSPECIFIED
}

func (x *Command_Request) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type Command_Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Command AgentCommand       `protobuf:"varint,1,opt,name=command,proto3,enum=implant.AgentCommand" json:"command,omitempty"`
	Data    []byte             `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	Status  AgentCommandStatus `protobuf:"varint,4,opt,name=status,proto3,enum=implant.AgentCommandStatus" json:"status,omitempty"`
}

func (x *Command_Response) Reset() {
	*x = Command_Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_implant_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command_Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command_Response) ProtoMessage() {}

func (x *Command_Response) ProtoReflect() protoreflect.Message {
	mi := &file_implant_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Command_Response.ProtoReflect.Descriptor instead.
func (*Command_Response) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{2, 1}
}

func (x *Command_Response) GetCommand() AgentCommand {
	if x != nil {
		return x.Command
	}
	return AgentCommand_AGENT_COMMAND_UNSPECIFIED
}

func (x *Command_Response) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *Command_Response) GetStatus() AgentCommandStatus {
	if x != nil {
		return x.Status
	}
	return AgentCommandStatus_COMMAND_STATUS_UNSPECIFIED
}

var File_implant_proto protoreflect.FileDescriptor

var file_implant_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x07, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65,
	0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xbe, 0x03, 0x0a, 0x0b, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x32, 0x5f, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x32, 0x44,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x32, 0x5f, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x32, 0x50, 0x61,
	0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x38, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76,
	0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e,
	0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72,
	0x12, 0x42, 0x0a, 0x0e, 0x63, 0x32, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x5f,
	0x6d, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49, 0x6e, 0x74, 0x33,
	0x32, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0c, 0x63, 0x32, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76,
	0x61, 0x6c, 0x4d, 0x73, 0x12, 0x42, 0x0a, 0x0f, 0x75, 0x73, 0x65, 0x5f, 0x77, 0x65, 0x62, 0x5f,
	0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0d, 0x75, 0x73, 0x65, 0x57, 0x65,
	0x62, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x12, 0x35, 0x0a, 0x07, 0x77, 0x65, 0x62, 0x5f,
	0x75, 0x72, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69,
	0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x06, 0x77, 0x65, 0x62, 0x55, 0x72, 0x6c, 0x12,
	0x35, 0x0a, 0x07, 0x77, 0x65, 0x62, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x06,
	0x77, 0x65, 0x62, 0x4b, 0x65, 0x79, 0x12, 0x41, 0x0a, 0x0e, 0x74, 0x68, 0x72, 0x6f, 0x74, 0x74,
	0x6c, 0x65, 0x5f, 0x73, 0x65, 0x6e, 0x64, 0x71, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0d, 0x74, 0x68, 0x72, 0x6f,
	0x74, 0x74, 0x6c, 0x65, 0x53, 0x65, 0x6e, 0x64, 0x71, 0x22, 0x71, 0x0a, 0x0b, 0x53, 0x79, 0x73,
	0x49, 0x6e, 0x66, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x12, 0x1a, 0x0a, 0x08, 0x68, 0x6f, 0x73, 0x74,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x68, 0x6f, 0x73, 0x74,
	0x6e, 0x61, 0x6d, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x70, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x70, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x67, 0x69,
	0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x67, 0x69, 0x64, 0x22, 0xe0, 0x01, 0x0a,
	0x07, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x1a, 0x4e, 0x0a, 0x07, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x2f, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x41,
	0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x07, 0x63, 0x6f, 0x6d,
	0x6d, 0x61, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x1a, 0x84, 0x01, 0x0a, 0x08, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2f, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74,
	0x2e, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x52, 0x07, 0x63,
	0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x33, 0x0a, 0x06, 0x73, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1b, 0x2e, 0x69, 0x6d, 0x70,
	0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e,
	0x64, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2a,
	0xaa, 0x02, 0x0a, 0x0c, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
	0x12, 0x1d, 0x0a, 0x19, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e,
	0x44, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12,
	0x19, 0x0a, 0x15, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44,
	0x5f, 0x43, 0x48, 0x45, 0x43, 0x4b, 0x49, 0x4e, 0x10, 0x01, 0x12, 0x19, 0x0a, 0x15, 0x41, 0x47,
	0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x5f, 0x53, 0x59, 0x53, 0x49,
	0x4e, 0x46, 0x4f, 0x10, 0x02, 0x12, 0x19, 0x0a, 0x15, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43,
	0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x5f, 0x45, 0x58, 0x45, 0x43, 0x55, 0x54, 0x45, 0x10, 0x03,
	0x12, 0x23, 0x0a, 0x1f, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e,
	0x44, 0x5f, 0x45, 0x58, 0x45, 0x43, 0x55, 0x54, 0x45, 0x5f, 0x53, 0x48, 0x45, 0x4c, 0x4c, 0x43,
	0x4f, 0x44, 0x45, 0x10, 0x04, 0x12, 0x19, 0x0a, 0x15, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43,
	0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x5f, 0x4d, 0x45, 0x53, 0x53, 0x41, 0x47, 0x45, 0x10, 0x05,
	0x12, 0x1a, 0x0a, 0x16, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e,
	0x44, 0x5f, 0x53, 0x48, 0x55, 0x54, 0x44, 0x4f, 0x57, 0x4e, 0x10, 0x06, 0x12, 0x16, 0x0a, 0x12,
	0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x5f, 0x4b, 0x45,
	0x59, 0x58, 0x10, 0x07, 0x12, 0x1c, 0x0a, 0x18, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f,
	0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x5f, 0x53, 0x45, 0x54, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x47,
	0x10, 0x08, 0x12, 0x18, 0x0a, 0x14, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x4f, 0x4d, 0x4d,
	0x41, 0x4e, 0x44, 0x5f, 0x49, 0x47, 0x4e, 0x4f, 0x52, 0x45, 0x10, 0x09, 0x2a, 0xe2, 0x02, 0x0a,
	0x10, 0x43, 0x32, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x12, 0x19, 0x0a, 0x15, 0x43, 0x32, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55,
	0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e,
	0x4e, 0x45, 0x45, 0x44, 0x5f, 0x4d, 0x4f, 0x52, 0x45, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x10, 0x01,
	0x12, 0x11, 0x0a, 0x0d, 0x44, 0x41, 0x54, 0x41, 0x5f, 0x52, 0x45, 0x43, 0x45, 0x49, 0x56, 0x45,
	0x44, 0x10, 0x02, 0x12, 0x0b, 0x0a, 0x07, 0x4e, 0x4f, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x10, 0x03,
	0x12, 0x17, 0x0a, 0x13, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x49, 0x4d, 0x50, 0x4f, 0x52, 0x54,
	0x49, 0x4e, 0x47, 0x5f, 0x4b, 0x45, 0x59, 0x10, 0x04, 0x12, 0x19, 0x0a, 0x15, 0x45, 0x52, 0x52,
	0x4f, 0x52, 0x5f, 0x44, 0x45, 0x52, 0x49, 0x56, 0x49, 0x4e, 0x47, 0x5f, 0x53, 0x45, 0x43, 0x52,
	0x45, 0x54, 0x10, 0x05, 0x12, 0x1c, 0x0a, 0x18, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x44, 0x45,
	0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4e, 0x47, 0x5f, 0x4d, 0x45, 0x53, 0x53, 0x41, 0x47, 0x45,
	0x10, 0x06, 0x12, 0x19, 0x0a, 0x15, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x47, 0x45, 0x4e, 0x45,
	0x52, 0x41, 0x54, 0x49, 0x4e, 0x47, 0x5f, 0x4b, 0x45, 0x59, 0x53, 0x10, 0x07, 0x12, 0x19, 0x0a,
	0x15, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x4d,
	0x45, 0x53, 0x53, 0x41, 0x47, 0x45, 0x10, 0x08, 0x12, 0x17, 0x0a, 0x13, 0x45, 0x52, 0x52, 0x4f,
	0x52, 0x5f, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10,
	0x09, 0x12, 0x15, 0x0a, 0x11, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x48, 0x45, 0x43, 0x4b,
	0x49, 0x4e, 0x47, 0x5f, 0x49, 0x4e, 0x10, 0x0a, 0x12, 0x1a, 0x0a, 0x16, 0x45, 0x52, 0x52, 0x4f,
	0x52, 0x5f, 0x4b, 0x45, 0x59, 0x58, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x41, 0x4c, 0x4c, 0x4f, 0x57,
	0x45, 0x44, 0x10, 0x0b, 0x12, 0x19, 0x0a, 0x15, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x49, 0x4e,
	0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x53, 0x59, 0x53, 0x49, 0x4e, 0x46, 0x4f, 0x10, 0x0c, 0x12,
	0x10, 0x0a, 0x0c, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x45, 0x44, 0x10,
	0x0d, 0x2a, 0x6a, 0x0a, 0x12, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e,
	0x64, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x1e, 0x0a, 0x1a, 0x43, 0x4f, 0x4d, 0x4d, 0x41,
	0x4e, 0x44, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43,
	0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1a, 0x0a, 0x16, 0x43, 0x4f, 0x4d, 0x4d, 0x41,
	0x4e, 0x44, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x45, 0x53,
	0x53, 0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x43, 0x4f, 0x4d, 0x4d, 0x41, 0x4e, 0x44, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x02, 0x42, 0x0b, 0x5a,
	0x09, 0x2e, 0x2f, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_implant_proto_rawDescOnce sync.Once
	file_implant_proto_rawDescData = file_implant_proto_rawDesc
)

func file_implant_proto_rawDescGZIP() []byte {
	file_implant_proto_rawDescOnce.Do(func() {
		file_implant_proto_rawDescData = protoimpl.X.CompressGZIP(file_implant_proto_rawDescData)
	})
	return file_implant_proto_rawDescData
}

var file_implant_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_implant_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_implant_proto_goTypes = []interface{}{
	(AgentCommand)(0),              // 0: implant.AgentCommand
	(C2ResponseStatus)(0),          // 1: implant.C2ResponseStatus
	(AgentCommandStatus)(0),        // 2: implant.AgentCommandStatus
	(*AgentConfig)(nil),            // 3: implant.AgentConfig
	(*SysInfoData)(nil),            // 4: implant.SysInfoData
	(*Command)(nil),                // 5: implant.Command
	(*Command_Request)(nil),        // 6: implant.Command.Request
	(*Command_Response)(nil),       // 7: implant.Command.Response
	(*wrapperspb.StringValue)(nil), // 8: google.protobuf.StringValue
	(*wrapperspb.UInt32Value)(nil), // 9: google.protobuf.UInt32Value
	(*wrapperspb.BoolValue)(nil),   // 10: google.protobuf.BoolValue
}
var file_implant_proto_depIdxs = []int32{
	8,  // 0: implant.AgentConfig.resolver:type_name -> google.protobuf.StringValue
	9,  // 1: implant.AgentConfig.c2_interval_ms:type_name -> google.protobuf.UInt32Value
	10, // 2: implant.AgentConfig.use_web_channel:type_name -> google.protobuf.BoolValue
	8,  // 3: implant.AgentConfig.web_url:type_name -> google.protobuf.StringValue
	8,  // 4: implant.AgentConfig.web_key:type_name -> google.protobuf.StringValue
	10, // 5: implant.AgentConfig.throttle_sendq:type_name -> google.protobuf.BoolValue
	0,  // 6: implant.Command.Request.command:type_name -> implant.AgentCommand
	0,  // 7: implant.Command.Response.command:type_name -> implant.AgentCommand
	2,  // 8: implant.Command.Response.status:type_name -> implant.AgentCommandStatus
	9,  // [9:9] is the sub-list for method output_type
	9,  // [9:9] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_implant_proto_init() }
func file_implant_proto_init() {
	if File_implant_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_implant_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AgentConfig); i {
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
		file_implant_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SysInfoData); i {
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
		file_implant_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Command); i {
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
		file_implant_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Command_Request); i {
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
		file_implant_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Command_Response); i {
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
			RawDescriptor: file_implant_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_implant_proto_goTypes,
		DependencyIndexes: file_implant_proto_depIdxs,
		EnumInfos:         file_implant_proto_enumTypes,
		MessageInfos:      file_implant_proto_msgTypes,
	}.Build()
	File_implant_proto = out.File
	file_implant_proto_rawDesc = nil
	file_implant_proto_goTypes = nil
	file_implant_proto_depIdxs = nil
}
