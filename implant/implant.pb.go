// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.9
// source: implant.proto

package implant

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

type AgentCommand int32

const (
	AgentCommand_AGENT_UNSPECIFIED       AgentCommand = 0
	AgentCommand_AGENT_CHECKIN           AgentCommand = 1
	AgentCommand_AGENT_SYSINFO           AgentCommand = 2
	AgentCommand_AGENT_EXECUTE           AgentCommand = 3
	AgentCommand_AGENT_EXECUTE_SHELLCODE AgentCommand = 4
	AgentCommand_AGENT_MESSAGE           AgentCommand = 5
	AgentCommand_AGENT_SHUTDOWN          AgentCommand = 6
	AgentCommand_AGENT_KEYX              AgentCommand = 7
	AgentCommand_AGENT_SET_CONFIG        AgentCommand = 8
	AgentCommand_AGENT_IGNORE            AgentCommand = 9
)

// Enum value maps for AgentCommand.
var (
	AgentCommand_name = map[int32]string{
		0: "AGENT_UNSPECIFIED",
		1: "AGENT_CHECKIN",
		2: "AGENT_SYSINFO",
		3: "AGENT_EXECUTE",
		4: "AGENT_EXECUTE_SHELLCODE",
		5: "AGENT_MESSAGE",
		6: "AGENT_SHUTDOWN",
		7: "AGENT_KEYX",
		8: "AGENT_SET_CONFIG",
		9: "AGENT_IGNORE",
	}
	AgentCommand_value = map[string]int32{
		"AGENT_UNSPECIFIED":       0,
		"AGENT_CHECKIN":           1,
		"AGENT_SYSINFO":           2,
		"AGENT_EXECUTE":           3,
		"AGENT_EXECUTE_SHELLCODE": 4,
		"AGENT_MESSAGE":           5,
		"AGENT_SHUTDOWN":          6,
		"AGENT_KEYX":              7,
		"AGENT_SET_CONFIG":        8,
		"AGENT_IGNORE":            9,
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

type AgentCommandStatus int32

const (
	AgentCommandStatus_STATUS_UNSPECIFIED AgentCommandStatus = 0
	AgentCommandStatus_STATUS_SUCCESS     AgentCommandStatus = 1
	AgentCommandStatus_STATUS_ERROR       AgentCommandStatus = 2
)

// Enum value maps for AgentCommandStatus.
var (
	AgentCommandStatus_name = map[int32]string{
		0: "STATUS_UNSPECIFIED",
		1: "STATUS_SUCCESS",
		2: "STATUS_ERROR",
	}
	AgentCommandStatus_value = map[string]int32{
		"STATUS_UNSPECIFIED": 0,
		"STATUS_SUCCESS":     1,
		"STATUS_ERROR":       2,
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
	return file_implant_proto_enumTypes[1].Descriptor()
}

func (AgentCommandStatus) Type() protoreflect.EnumType {
	return &file_implant_proto_enumTypes[1]
}

func (x AgentCommandStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AgentCommandStatus.Descriptor instead.
func (AgentCommandStatus) EnumDescriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{1}
}

type AgentConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	C2Domain      string `protobuf:"bytes,1,opt,name=c2_domain,json=c2Domain,proto3" json:"c2_domain,omitempty"`
	C2Password    string `protobuf:"bytes,2,opt,name=c2_password,json=c2Password,proto3" json:"c2_password,omitempty"`
	Resolver      string `protobuf:"bytes,3,opt,name=resolver,proto3" json:"resolver,omitempty"`
	C2IntervalMs  uint32 `protobuf:"varint,4,opt,name=c2_interval_ms,json=c2IntervalMs,proto3" json:"c2_interval_ms,omitempty"`
	UseWebChannel bool   `protobuf:"varint,5,opt,name=use_web_channel,json=useWebChannel,proto3" json:"use_web_channel,omitempty"`
	WebUrl        string `protobuf:"bytes,6,opt,name=web_url,json=webUrl,proto3" json:"web_url,omitempty"`
	WebKey        string `protobuf:"bytes,7,opt,name=web_key,json=webKey,proto3" json:"web_key,omitempty"`
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

func (x *AgentConfig) GetResolver() string {
	if x != nil {
		return x.Resolver
	}
	return ""
}

func (x *AgentConfig) GetC2IntervalMs() uint32 {
	if x != nil {
		return x.C2IntervalMs
	}
	return 0
}

func (x *AgentConfig) GetUseWebChannel() bool {
	if x != nil {
		return x.UseWebChannel
	}
	return false
}

func (x *AgentConfig) GetWebUrl() string {
	if x != nil {
		return x.WebUrl
	}
	return ""
}

func (x *AgentConfig) GetWebKey() string {
	if x != nil {
		return x.WebKey
	}
	return ""
}

// c2 and agent communicate via Command messages
// Request message comes from the c2 and instructs the agent what to do
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
		mi := &file_implant_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command) ProtoMessage() {}

func (x *Command) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Command.ProtoReflect.Descriptor instead.
func (*Command) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{1}
}

type Command_Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Command AgentCommand `protobuf:"varint,1,opt,name=command,proto3,enum=implant.AgentCommand" json:"command,omitempty"`
	Input   []byte       `protobuf:"bytes,2,opt,name=input,proto3" json:"input,omitempty"`
	Config  *AgentConfig `protobuf:"bytes,3,opt,name=config,proto3" json:"config,omitempty"`
}

func (x *Command_Request) Reset() {
	*x = Command_Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_implant_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command_Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command_Request) ProtoMessage() {}

func (x *Command_Request) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Command_Request.ProtoReflect.Descriptor instead.
func (*Command_Request) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{1, 0}
}

func (x *Command_Request) GetCommand() AgentCommand {
	if x != nil {
		return x.Command
	}
	return AgentCommand_AGENT_UNSPECIFIED
}

func (x *Command_Request) GetInput() []byte {
	if x != nil {
		return x.Input
	}
	return nil
}

func (x *Command_Request) GetConfig() *AgentConfig {
	if x != nil {
		return x.Config
	}
	return nil
}

type Command_Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Command AgentCommand       `protobuf:"varint,1,opt,name=command,proto3,enum=implant.AgentCommand" json:"command,omitempty"`
	Output  []byte             `protobuf:"bytes,2,opt,name=output,proto3" json:"output,omitempty"`
	Status  AgentCommandStatus `protobuf:"varint,4,opt,name=status,proto3,enum=implant.AgentCommandStatus" json:"status,omitempty"`
}

func (x *Command_Response) Reset() {
	*x = Command_Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_implant_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Command_Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Command_Response) ProtoMessage() {}

func (x *Command_Response) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Command_Response.ProtoReflect.Descriptor instead.
func (*Command_Response) Descriptor() ([]byte, []int) {
	return file_implant_proto_rawDescGZIP(), []int{1, 1}
}

func (x *Command_Response) GetCommand() AgentCommand {
	if x != nil {
		return x.Command
	}
	return AgentCommand_AGENT_UNSPECIFIED
}

func (x *Command_Response) GetOutput() []byte {
	if x != nil {
		return x.Output
	}
	return nil
}

func (x *Command_Response) GetStatus() AgentCommandStatus {
	if x != nil {
		return x.Status
	}
	return AgentCommandStatus_STATUS_UNSPECIFIED
}

var File_implant_proto protoreflect.FileDescriptor

var file_implant_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x07, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x22, 0xe7, 0x01, 0x0a, 0x0b, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x32, 0x5f, 0x64,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x32, 0x44,
	0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x32, 0x5f, 0x70, 0x61, 0x73, 0x73,
	0x77, 0x6f, 0x72, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x32, 0x50, 0x61,
	0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76,
	0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76,
	0x65, 0x72, 0x12, 0x24, 0x0a, 0x0e, 0x63, 0x32, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61,
	0x6c, 0x5f, 0x6d, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x63, 0x32, 0x49, 0x6e,
	0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x4d, 0x73, 0x12, 0x26, 0x0a, 0x0f, 0x75, 0x73, 0x65, 0x5f,
	0x77, 0x65, 0x62, 0x5f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0d, 0x75, 0x73, 0x65, 0x57, 0x65, 0x62, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c,
	0x12, 0x17, 0x0a, 0x07, 0x77, 0x65, 0x62, 0x5f, 0x75, 0x72, 0x6c, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x77, 0x65, 0x62, 0x55, 0x72, 0x6c, 0x12, 0x17, 0x0a, 0x07, 0x77, 0x65, 0x62,
	0x5f, 0x6b, 0x65, 0x79, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x77, 0x65, 0x62, 0x4b,
	0x65, 0x79, 0x22, 0x94, 0x02, 0x0a, 0x07, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x1a, 0x7e,
	0x0a, 0x07, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2f, 0x0a, 0x07, 0x63, 0x6f, 0x6d,
	0x6d, 0x61, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x69, 0x6d, 0x70,
	0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e,
	0x64, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e,
	0x70, 0x75, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x69, 0x6e, 0x70, 0x75, 0x74,
	0x12, 0x2c, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x14, 0x2e, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x41, 0x67, 0x65, 0x6e, 0x74,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x1a, 0x88,
	0x01, 0x0a, 0x08, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2f, 0x0a, 0x07, 0x63,
	0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x69,
	0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d,
	0x61, 0x6e, 0x64, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x12, 0x16, 0x0a, 0x06,
	0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x6f, 0x75,
	0x74, 0x70, 0x75, 0x74, 0x12, 0x33, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x1b, 0x2e, 0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x2e, 0x41,
	0x67, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2a, 0xda, 0x01, 0x0a, 0x0c, 0x41, 0x67,
	0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x12, 0x15, 0x0a, 0x11, 0x41, 0x47,
	0x45, 0x4e, 0x54, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10,
	0x00, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x43, 0x48, 0x45, 0x43, 0x4b,
	0x49, 0x4e, 0x10, 0x01, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x59,
	0x53, 0x49, 0x4e, 0x46, 0x4f, 0x10, 0x02, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x47, 0x45, 0x4e, 0x54,
	0x5f, 0x45, 0x58, 0x45, 0x43, 0x55, 0x54, 0x45, 0x10, 0x03, 0x12, 0x1b, 0x0a, 0x17, 0x41, 0x47,
	0x45, 0x4e, 0x54, 0x5f, 0x45, 0x58, 0x45, 0x43, 0x55, 0x54, 0x45, 0x5f, 0x53, 0x48, 0x45, 0x4c,
	0x4c, 0x43, 0x4f, 0x44, 0x45, 0x10, 0x04, 0x12, 0x11, 0x0a, 0x0d, 0x41, 0x47, 0x45, 0x4e, 0x54,
	0x5f, 0x4d, 0x45, 0x53, 0x53, 0x41, 0x47, 0x45, 0x10, 0x05, 0x12, 0x12, 0x0a, 0x0e, 0x41, 0x47,
	0x45, 0x4e, 0x54, 0x5f, 0x53, 0x48, 0x55, 0x54, 0x44, 0x4f, 0x57, 0x4e, 0x10, 0x06, 0x12, 0x0e,
	0x0a, 0x0a, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x4b, 0x45, 0x59, 0x58, 0x10, 0x07, 0x12, 0x14,
	0x0a, 0x10, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x53, 0x45, 0x54, 0x5f, 0x43, 0x4f, 0x4e, 0x46,
	0x49, 0x47, 0x10, 0x08, 0x12, 0x10, 0x0a, 0x0c, 0x41, 0x47, 0x45, 0x4e, 0x54, 0x5f, 0x49, 0x47,
	0x4e, 0x4f, 0x52, 0x45, 0x10, 0x09, 0x2a, 0x52, 0x0a, 0x12, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x43,
	0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x16, 0x0a, 0x12,
	0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49,
	0x45, 0x44, 0x10, 0x00, 0x12, 0x12, 0x0a, 0x0e, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x53,
	0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x53, 0x54, 0x41, 0x54,
	0x55, 0x53, 0x5f, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x10, 0x02, 0x42, 0x0b, 0x5a, 0x09, 0x2e, 0x2f,
	0x69, 0x6d, 0x70, 0x6c, 0x61, 0x6e, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_implant_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_implant_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_implant_proto_goTypes = []interface{}{
	(AgentCommand)(0),        // 0: implant.AgentCommand
	(AgentCommandStatus)(0),  // 1: implant.AgentCommandStatus
	(*AgentConfig)(nil),      // 2: implant.AgentConfig
	(*Command)(nil),          // 3: implant.Command
	(*Command_Request)(nil),  // 4: implant.Command.Request
	(*Command_Response)(nil), // 5: implant.Command.Response
}
var file_implant_proto_depIdxs = []int32{
	0, // 0: implant.Command.Request.command:type_name -> implant.AgentCommand
	2, // 1: implant.Command.Request.config:type_name -> implant.AgentConfig
	0, // 2: implant.Command.Response.command:type_name -> implant.AgentCommand
	1, // 3: implant.Command.Response.status:type_name -> implant.AgentCommandStatus
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
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
		file_implant_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
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
		file_implant_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
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
			NumEnums:      2,
			NumMessages:   4,
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