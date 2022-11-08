package implant

import (
	"encoding/hex"
	"net"
	"strconv"

	"google.golang.org/protobuf/proto"
)

func BytesToHexString(bytes []byte) string {
	s := hex.EncodeToString(bytes)
	return s
}

func HexStringToBytes(str string) ([]byte, error) {
	b, err := hex.DecodeString(str)
	if err != nil {
		return []byte{}, err
	}
	return b, nil
}

func HexBytesToInt(str string) (int, error) {
	i, err := strconv.ParseInt(str, 16, 32)
	if err != nil {
		return 0, err
	}
	return int(i), nil
}

// https://play.golang.org/p/Ov5ESWCopND
func ExpandIPv6(ipv6 net.IP) string {
	buffer := make([]byte, hex.EncodedLen(len(ipv6)))
	_ = hex.Encode(buffer, ipv6)
	return string(buffer[0:4]) + ":" +
		string(buffer[4:8]) + ":" +
		string(buffer[8:12]) + ":" +
		string(buffer[12:16]) + ":" +
		string(buffer[16:20]) + ":" +
		string(buffer[20:24]) + ":" +
		string(buffer[24:28]) + ":" +
		string(buffer[28:])
}

func unmarshalCommandRequest(data []byte) (*Command_Request, error) {
	commandRequest := &Command_Request{}
	err := proto.Unmarshal(data, commandRequest)
	if err != nil {
		return nil, err
	}
	return commandRequest, nil
}
