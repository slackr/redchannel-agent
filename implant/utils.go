package implant

import (
	"encoding/hex"
	"net"
	"strconv"
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
func ExpandIPv6(ip net.IP) string {
	dst := make([]byte, hex.EncodedLen(len(ip)))
	_ = hex.Encode(dst, ip)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}
