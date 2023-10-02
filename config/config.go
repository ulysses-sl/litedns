package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

const TLDListURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
const MaxConfigFileSize = 4096
const DefaultMinTTL = 600
const DefaultMaxTTL = 86400
const PortMin = 1
const PortMax = 65535
const DefaultListenPort = 53

type DNSProto string

const (
	UDPProto string = "udp"
	TCPProto        = "tcp"
	TLSProto        = "tcp-tls"
)

var DNSProtoLookup = map[string]struct{}{
	UDPProto: {},
	TCPProto: {},
	TLSProto: {},
}

func (p *DNSProto) UnmarshalJSON(b []byte) error {
	var proto string
	err := json.Unmarshal(b, &proto)
	if err != nil {
		return err
	}
	if _, ok := DNSProtoLookup[proto]; !ok {
		return fmt.Errorf("invalid protocol: %s", proto)
	}
	*p = DNSProto(proto)
	return nil
}

type RecordType struct {
	Name  string
	Value uint16
}

const (
	TypeA     string = "A"
	TypeAAAA         = "AAAA"
	TypeCNAME        = "CNAME"
	TypeMX           = "MX"
	TypeNS           = "NS"
	TypePTR          = "PTR"
	TypeSOA          = "SOA"
	TypeSRV          = "SRV"
	TypeTXT          = "TXT"
)

var RecordStrToType = map[string]RecordType{
	TypeA:     {Name: TypeA, Value: dns.TypeA},
	TypeAAAA:  {Name: TypeAAAA, Value: dns.TypeAAAA},
	TypeCNAME: {Name: TypeCNAME, Value: dns.TypeCNAME},
	TypeMX:    {Name: TypeMX, Value: dns.TypeMX},
	TypeNS:    {Name: TypeNS, Value: dns.TypeNS},
	TypePTR:   {Name: TypePTR, Value: dns.TypePTR},
	TypeSOA:   {Name: TypeSOA, Value: dns.TypeSOA},
	TypeSRV:   {Name: TypeSRV, Value: dns.TypeSRV},
	TypeTXT:   {Name: TypeTXT, Value: dns.TypeTXT},
}

func (rt *RecordType) UnmarshalJSON(b []byte) error {
	var rtStr string
	err := json.Unmarshal(b, &rtStr)
	if err != nil {
		return err
	}
	recType, ok := RecordStrToType[rtStr]
	if ok {
		*rt = recType
		return nil
	}
	return errors.New("invalid DNS record type: " + rtStr)
}

type IPAddr net.IP

func (addr *IPAddr) UnmarshalJSON(b []byte) error {
	var addrStr string
	err := json.Unmarshal(b, &addrStr)
	if err != nil {
		return err
	}
	parsed := net.ParseIP(addrStr)
	if parsed == nil {
		return errors.New("invalid IP address: " + addrStr)
	}
	v4Addr := parsed.To4()
	if v4Addr != nil {
		if strings.Contains(v4Addr.String(), ":") {
			return errors.New("the IP address should not include the port: " +
				" " + addrStr)
		}
	} else if strings.Contains(parsed.String(), "[") {
		return errors.New("the IP address should not include the port: " +
			" " + addrStr)
	}
	*addr = IPAddr(parsed)
	return nil
}

type INetPort uint16

func (p *INetPort) UnmarshalJSON(b []byte) error {
	var port int
	err := json.Unmarshal(b, &port)
	if err != nil {
		return err
	}
	if port < PortMin || port > PortMax {
		return fmt.Errorf("invalid port number: %d", port)
	}
	*p = INetPort(port)
	return nil
}

type LiteDNSConfig struct {
	UpstreamServers   []*ServerConfig
	LocalNameServers  []*ServerConfig
	AdBlocker         *AdBlockerConfig
	CachedRecordTypes []uint16
	MinTTL            int64
	MaxTTL            int64
	ListenIP          net.IP
	ListenPort        uint16
}

type jsonMainConfig struct {
	UpstreamServers   []*jsonServerConfig `json:"upstreamServer"`
	LocalNameServers  []*jsonServerConfig `json:"localNameServer"`
	AdBlocker         *jsonABConfig       `json:"adBlocker"`
	CachedRecordTypes []*RecordType       `json:"cachedRecordTypes"`
	MinTTL            int64               `json:"minTTL"`
	MaxTTL            int64               `json:"maxTTL"`
	ListenIP          IPAddr              `json:"listenIP"`
	ListenPort        INetPort            `json:"listenPort"`
}

func (jcfg *jsonMainConfig) toConfig() *LiteDNSConfig {
	var acfg *AdBlockerConfig
	usrv := make([]*ServerConfig, len(jcfg.UpstreamServers))
	for _, s := range jcfg.UpstreamServers {
		if s == nil {
			log.Fatal("Invalid upstream server configuration")
		}
		usrv = append(usrv, s.toConfig())
	}
	lsrv := make([]*ServerConfig, len(jcfg.LocalNameServers))
	for _, s := range jcfg.LocalNameServers {
		if s == nil {
			log.Fatal("Invalid upstream server configuration")
		}
		lsrv = append(usrv, s.toConfig())
	}
	if jcfg.AdBlocker != nil {
		acfg = jcfg.AdBlocker.toConfig()
	}
	ctypes := make([]uint16, len(jcfg.CachedRecordTypes))
	for _, t := range jcfg.CachedRecordTypes {
		if t == nil {
			log.Fatal("Invalid upstream server configuration")
		}
		ctypes = append(ctypes, t.Value)
	}
	cfg := &LiteDNSConfig{
		UpstreamServers:   usrv,
		LocalNameServers:  lsrv,
		AdBlocker:         acfg,
		CachedRecordTypes: ctypes,
		MinTTL:            jcfg.MinTTL,
		MaxTTL:            jcfg.MaxTTL,
		ListenIP:          net.IP(jcfg.ListenIP),
		ListenPort:        uint16(jcfg.ListenPort),
	}
	return cfg
}

type ServerConfig struct {
	IP    net.IP
	Port  uint16
	Proto string
}

func (sc *ServerConfig) String() string {
	return JoinIPPort(sc.IP, sc.Port)
}

type jsonServerConfig struct {
	IP    IPAddr   `json:"serverIP"`
	Port  INetPort `json:"serverPort"`
	Proto DNSProto `json:"protocol"`
}

func (jcfg *jsonServerConfig) toConfig() *ServerConfig {
	cfg := &ServerConfig{
		IP:    net.IP(jcfg.IP),
		Port:  uint16(jcfg.Port),
		Proto: string(jcfg.Proto),
	}
	return cfg
}

type AdBlockerConfig struct {
	BlockListUrl string
	SinkIP4      net.IP
	SinkIP6      net.IP
}

type jsonABConfig struct {
	BlockListUrl string `json:"blockListUrl"`
	SinkIP4      IPAddr `json:"sinkIP4"`
	SinkIP6      IPAddr `json:"sinkIP6"`
}

func (jcfg *jsonABConfig) toConfig() *AdBlockerConfig {
	cfg := &AdBlockerConfig{
		BlockListUrl: jcfg.BlockListUrl,
		SinkIP4:      net.IP(jcfg.SinkIP4),
		SinkIP6:      net.IP(jcfg.SinkIP6),
	}
	return cfg
}

func LoadConfig(filename string) (config *LiteDNSConfig, err error) {
	configFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := configFile.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	stat, err := configFile.Stat()
	if err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, errors.New("The file is a directory: " + filename)
	}
	if stat.Size() > MaxConfigFileSize {
		return nil, errors.New("The file is too big: " + filename)
	}
	byteValue, err := io.ReadAll(configFile)
	if err != nil {
		return nil, err
	}
	var jcfg jsonMainConfig
	if jerr := json.Unmarshal(byteValue, &jcfg); jerr != nil {
		return nil, jerr
	}
	if verr := VerifyConfig(&jcfg); verr != nil {
		return nil, verr
	}
	cfg := jcfg.toConfig()
	return cfg, nil
}

func VerifyConfig(config *jsonMainConfig) error {
	if config.MinTTL < 0 {
		return fmt.Errorf("min TTL should be non-negative: %d",
			config.MinTTL)
	}
	if config.MinTTL > DefaultMaxTTL {
		return fmt.Errorf("min TTL cannot exceed %d: %d",
			DefaultMaxTTL,
			config.MinTTL)
	}
	if config.MinTTL == 0 {
		config.MinTTL = DefaultMinTTL
	}
	if config.MaxTTL < 0 {
		return fmt.Errorf("max TTL should be non-negative: %d",
			config.MaxTTL)
	}
	if config.MaxTTL > DefaultMaxTTL {
		return fmt.Errorf("max TTL cannot exceed %d: %d",
			DefaultMaxTTL,
			config.MaxTTL)
	}
	if config.MaxTTL == 0 {
		config.MaxTTL = DefaultMaxTTL
	}
	if config.MaxTTL < config.MinTTL {
		return fmt.Errorf("max TTL %d is smaller than min TTL %d",
			config.MaxTTL,
			config.MinTTL)
	}
	if config.ListenPort == 0 {
		config.ListenPort = DefaultListenPort
	}
	return nil
}
