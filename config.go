package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

const TLDListURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
const MaxConfigFileSize = 4096
const DefaultCacheTTL = 600
const DefaultMinTTL = 600
const DefaultMaxTTL = 86400
const PortMin = 1
const PortMax = 65535
const DefaultListenPort = 53

/*
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
*/

type LiteDNSConfig struct {
	UpstreamServers  []*ServerConfig  `json:"upstreamServer"`
	LocalNameServers []*ServerConfig  `json:"localNameServer"`
	AdBlocker        *AdBlockerConfig `json:"adBlocker"`
	//CachedRecordTypes []*RecordType    `json:"cachedRecordTypes"`
	CacheTTL int64 `json:"cacheTTL"`
	//MinTTL            uint32           `json:"minTTL"`
	//MaxTTL            uint32           `json:"maxTTL"`
	ListenIP    net.IP `json:"listenIP"`
	ListenPort  uint16 `json:"listenPort"`
	ListenProto string `json:"listenProtocol"`
}

type ServerConfig struct {
	IP    net.IP
	Port  uint16
	Proto string
}

func (sc *ServerConfig) String() string {
	if ipv4 := sc.IP.To4(); ipv4 != nil {
		return fmt.Sprintf("%s:%d", ipv4.String(), sc.Port)
	} else {
		return fmt.Sprintf("[%s]:%d", sc.IP.String(), sc.Port)
	}
}

type AdBlockerConfig struct {
	ABPFilterURL string `json:"abpFilterURL"`
	SinkIP4      net.IP `json:"sinkIP4"`
	SinkIP6      net.IP `json:"sinkIP6"`
}

func LoadConfig(filename string) (_ *LiteDNSConfig, err error) {
	var configFile *os.File
	configFile, err = os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := configFile.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	var stat os.FileInfo
	stat, err = configFile.Stat()
	if err != nil {
		return nil, err
	}
	if stat.IsDir() {
		return nil, errors.New("The file is a directory: " + filename)
	}
	if stat.Size() > MaxConfigFileSize {
		return nil, errors.New("The file is too big: " + filename)
	}
	var byteValue []byte
	byteValue, err = io.ReadAll(configFile)
	if err != nil {
		return nil, err
	}
	var cfg LiteDNSConfig
	if err = json.Unmarshal(byteValue, &cfg); err != nil {
		return nil, err
	}
	if err = VerifyConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func VerifyConfig(config *LiteDNSConfig) error {
	/*
		if config.MinTTL == 0 {
			config.MinTTL = DefaultMinTTL
		}
		if config.MaxTTL == 0 {
			config.MaxTTL = DefaultMaxTTL
		}
	*/
	if config.CacheTTL <= 0 {
		config.CacheTTL = DefaultCacheTTL
	}
	if config.CacheTTL > DefaultMaxTTL {
		config.CacheTTL = DefaultMaxTTL
	}
	if config.CacheTTL < DefaultMinTTL {
		config.CacheTTL = DefaultMinTTL
	}

	/*
		if config.MinTTL > DefaultMaxTTL {
			return fmt.Errorf("min TTL should be between 0 and %d: %d",
				DefaultMaxTTL,
				config.MinTTL)
		}
		if config.MaxTTL > DefaultMaxTTL {
			return fmt.Errorf("max TTL should be between 0 and %d: %d",
				DefaultMaxTTL,
				config.MaxTTL)
		}
		if config.MaxTTL < config.MinTTL {
			return fmt.Errorf("max TTL %d should be greater or equal to min TTL %d",
				config.MaxTTL,
				config.MinTTL)
		}
	*/

	/*
		if len(config.CachedRecordTypes) == 0 {
			return fmt.Errorf("no DNS record type was specified for caching")
		}
		seenRecTypes := make(map[uint16]struct{}, len(RecordStrToType))
		for _, rt := range config.CachedRecordTypes {
			if _, seen := seenRecTypes[rt.Value]; seen {
				return fmt.Errorf(
					"duplicate record types was specified to be cached: %s",
					rt.Name)
			}
			seenRecTypes[rt.Value] = struct{}{}
		}
	*/

	if len(config.UpstreamServers) == 0 {
		return fmt.Errorf("no upstream DNS server was specified")
	}
	seenUpstreamSrv := make(map[string]struct{}, len(config.UpstreamServers))
	for _, srv := range config.UpstreamServers {
		ipStr := srv.IP.String()
		if _, seen := seenUpstreamSrv[ipStr]; seen {
			return fmt.Errorf(
				"duplicate upstream DNS server: %s", ipStr)
		}
		seenUpstreamSrv[ipStr] = struct{}{}
	}

	seenLocalSrv := make(map[string]struct{}, len(config.LocalNameServers))
	for _, srv := range config.LocalNameServers {
		ipStr := srv.IP.String()
		if _, seen := seenLocalSrv[ipStr]; seen {
			return fmt.Errorf(
				"duplicate local network DNS server: %s", ipStr)
		}
		seenLocalSrv[ipStr] = struct{}{}
	}

	if config.ListenPort == 0 {
		config.ListenPort = DefaultListenPort
	}
	return nil
}
