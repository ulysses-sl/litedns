package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"os"
)

const TLDListURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
const MaxConfigFileSize = 4096
const DefaultCacheTTL = 600
const DefaultMinTTL = 600
const DefaultMaxTTL = 86400
const DefaultNegativeCacheTTL = 10
const DefaultCachePurgeInterval = 600
const DefaultCacheCompactInterval = 1800
const PortMin = 1
const PortMax = 65535
const DefaultListenPort = 53

type RecordType struct {
	Name  string
	Value uint16
}

var RecordStrToType map[string]RecordType

func InitRecordStrToType() {
	if RecordStrToType != nil {
		return
	}
	RecordStrToType = make(map[string]RecordType)
	for rType, rTypeStr := range dns.TypeToString {
		RecordStrToType[rTypeStr] = RecordType{
			Name:  rTypeStr,
			Value: rType,
		}
	}
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

type LiteDNSConfig struct {
	UpstreamServers  []*ServerConfig  `json:"upstreamServers"`
	LocalNameServers []*ServerConfig  `json:"LocalNameServers"`
	AdBlocker        *AdBlockerConfig `json:"adBlocker"`
	CacheConfig      *DNSCacheConfig  `json:"cacheConfig"`
	ListenerConfig   *ServerConfig    `json:"listenerConfig"`
}

type ServerConfig struct {
	IP    net.IP `json:"ip"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
}

type AdBlockerConfig struct {
	ABPFilterURL string `json:"abpFilterURL"`
	SinkIP4      net.IP `json:"sinkIP4"`
	SinkIP6      net.IP `json:"sinkIP6"`
}

type DNSCacheConfig struct {
	CacheSize   int           `json:"cacheSize"`
	CacheTTL    int64         `json:"cacheTTL"`
	RecordTypes []*RecordType `json:"recordTypes"`
}

func (sc *ServerConfig) String() string {
	if ipv4 := sc.IP.To4(); ipv4 != nil {
		return fmt.Sprintf("%s:%d", ipv4.String(), sc.Port)
	} else {
		return fmt.Sprintf("[%s]:%d", sc.IP.String(), sc.Port)
	}
}

func LoadConfig(filename string) (_ *LiteDNSConfig, err error) {
	InitRecordStrToType()
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
	if config.CacheConfig.CacheTTL <= 0 {
		config.CacheConfig.CacheTTL = DefaultCacheTTL
	}
	if config.CacheConfig.CacheTTL > DefaultMaxTTL {
		config.CacheConfig.CacheTTL = DefaultMaxTTL
	}
	if config.CacheConfig.CacheTTL < DefaultMinTTL {
		config.CacheConfig.CacheTTL = DefaultMinTTL
	}
	if len(config.CacheConfig.RecordTypes) == 0 {
		return fmt.Errorf("no DNS record type was specified for caching")
	}
	config.CacheConfig.RecordTypes = Unique(config.CacheConfig.RecordTypes,
		func(r *RecordType) uint16 { return r.Value })
	if len(config.UpstreamServers) == 0 {
		return fmt.Errorf("no upstream DNS server was specified")
	}
	config.UpstreamServers = Unique(config.UpstreamServers,
		func(s *ServerConfig) string { return s.IP.String() })
	for _, s := range config.UpstreamServers {
		if s.Port == 0 {
			return fmt.Errorf("invalid port 0 for the upstream server %s",
				s.String())
		}
	}
	config.LocalNameServers = Unique(config.LocalNameServers,
		func(s *ServerConfig) string { return s.IP.String() })
	for _, s := range config.LocalNameServers {
		if s.Port == 0 {
			return fmt.Errorf("invalid port 0 for the local area server %s",
				s.String())
		}
	}
	if config.ListenerConfig.Port == 0 {
		return fmt.Errorf("invalid port 0 for the local server")
	}
	return nil
}
