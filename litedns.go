package main

import (
	"github.com/miekg/dns"
	"log"
	"net"
	"time"
)

var GlobalConfig *LiteDNSConfig
var OfficialTLDs map[string]struct{}

const CONFIG_FILENAME = "litedns.conf"
const STAT_PRINT_INTERVAL = 900

func main() {
	Run()
}

func Run() {
	if cfg, err := LoadConfig(CONFIG_FILENAME); err != nil {
		log.Fatalf("Unable to load config: %s\n", err.Error())
	} else {
		log.Printf("Loaded LiteDNS config from %s",
			CONFIG_FILENAME)
		GlobalConfig = cfg
	}

	if tlds, err := LatestTLDs(GlobalConfig.UpstreamServers); err != nil {
		log.Fatalf("Unable to load IANA TLD list: %s\n", err.Error())
	} else {
		log.Printf("Loaded IANA TLD list, total %d", len(tlds))
		OfficialTLDs = tlds
	}

	go func() {
		tldUpdateInterval := 86400 * time.Second
		tldUpdateT := time.NewTimer(tldUpdateInterval)
		for {
			<-tldUpdateT.C
			tlds, err := LatestTLDs(GlobalConfig.UpstreamServers)
			if err != nil {
				log.Printf("Unable to load IANA TLD list: %s\n",
					err.Error())
			} else {
				OfficialTLDs = tlds
			}
			tldUpdateT.Reset(tldUpdateInterval)
		}
	}()

	cache := NewDNSCache(GlobalConfig.CacheConfig)
	adb := NewAdBlockerHTTP(GlobalConfig.UpstreamServers,
		GlobalConfig.AdBlocker.ABPFilterURL)
	uPool := NewDNSClientPool(GlobalConfig.UpstreamServers)
	lPool := NewDNSClientPool(GlobalConfig.LocalNameServers)

	handler := NewDNSHandler(cache, adb, uPool, lPool)

	dns.Handle(".", handler)

	listenAddr := GlobalConfig.ListenerConfig.IP
	listenPort := GlobalConfig.ListenerConfig.Port

	udpAddr := net.TCPAddr{IP: listenAddr, Port: int(listenPort)}
	tcpAddr := net.TCPAddr{IP: listenAddr, Port: int(listenPort)}
	// start server
	udpServer := &dns.Server{Addr: udpAddr.String(), Net: UDPProto}
	log.Printf("Starting UDP server at %v\n", udpAddr.String())
	tcpServer := &dns.Server{Addr: tcpAddr.String(), Net: TCPProto}
	log.Printf("Starting TCP server at %v\n", tcpAddr.String())
	udperr := udpServer.ListenAndServe()
	tcperr := tcpServer.ListenAndServe()

	go func() {
		StatTimer := time.NewTicker(STAT_PRINT_INTERVAL * time.Second)
		for {
			<-StatTimer.C
			PrintStat()
		}
	}()

	defer func(udpSrv, tcpSrv *dns.Server) {
		sderr1 := udpSrv.Shutdown()
		sderr2 := tcpSrv.Shutdown()
		if sderr1 != nil {
			if sderr2 != nil {
				log.Printf("Error while shutting down the TCP server: %s\n ",
					sderr2.Error())
			}
			log.Fatalf("Error while shutting down the UDP server: %s\n",
				sderr1.Error())
		}
		if sderr2 != nil {
			log.Fatalf("Error while shutting down the TCP server: %s\n",
				sderr1.Error())
		}
	}(udpServer, tcpServer)
	if udperr != nil {
		if tcperr != nil {
			log.Printf("Failed to start TCP server: %s\n", tcperr.Error())
		}
		log.Fatalf("Failed to start UDP server: %s\n", udperr.Error())
	}
	if tcperr != nil {
		log.Fatalf("Failed to start TCP server: %s\n", tcperr.Error())
	}
}
