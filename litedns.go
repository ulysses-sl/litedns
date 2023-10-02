package main

import (
	"github.com/miekg/dns"
	"litedns/client"
	"litedns/handler"
	"log"
	"strconv"
)

var GlobalConfig *LiteDNSConfig

func Run() {
	if cfg, err := LoadConfig("litedns.conf"); err != nil {
		log.Fatalf("Unable to load config: %s\n ", err.Error())
	} else {
		GlobalConfig = cfg
	}

	cache := NewDNSCache(GlobalConfig.CachedRecordTypes)

	tCache := cache.NewTieredCache(cfg.MinTTL, cfg.MaxTTL)
	dummyHdlr := NewDummyHandler(cfg.AdBlocker.SinkIP4, cfg.AdBlocker.SinkIP6)
	uClients := NewDNSClientPool(cfg.UpstreamServers)

	selfServer := &ServerConfig{
		IP:    cfg.ListenIP,
		Port:  cfg.ListenPort,
		Proto: cfg.ListenProto,
	}
	ab := NewAdBlocker(cfg.UpstreamServers, selfServer, cfg.AdBlocker.ABPFilterURL)
	uHandler := handler.NewCachingHandler(uClients, tCache, ab, dummyHdlr)

	lClients := client.NewDNSClientPool(cfg.LocalNameServers)
	lHandler := handler.NewBaseHandler(lClients)

	dHandler := handler.NewDummyHandler(cfg.AdBlocker.SinkIP4, cfg.AdBlocker.SinkIP6)

	mux := handler.newMuxHandler(uHandler, lHandler, dHandler)

	dns.Handle(".", mux)

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(int(cfg.ListenPort)), Net: "udp"}
	log.Printf("Starting at %d\n", int(cfg.ListenPort))
	err = server.ListenAndServe()
	defer func(server *dns.Server) {
		sderr := server.Shutdown()
		if sderr != nil {
			log.Fatalf("Error while shutting down the server: %s\n ",
				err.Error())
		}
	}(server)
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
