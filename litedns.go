package main

import (
	"flag"
	"github.com/miekg/dns"
	"log"
	"strconv"
)

func main() {
	port := flag.Int("p", 53, "local DNS server port")
	flag.Parse()

	cc1 := &clientConfig{
		ns:    "1.1.1.1",
		port:  853,
		proto: "tcp-tls",
	}

	cc2 := &clientConfig{
		ns:    "1.0.0.1",
		port:  853,
		proto: "tcp-tls",
	}

	clientConfigs := []*clientConfig{
		cc1,
		cc2,
	}

	queryTypes := []uint16{
		dns.TypeA,
		//dns.TypeNS,
		//dns.TypeCNAME,
		//dns.TypeSOA,
		dns.TypePTR,
		//dns.TypeMX,
		//dns.TypeTXT,
		dns.TypeAAAA,
		//dns.TypeSRV,
	}

	d := NewDispatcher(clientConfigs, queryTypes)
	dns.HandleFunc(".", d.handleDNSRequest())

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "udp"}
	log.Printf("Starting at %d\n", *port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
