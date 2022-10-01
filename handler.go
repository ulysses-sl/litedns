package main

import (
	"log"
	"strings"
	"github.com/miekg/dns"
	"time"
)

type Dispatcher interface {
	handleDNSRequest() func(dns.ResponseWriter, *dns.Msg)
}

func NewDispatcher(cc1 *clientConfig, cc2 *clientConfig) Dispatcher {
	return NewCachingDispatcher(cc1, cc2)
}

type cachingDispatcher struct {
	cache      DNSCache
	clientPool chan DNSClient
	cacheQueue chan *dns.Msg
	adBlocker  AdBlocker
}

func NewCachingDispatcher(cc1 *clientConfig, cc2 *clientConfig) *cachingDispatcher {
	clients := [2]DNSClient{
		NewDNSClient(cc1),
		NewDNSClient(cc2),
	}

	cache := NewDNSTrieCache()

	cpool := make(chan DNSClient)

	cacheq := make(chan *dns.Msg, 10)

	ab := NewAdBlocker(cache)

	cd := cachingDispatcher{
		cache:      cache,
		clientPool: cpool,
		cacheQueue: cacheq,
		adBlocker:  ab,
	}

	cd.processCacheQueue()
	cd.supplyClients(clients[:])

	return &cd
}

func (cd *cachingDispatcher) processCacheQueue() {
	go func() {
		for {
			msg := <- cd.cacheQueue
			cd.cache.Insert(msg)
		}
	}()
}

func (cd *cachingDispatcher) supplyClients(clients []DNSClient) {
	go func() {
		i := 0
		for {
			if i >= len(clients) {
				i = 0
			}
			cd.clientPool <- clients[i]
			i += 1
		}
	}()
}

func (cd *cachingDispatcher) handleDNSRequest() func(dns.ResponseWriter, *dns.Msg) {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		startTime := time.Now().UnixMilli()
		name := dns.CanonicalName(req.Question[0].Name)
		qtypeStr := dns.TypeToString[req.Question[0].Qtype]
		if strings.Count(name, ".") == 1 {
			log.Printf(name + " " + qtypeStr + " : Local hostname lookup is forbidden\n")
			w.WriteMsg(handleWithRcode(req, dns.RcodeServerFailure))
			log.Printf("%s: responded in %d ms", name, (time.Now().UnixMilli() - startTime))
			return
		}
		if isLocalIPLookup(name) {
			log.Printf(name + " " + qtypeStr + " : Local IP lookup is forbidden\n")
			w.WriteMsg(handleWithRcode(req, dns.RcodeServerFailure))
			log.Printf("%s: responded in %d ms", name, (time.Now().UnixMilli() - startTime))
			return
		}
		cached, err := cd.cache.Lookup(req)
		if err != nil {
			log.Printf("[BLOCKED] %s", err.Error())
			w.WriteMsg(handleWithRcode(req, dns.RcodeNameError))
			log.Printf("%s: responded in %d ms", name, (time.Now().UnixMilli() - startTime))
			return
		} else if cached != nil {
			w.WriteMsg(handleWithUpstreamResp(req, cached))
			log.Printf("%s: responded in %d ms", name, (time.Now().UnixMilli() - startTime))
			return
		} else if cd.adBlocker.BlockIfMatch(name) {
			w.WriteMsg(handleWithRcode(req, dns.RcodeNameError))
			log.Printf("%s: responded in %d ms", name, (time.Now().UnixMilli() - startTime))
			return
		}
		req.RecursionDesired = true

		c := <-cd.clientPool

		resp, err := c.Exchange(req)

		if err != nil {
			log.Printf("Connection Failure: " + err.Error() + "\n")
			w.WriteMsg(handleWithRcode(req, dns.RcodeServerFailure))
			log.Printf("%s: responded in %d ms", name, (time.Now().UnixMilli() - startTime))
			return
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			cd.cacheQueue <- resp
		}
		w.WriteMsg(handleWithUpstreamResp(req, resp))
		log.Printf("%s: responded in %d ms", name, (time.Now().UnixMilli() - startTime))
	}
}

func handleWithRcode(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, rcode)
	return m
}

func handleWithUpstreamResp(req *dns.Msg, resp *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, resp.Rcode)
	m.Answer = append(m.Answer, resp.Answer...)
	return m
}
