package main

import (
	"github.com/miekg/dns"
	"log"
	"strings"
	//"time"
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

	cacheq := make(chan *dns.Msg, 200)

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
			msg := <-cd.cacheQueue
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
		//startT := time.Now().UnixMilli()
		name := dns.CanonicalName(req.Question[0].Name)
		qtypeStr := dns.TypeToString[req.Question[0].Qtype]
		if strings.Count(name, ".") == 1 {
			//log.Printf("%s %s : Local hostname lookup is forbidden\n", name, qtypeStr)
			w.WriteMsg(handleWithRcode(req, dns.RcodeServerFailure))
			//endT :=time.Now().UnixMilli()
			//log.Printf("[DENIED] %4d ms, %-5s %s", endT - startT, qtypeStr, name)
			log.Printf("[DENIED] %-5s  %s", qtypeStr, name)
			return
		}
		if isLocalIPLookup(name) {
			//log.Printf("%s %s : Local IP lookup is forbidden\n", name, qtypeStr)
			w.WriteMsg(handleWithRcode(req, dns.RcodeServerFailure))
			//endT :=time.Now().UnixMilli()
			//log.Printf("[DENIED] %4d ms, %-5s %s", endT - startT, qtypeStr, name)
			log.Printf("[DENIED] %-5s  %s", qtypeStr, name)
			return
		}
		cached, err := cd.cache.Lookup(req)
		if err != nil {
			w.WriteMsg(handleWithRcode(req, dns.RcodeNameError))
			//endT :=time.Now().UnixMilli()
			//log.Printf("[ADBLCK] %4d ms, %-5s %s", endT - startT, qtypeStr, name)
			log.Printf("[BLOCKD] %-5s  %s", qtypeStr, name)
			return
		} else if cached != nil {
			w.WriteMsg(handleWithUpstreamResp(req, cached))
			//endT :=time.Now().UnixMilli()
			//log.Printf("[LOOKUP] %4d ms, %-5s %s", endT - startT, qtypeStr, name)
			return
		} else if cd.adBlocker.BlockIfMatch(name) {
			w.WriteMsg(handleWithRcode(req, dns.RcodeNameError))
			//endT :=time.Now().UnixMilli()
			//log.Printf("[NEWBLK] %4d ms, %-5s %s", endT - startT, qtypeStr, name)
			log.Printf("[NEWBLK] %-5s  %s", qtypeStr, name)
			return
		}
		//req.RecursionDesired = true

		c := <-cd.clientPool

		resp, err := c.Exchange(req)

		if err != nil {
			log.Printf("Connection Failure: " + err.Error() + "\n")
			w.WriteMsg(handleWithRcode(req, dns.RcodeServerFailure))
			//endT :=time.Now().UnixMilli()
			//log.Printf("[CONERR] %4d ms, %-5s %s", endT - startT, qtypeStr, name)
			return
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			cd.cacheQueue <- resp
		}
		w.WriteMsg(handleWithUpstreamResp(req, resp))
		//endT :=time.Now().UnixMilli()
		//log.Printf("[MISSED] %4d ms, %-5s %s", endT - startT, qtypeStr, name)
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
