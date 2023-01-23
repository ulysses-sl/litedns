package main

import (
	"errors"
	"github.com/miekg/dns"
	"log"
	"strings"
	//"time"
)

type Dispatcher interface {
	handleDNSRequest() func(dns.ResponseWriter, *dns.Msg)
}

func NewDispatcher(clientConfigs []*clientConfig, queryTypes []uint16) Dispatcher {
	return NewCachingDispatcher(clientConfigs, queryTypes)
}

type cachingDispatcher struct {
	cache      DNSCache
	clientPool chan DNSClient
	cacheQueue chan *dns.Msg
	adBlocker  AdBlocker
}

func NewCachingDispatcher(clientConfigs []*clientConfig, queryTypes []uint16) *cachingDispatcher {
	var clients []DNSClient

	for _, cc := range clientConfigs {
		clients = append(clients, NewDNSClient(cc))
	}

	cache := NewDNSTrieCache(queryTypes)

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
			resp := handleWithRcode(req, dns.RcodeServerFailure)
			w.WriteMsg(resp)
			log.Printf("[DENIED] %-5s  %s, ", qtypeStr, name)
			return
		}
		if isLocalIPLookup(name) {
			resp := handleWithRcode(req, dns.RcodeServerFailure)
			w.WriteMsg(resp)
			log.Printf("[DENIED] %-5s  %s", qtypeStr, name)
			return
		}
		cached, err := cd.cache.Lookup(req)
		if err != nil {
			resp := handleWithRcode(req, dns.RcodeNameError)
			w.WriteMsg(resp)
			log.Printf("[BLOCKD] %-5s  %s", qtypeStr, name)
			return
		} else if cached != nil {
			resp := handleWithUpstreamResp(req, cached)
			w.WriteMsg(resp)
			return
		} else if cd.adBlocker.BlockIfMatch(name) {
			resp := handleWithRcode(req, dns.RcodeNameError)
			w.WriteMsg(resp)
			log.Printf("[NEWBLK] %-5s  %s", qtypeStr, name)
			return
		}

		c := <-cd.clientPool

		newAnswer, err := c.Exchange(req)

		if err != nil {
			if errors.Is(err, dns.ErrId) {
				cached, err = cd.cache.Lookup(req)
				if err != nil {
					resp := handleWithRcode(req, dns.RcodeNameError)
					w.WriteMsg(resp)
					log.Printf("[BLOCKD] %-5s  %s", qtypeStr, name)
				} else if cached != nil {
					resp := handleWithUpstreamResp(req, cached)
					w.WriteMsg(resp)
				}
			} else {
				log.Printf("Connection Failure: " + err.Error() + "\n")
				w.WriteMsg(handleWithRcode(req, dns.RcodeServerFailure))
			}
			return
		}

		if newAnswer.Rcode == dns.RcodeSuccess && len(newAnswer.Answer) > 0 {
			cd.cacheQueue <- newAnswer
			//log.Printf("[CACHED] %-5s  %s", qtypeStr, name)
		}
		resp := handleWithUpstreamResp(req, newAnswer)
		w.WriteMsg(resp)
	}
}

func handleWithRcode(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.Id = req.Id
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
