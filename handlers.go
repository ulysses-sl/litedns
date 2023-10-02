package main

import (
	"errors"
	"github.com/miekg/dns"
	"log"
	"net"
)

func ServeResponse(w dns.ResponseWriter, msg *dns.Msg) {
	if err := w.WriteMsg(msg); err != nil {
		log.Fatalf("error while writing resp for %s: %s",
			msg.Question[0].String(), err.Error())
	}
}

func ServeFailResponse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	ServeResponse(w, m)
}

func ServeNXResponse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeNameError)
	ServeResponse(w, m)
}

func ServeWithResponse(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.Answer = append(m.Answer, resp.Answer...)
	ServeResponse(w, m)
}

func ServeWithAnswer(w dns.ResponseWriter, req *dns.Msg, answer dns.RR) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.Answer = append(m.Answer, answer)
	ServeResponse(w, m)
}

func FakeRecordA(name string, ip net.IP) dns.RR {
	if ip == nil {
		ip = net.ParseIP("0.0.0.0")
	}
	if ip.To4() == nil {
		log.Panicf("invalid IPv4 address: %s", ip.String())
	}
	r := new(dns.A)
	r.A = ip
	r.Hdr = dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	return r
}

func FakeRecordAAAA(name string, ip net.IP) dns.RR {
	if ip == nil {
		ip = net.ParseIP("::")
	}
	if ip.To4() != nil || ip.To16() == nil {
		log.Panicf("invalid IPv6 address: %s", ip.String())
	}
	r := new(dns.AAAA)
	r.AAAA = ip
	r.Hdr = dns.RR_Header{
		Name:   name,
		Rrtype: dns.TypeAAAA,
		Class:  dns.ClassINET,
		Ttl:    3600,
	}
	return r
}

func ServeBlockedResponse(w dns.ResponseWriter, req *dns.Msg) {
	switch req.Question[0].Qtype {
	case dns.TypeA:
		ServeWithAnswer(w, req, FakeRecordA(req.Question[0].Name, nil))
	case dns.TypeAAAA:
		ServeWithAnswer(w, req, FakeRecordAAAA(req.Question[0].Name, nil))
	default:
		ServeFailResponse(w, req)
	}
}

type MainHandler struct {
	cache      DNSCache
	adBlocker  AdBlocker
	clientPool *DNSClientPool
}

func NewDNSHandler(cache DNSCache,
	adBlocker AdBlocker, cPool *DNSClientPool) dns.Handler {
	h := &MainHandler{
		cache:      cache,
		adBlocker:  adBlocker,
		clientPool: cPool,
	}
	return h
}

func (h *MainHandler) ServeUncached(w dns.ResponseWriter, req *dns.Msg) {
	dname := req.Question[0].Name
	if h.adBlocker.IsBlocked(dname) {
		_ = h.cache.Block(dname)
		ServeBlockedResponse(w, req)
		return
	}
	client := <-h.clientPool.C
	resp, err := client.Exchange(req)
	if err != nil {
		log.Printf("error while making request: %v", err)
		ServeFailResponse(w, req)
		return
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, resp.Rcode)
	m.Answer = append(m.Answer, resp.Answer...)

	ServeResponse(w, m)
}

func (h *MainHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	cachedResp, err := h.cache.Query(req)
	switch {
	case err == nil:
		if cachedResp != nil {
			ServeWithResponse(w, req, cachedResp)
		} else {
			h.ServeUncached(w, req)
		}
	case errors.Is(err, ExpiredCacheError):
		h.ServeUncached(w, req)
	case errors.Is(err, DomainBlockedError):
		ServeBlockedResponse(w, req)
	default:
		ServeFailResponse(w, req)
	}
}
