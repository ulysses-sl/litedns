package handler

import (
	"github.com/miekg/dns"
	"litedns/adblocker"
	cache2 "litedns/cache"
	"litedns/client"
	"log"
)

type cachingHandler struct {
	dummyHdlr  dns.Handler
	clientPool *client.DNSClientPool
	cache      cache2.DNSCache
	adBlocker  adblocker.AdBlocker
}

func NewCachingHandler(cPool *client.DNSClientPool,
	cache cache2.DNSCache, adBlocker adblocker.AdBlocker,
	dummyHdlr dns.Handler) dns.Handler {
	h := &cachingHandler{
		dummyHdlr:  dummyHdlr,
		clientPool: cPool,
		cache:      cache,
		adBlocker:  adBlocker,
	}
	return h
}

func (cd *cachingHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	cached, status := cd.cache.Lookup(req)
	switch status {
	case cache2.EntryFound:
		serveWithResponse(w, req, cached)
	case cache2.DomainBlocked:
		cd.dummyHdlr.ServeDNS(w, req)
	case cache2.NotFound:
		fallthrough
	case cache2.Expired:
		fallthrough
	case cache2.UncachedType:
		if cd.adBlocker.BlockIfMatch(req.Question[0].Name) {
			cd.dummyHdlr.ServeDNS(w, req)
			// Cache insert
			if cerr := cd.cache.Block(req.Question[0].Name); cerr != nil {
				log.Panicf("Invalid cache insert: %s", cerr.Error())
			}
			return
		}
		client := <-cd.clientPool.C
		resp, xerr := client.Exchange(req)
		if xerr != nil {
			log.Printf("error while making request: %s", xerr.Error())
			serveFailResponse(w, req)
			return
		}
		serveWithResponse(w, req, resp)
		// Cache insert
		if resp.Rcode != dns.RcodeSuccess {
			return
		}
		if status == cache2.UncachedType {
			return
		}
		if cerr := cd.cache.Insert(resp); cerr != nil {
			log.Panicf("Invalid cache insert: %s", cerr.Error())
		}
	case cache2.LookupError:
		serveFailResponse(w, req)
	default:
		panic("Unknown cache lookup status")
	}
}
