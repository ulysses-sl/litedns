package main

import (
	"errors"
	"github.com/miekg/dns"
	"log"
)

func ServeResponse(w dns.ResponseWriter, msg *dns.Msg) {
	err := w.WriteMsg(msg)
	if err != nil {
		log.Panicf("error while writing resp for %s: %s",
			msg.Question[0].String(), err.Error())
	}
}

type MainHandler struct {
	cache              DNSCache
	adBlocker          AdBlocker
	inflightMgr        *InflightManager
	upstreamClients    *DNSClientPool
	localResolvClients *DNSClientPool
}

func NewDNSHandler(cache DNSCache, adBlocker AdBlocker,
	upstreamClients, localResolvClients *DNSClientPool) dns.Handler {
	h := &MainHandler{
		cache:              cache,
		adBlocker:          adBlocker,
		inflightMgr:        NewInflightManager(),
		upstreamClients:    upstreamClients,
		localResolvClients: localResolvClients,
	}
	return h
}

func (h *MainHandler) QueryWithClient(req *dns.Msg) *dns.Msg {
	client := <-h.upstreamClients.C
	resp, err := client.Exchange(req)
	if err != nil {
		return nil
	}
	return resp
}

func (h *MainHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	logRequest, logEntry := StartLogEntry()
	var resp *dns.Msg
	defer func() {
		if err := w.Close(); err != nil {
			log.Printf("Error while closing the connection: %s",
				err.Error())
		}
	}()
	if h == nil {
		log.Panicf("Attempted to use uninitialized DNS request handler")
	}
	if req == nil {
		log.Panicf("Attempted to handle nil DNS request")
	}
	if req.Response {
		resp = CreateServFailResp(req)
		ServeResponse(w, resp)
		log.Printf("Warning: Received a response instead of a query")
		PopulateLogEntry(logEntry, resp)
		logRequest(logEntry)
		return
	}
	if len(req.Question) != 1 {
		resp = CreateServFailResp(req)
		ServeResponse(w, resp)
		log.Printf("Warning: Invalid number of questions in a query (%d)",
			len(req.Question))
		PopulateLogEntry(logEntry, resp)
		logRequest(logEntry)
		return
	}
	if req.Question[0].Qclass != dns.ClassINET {
		ServeResponse(w, resp)
		log.Printf("Warning: Received a non-ClassINET query")
		PopulateLogEntry(logEntry, resp)
		logRequest(logEntry)
		return
	}
	var client DNSClient
	if logEntry.isLocalReq = IsLocalQuery(req); logEntry.isLocalReq {
		client = <-h.localResolvClients.C
	} else {
		client = <-h.upstreamClients.C
	}
	cname := dns.CanonicalName(req.Question[0].Name)
	if h.adBlocker.IsBlocked(cname) {
		resp = CreateBlockedResp(req)
		ServeResponse(w, resp)
		logEntry.cacheStatus = BlockedDomain
		PopulateLogEntry(logEntry, resp)
		logRequest(logEntry)
		return
	}

	sessionKey := InflightSessionKey(w, req)
	session, isFirst := h.inflightMgr.ReserveSession(sessionKey)
	defer h.inflightMgr.ReleaseSession(sessionKey)

	var shouldCacheResult bool
	cachedResp, err := h.cache.Query(req, sessionKey)
	switch {
	case err == nil:
		if cachedResp != nil {
			resp = CreateRespFromResp(req, cachedResp)
			ServeResponse(w, resp)
			logEntry.cacheStatus = CacheHit
			PopulateLogEntry(logEntry, resp)
			logRequest(logEntry)
			return
		}
		logEntry.cacheStatus = CacheMiss
		shouldCacheResult = true
	case errors.Is(err, ExpiredCacheError):
		logEntry.cacheStatus = CacheExpired
		shouldCacheResult = true
	case errors.Is(err, UnsupportedCachingError):
		logEntry.cacheStatus = BypassCache
		shouldCacheResult = false
	default:
		resp = CreateServFailResp(req)
		ServeResponse(w, resp)
		logEntry.cacheStatus = CacheError
		PopulateLogEntry(logEntry, resp)
		logRequest(logEntry)
		return
	}

	if !isFirst {
		<-session.Wait
		resp = CreateRespFromResp(req, session.Cached)
		ServeResponse(w, resp)
		PopulateLogEntry(logEntry, resp)
		logRequest(logEntry)
		return
	}
	session.Cached = h.MakeQueryRequest(client, req)
	if session.Cached == nil {
		session.Cached = CreateServFailResp(req)
	}
	if h.ContainsBlockedTarget(session.Cached) {
		if berr := h.adBlocker.Block(cname); berr != nil {
			log.Printf("Failed to block req %v: %v", req.String(), berr)
		}
		session.Cached = CreateBlockedResp(req)
	}
	if shouldCacheResult {
		if cerr := h.cache.Update(session.Cached, sessionKey); cerr != nil {
			log.Printf("Unable to cache upstream resp: %s", err.Error())
		}
	}
	resp = CreateRespFromResp(req, session.Cached)
	ServeResponse(w, resp)
	PopulateLogEntry(logEntry, resp)
	logRequest(logEntry)
}

func (h *MainHandler) MakeQueryRequest(client DNSClient, req *dns.Msg) *dns.Msg {
	uReq := CreateUpstreamRequest(req)

	resp, err := client.Exchange(uReq)
	if err != nil {
		return nil
	}
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		return resp
	}
	return resp
}

func (h *MainHandler) ContainsBlockedTarget(resp *dns.Msg) bool {
	if resp == nil {
		return false
	}
	switch resp.Question[0].Qtype {
	case dns.TypeCNAME:
		for _, rr := range resp.Answer {
			if h.adBlocker.IsBlocked(rr.(*dns.CNAME).Target) {
				return true
			}
		}
	case dns.TypeDNAME:
		for _, rr := range resp.Answer {
			if h.adBlocker.IsBlocked(rr.(*dns.DNAME).Target) {
				return true
			}
		}
	case dns.TypeSRV:
		for _, rr := range resp.Answer {
			if h.adBlocker.IsBlocked(rr.(*dns.SRV).Target) {
				return true
			}
		}
	case dns.TypePTR:
		for _, rr := range resp.Answer {
			if h.adBlocker.IsBlocked(rr.(*dns.PTR).Ptr) {
				return true
			}
		}
	}
	return false
}
