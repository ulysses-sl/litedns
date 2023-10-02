package handler

import (
	"github.com/miekg/dns"
	"litedns/client"
	"log"
)

type baseHandler struct {
	clientPool *client.DNSClientPool
}

func NewBaseHandler(cPool *client.DNSClientPool) dns.Handler {
	h := &baseHandler{
		clientPool: cPool,
	}
	return h
}

func (h *baseHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	client := <-h.clientPool.C
	resp, err := client.Exchange(req)
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	if err != nil {
		log.Printf("error while making request: %s", err.Error())
		m.SetRcode(req, dns.RcodeServerFailure)
	} else {
		m.SetRcode(req, resp.Rcode)
		m.Answer = append(m.Answer, resp.Answer...)
	}
	serveResponse(w, m)
}
