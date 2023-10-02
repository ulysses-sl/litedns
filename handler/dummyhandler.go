package handler

import (
	"github.com/miekg/dns"
	"log"
	"net"
)

type dummyHandler struct {
	dummyAddr4 net.IP
	dummyAddr6 net.IP
}

func NewDummyHandler(dummyAddr4 net.IP, dummyAddr6 net.IP) dns.Handler {
	if dummyAddr4 == nil {
		dummyAddr4 = net.ParseIP("0.0.0.0")
	}
	if dummyAddr4.To4() == nil {
		log.Panicf("invalid IPv4 address: %s", dummyAddr4.String())
	}
	if dummyAddr6 == nil {
		dummyAddr6 = net.ParseIP("::")
	}
	h := &dummyHandler{
		dummyAddr4: dummyAddr4,
		dummyAddr6: dummyAddr6,
	}
	return h
}

func (dh *dummyHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	switch req.Question[0].Qtype {
	case dns.TypeA:
		answer := fakeRecordA(req.Question[0].Name, dh.dummyAddr4)
		serveWithAnswer(w, req, answer)
	case dns.TypeAAAA:
		answer := fakeRecordAAAA(req.Question[0].Name, dh.dummyAddr6)
		serveWithAnswer(w, req, answer)
	case dns.TypePTR:
		serveFailResponse(w, req)
	default:
		serveNXResponse(w, req)
	}
}
