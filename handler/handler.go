package handler

import (
	"github.com/miekg/dns"
	"log"
	"net"
)

func serveResponse(w dns.ResponseWriter, msg *dns.Msg) {
	if err := w.WriteMsg(msg); err != nil {
		log.Fatalf("error while writing resp for %s: %s",
			msg.Question[0].String(), err.Error())
	}
}

func serveFailResponse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	serveResponse(w, m)
}

func serveNXResponse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeNameError)
	serveResponse(w, m)
}

func serveWithResponse(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.Answer = append(m.Answer, resp.Answer...)
	serveResponse(w, m)
}

func serveWithAnswer(w dns.ResponseWriter, req *dns.Msg, answer dns.RR) {
	m := new(dns.Msg)
	m.Id = req.Id
	m.SetReply(req)
	m.Answer = append(m.Answer, answer)
	serveResponse(w, m)
}

func fakeRecordA(name string, ip net.IP) dns.RR {
	if ip == nil {
		net.ParseIP("0.0.0.0")
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

func fakeRecordAAAA(name string, ip net.IP) dns.RR {
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
