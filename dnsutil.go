package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"slices"
	"strings"
)

const EDNS_BUFFER_SIZE = 1232

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

func CreateServFailResp(req *dns.Msg) *dns.Msg {
	if req == nil {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	} else {
		resp.SetEdns0(EDNS_BUFFER_SIZE, true)
	}
	return resp
}

func CreateNXResp(req *dns.Msg) *dns.Msg {
	if req == nil {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError)
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	} else {
		resp.SetEdns0(EDNS_BUFFER_SIZE, true)
	}
	return resp
}

func CreateRespFromResp(req *dns.Msg, origResp *dns.Msg) *dns.Msg {
	if req == nil {
		return nil
	}
	if origResp == nil {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = origResp.Rcode
	resp.Compress = true
	resp.Answer = CloneSlice(origResp.Answer)
	resp.Ns = CloneSlice(origResp.Ns)
	resp.Extra = CloneSlice(origResp.Extra)
	if opt := origResp.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	} else if opt = req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	} else {
		resp.SetEdns0(EDNS_BUFFER_SIZE, true)
	}
	return resp
}

func CreateRespWithAnswer(req *dns.Msg, answer dns.RR) *dns.Msg {
	if req == nil {
		return nil
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = make([]dns.RR, 0, 1)
	resp.Answer = append(resp.Answer, answer)
	resp.Extra = make([]dns.RR, 0, 1)
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	} else {
		resp.SetEdns0(EDNS_BUFFER_SIZE, true)
	}
	return resp
}

func CreateUpstreamRequest(req *dns.Msg) *dns.Msg {
	uReq := new(dns.Msg)
	uReq.Id = dns.Id()
	uReq.Opcode = req.Opcode
	uReq.Question = CloneSlice(req.Question)
	uReq.Extra = make([]dns.RR, 0, 1)
	uReq.SetEdns0(EDNS_BUFFER_SIZE, true)
	uReq.AuthenticatedData = true
	uReq.RecursionDesired = true
	uReq.CheckingDisabled = true
	return uReq
}

func CreateBlockedResp(req *dns.Msg) *dns.Msg {
	switch req.Question[0].Qtype {
	case dns.TypeA:
		rrA := FakeRecordA(req.Question[0].Name, nil)
		return CreateRespWithAnswer(req, rrA)
	case dns.TypeAAAA:
		rrAAAA := FakeRecordAAAA(req.Question[0].Name, nil)
		return CreateRespWithAnswer(req, rrAAAA)
	default:
		return CreateServFailResp(req)
	}
}

const (
	PTRSuffix4 = ".in-addr.arpa."
	PTRSuffix6 = ".ip6.arpa."
)

// ReverseQueryToIP attempts to convert any PTR reverse DNS query to a
// corresponding IP address. If the string does not end with "in-addr.arpa"
func ReverseQueryToIP(s string) (net.IP, error) {
	cname := dns.CanonicalName(s)
	if revIP4Str, ok := strings.CutSuffix(cname, PTRSuffix4); ok {
		ipSegments := strings.Split(revIP4Str, ".")
		if len(ipSegments) < 4 {
			return nil, fmt.Errorf(
				"malformed IPv4 reverse search query: %s", s)
		}
		slices.Reverse(ipSegments)
		ipSegments = ipSegments[:4]
		ipStr := strings.Join(ipSegments, ".")
		ipAddr := net.ParseIP(ipStr)
		if ipAddr == nil {
			return nil, fmt.Errorf(
				"malformed IPv4 reverse search query: %s", s)
		}
		return ipAddr, nil
	}
	if revIP6Str, ok := strings.CutSuffix(cname, PTRSuffix6); ok {
		ipNibbles := strings.Split(revIP6Str, ".")
		if len(ipNibbles) < 32 {
			return nil, fmt.Errorf(
				"malformed IPv6 reverse search query: %s", s)
		}
		slices.Reverse(ipNibbles)
		ipNibbles = ipNibbles[:32]
		ipSegments := make([]string, 0, 8)
		for i := 0; i < len(ipNibbles); i += 4 {
			seg := strings.Join([]string{
				ipNibbles[i],
				ipNibbles[i+1],
				ipNibbles[i+2],
				ipNibbles[i+3],
			}, "")
			ipSegments = append(ipSegments, seg)
		}
		ipStr := strings.Join(ipSegments, ":")
		ipAddr := net.ParseIP(ipStr)
		if ipAddr == nil {
			return nil, fmt.Errorf(
				"malformed IPv6 reverse search query: %s", s)
		}
		return ipAddr, nil
	}
	return nil, nil
}

// IsSpecialIP checks if the IP is in the special reserved space.
func IsSpecialIP(ip net.IP) bool {
	if ip == nil {
		panic("Attempted to check nil net.IP")
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() ||
		ip.IsGlobalUnicast()
}

// IsLocalQuery checks if the query should be handled by the local resolver.
// If the given query is malformed or contains a hostname, bogus domain,
// or a reverse IP lookup for a special IP address, it returns true.
// Otherwise, it returns false.
func IsLocalQuery(q *dns.Msg) bool {
	if q == nil {
		panic("Invoked local host query check on nil *dns.Msg")
	}
	if numQ := len(q.Question); numQ != 1 {
		return true
	}
	if q.Question[0].Qclass != dns.ClassINET {
		return true
	}
	cname := dns.CanonicalName(q.Question[0].Name)
	labels := dns.SplitDomainName(cname)
	if len(labels) < 2 {
		return true
	}
	if labels[len(labels)-1] == "arpa" {
		subdomain := labels[len(labels)-2]
		if subdomain == "in-addr" || subdomain == "ip6" {
			goto CheckIP
		}
	}
	if _, isTLD := OfficialTLDs[labels[len(labels)-1]]; isTLD {
		return false
	}

CheckIP:
	// Check if it contains the IP address that should not be leaked
	ip, err := ReverseQueryToIP(cname)
	if err != nil {
		log.Printf("%v", err)
		return true
	}
	if ip != nil {
		return IsSpecialIP(ip)
	}
	// Safety catch net: if PTR query but the query string is not reverse IP,
	// default to local handling to avoid any query leak.
	if q.Question[0].Qtype == dns.TypePTR {
		return true
	}
	return false
}
