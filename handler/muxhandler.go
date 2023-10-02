package handler

import (
	"github.com/miekg/dns"
	"net"
	"strings"
	//"time"
)

const IPv4PTRSuffix = ".in-addr.arpa."
const IPv6PTRSuffix = ".ip6.arpa."

type muxHandler struct {
	defaultHandler dns.Handler
	localHandler   dns.Handler
	dummyHandler   dns.Handler
}

func newMuxHandler(
	defaultHdlr dns.Handler,
	localHdlr dns.Handler,
	dummyHdlr dns.Handler) *muxHandler {
	if defaultHdlr == nil {
		panic("Default handler cannot be nil")
	}
	h := &muxHandler{
		defaultHandler: defaultHdlr,
		localHandler:   localHdlr,
		dummyHandler:   dummyHdlr,
	}
	return h
}

func (mh *muxHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	var ip net.IP
	cname := dns.CanonicalName(req.Question[0].Name)
	isPTR := req.Question[0].Qtype == dns.TypePTR
	hasPTRv4Suffix := strings.HasSuffix(cname, IPv4PTRSuffix)
	hasPTRv6Suffix := strings.HasSuffix(cname, IPv6PTRSuffix)

	if isPTR {
		if hasPTRv4Suffix {
			ip = buildIPv4Addr(cname)
		} else if hasPTRv6Suffix {
			ip = buildIPv6Addr(cname)
		}
		if ip == nil {
			serveFailResponse(w, req)
			return
		}
		if ip.IsPrivate() {
			mh.serveLocal(w, req)
			return
		}
		if ip.IsUnspecified() || !ip.IsGlobalUnicast() {
			serveFailResponse(w, req)
			return
		}
		mh.defaultHandler.ServeDNS(w, req)
		return
	}
	if hasPTRv4Suffix || hasPTRv6Suffix {
		serveFailResponse(w, req)
		return
	}

	subdomains := strings.Split(cname[:len(cname)-1], ".")
	if len(subdomains) == 0 {
		serveFailResponse(w, req)
		return
	}
	if len(subdomains) == 1 {
		mh.serveLocal(w, req)
		return
	}

	mh.defaultHandler.ServeDNS(w, req)
}

func (mh *muxHandler) serveLocal(w dns.ResponseWriter, req *dns.Msg) {
	if mh.localHandler != nil {
		mh.localHandler.ServeDNS(w, req)
	} else {
		serveFailResponse(w, req)
	}
}

func buildIPv4Addr(cname string) net.IP {
	if !strings.HasSuffix(cname, IPv4PTRSuffix) {
		return nil
	}
	revIP := strings.Split(strings.TrimSuffix(cname, IPv4PTRSuffix), ".")
	if len(revIP) != 4 {
		return nil
	}
	ipSegments := make([]string, 0, 4)
	for i := len(revIP) - 1; i >= 0; i-- {
		ipSegments = append(ipSegments, revIP[i])
	}
	ip := net.ParseIP(strings.Join(ipSegments, "."))
	if ip.To4() == nil {
		return nil
	}
	return ip
}

func buildIPv6Addr(cname string) net.IP {
	if !strings.HasSuffix(cname, IPv6PTRSuffix) {
		return nil
	}
	revIP := strings.Split(strings.TrimSuffix(cname, IPv6PTRSuffix), ".")
	if len(revIP) != 32 {
		return nil
	}
	ipSegments := make([]string, 0, 39)
	for i := len(revIP) - 1; i > 0; i -= 4 {
		ipSegments = append(ipSegments, revIP[i])
		ipSegments = append(ipSegments, revIP[i-1])
		ipSegments = append(ipSegments, revIP[i-2])
		ipSegments = append(ipSegments, revIP[i-3])
		ipSegments = append(ipSegments, ":")
	}
	ip := net.ParseIP(strings.Join(ipSegments[:len(ipSegments)-1], ""))
	if ip.To4() != nil {
		return nil
	}
	return ip
}
