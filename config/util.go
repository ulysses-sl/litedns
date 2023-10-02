package config

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
)

func GetTTLDeadline(ttl uint32) *time.Time {
	now := time.Now()
	ttlDuration := time.Second * time.Duration(ttl)
	deadline := now.Add(ttlDuration)
	return &deadline
}

func isLocalIPLookup(name string) bool {
	if strings.HasSuffix(name, ".in-addr.arpa.") {
		lbls := strings.Split(name, ".")
		numLbls := len(lbls)
		if lbls[numLbls-4] == "127" {
			return true
		}
		if lbls[numLbls-4] == "10" {
			return true
		}
		if lbls[numLbls-4] == "192" && numLbls > 4 && lbls[numLbls-5] == "168" {
			return true
		}
	}
	return false
}

func Reversed(s string) string {
	var res []byte
	for i := len(s) - 1; i >= 0; i-- {
		res = append(res, s[i])
	}
	return string(res)
}

func Reverse(s []string) []string {
	if s == nil {
		return nil
	}
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func JoinIPPort(ipAddr net.IP, port uint16) string {
	if ipv4 := ipAddr.To4(); ipv4 != nil {
		return fmt.Sprintf("%s:%d", ipv4.String(), port)
	} else {
		return fmt.Sprintf("[%s]:%d", net.IP(ipAddr).String(), port)
	}
}

func Subdomains(dname string) []string {
	cname := dns.CanonicalName(dname)
	subdomains := strings.Split(cname[:len(cname)-1], ".")
	return subdomains
}
