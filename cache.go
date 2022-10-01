package main

import (
	"github.com/miekg/dns"
	"time"
	//"sync"
	//"sync/atomic"
)

type DNSCache interface {
	Lookup(*dns.Msg) (*dns.Msg, error)
	Insert(*dns.Msg) bool
	ForceResp(string)
}

type dnsRecord struct {
	entry *dns.Msg
	expiry int64
}

func NewDNSRecord(r *dns.Msg) *dnsRecord {
	if r == nil || len(r.Answer) == 0 {
		return nil
	}
	dr := dnsRecord{
		entry: r,
		expiry: time.Now().Unix() + (int64)(r.Answer[0].Header().Ttl),
	}
	return &dr
}

func (dr *dnsRecord) HasExpired() bool {
	return time.Now().Unix() < dr.expiry
}

type hostBlockedError struct {
	name string
}

func (hbe *hostBlockedError) Error() string {
	return "Host blocked: " + (*hbe).name
}

func NewHostBlockedError(name string) error {
	e := &hostBlockedError{name: name}
	return e
}
