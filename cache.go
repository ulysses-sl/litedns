package main

import (
	"github.com/miekg/dns"
	"time"
	//"log"
	//"sync"
	//"sync/atomic"
)

type DNSCache interface {
	Lookup(*dns.Msg) (*dns.Msg, error)
	Insert(*dns.Msg) bool
	ForceResp(string)
}

type dnsRecord struct {
	entry  *dns.Msg
	expiry int64
}

func NewDNSRecord(r *dns.Msg) *dnsRecord {
	if r == nil || len(r.Answer) == 0 {
		return nil
	}
	//ttlSeconds := (int64)(r.Answer[0].Header().Ttl)
	var ttlSeconds int64 = 3600
	dr := dnsRecord{
		entry:  r,
		expiry: time.Now().Unix() + ttlSeconds,
	}
	return &dr
}

func (dr *dnsRecord) HasExpired() bool {
	nowTime := time.Now().Unix()
	timeDiff := dr.expiry - nowTime
	//log.Printf("Current Timestamp %d, Expiry %d, diff %d", nowTime, dr.expiry, timeDiff)
	return timeDiff < 0
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
