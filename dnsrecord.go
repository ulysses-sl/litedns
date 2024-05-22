package main

import (
	"github.com/miekg/dns"
	"time"
)

type UnixTimestamp int64

type DNSRecord struct {
	session string
	entry   *dns.Msg
	expiry  UnixTimestamp
}

func CurrentUnixTime() UnixTimestamp {
	return UnixTimestamp(time.Now().Unix())
}

func NewExpiry(ttl int64) UnixTimestamp {
	return CurrentUnixTime() + UnixTimestamp(ttl)
}

func (expiry UnixTimestamp) GetTTL() uint32 {
	now := CurrentUnixTime()
	diff := expiry - now
	if diff <= 0 {
		return 0
	}
	if diff > DefaultMaxTTL {
		return DefaultMaxTTL
	}
	return uint32(diff)
}

func (r DNSRecord) IsExpired() bool {
	return r.expiry <= CurrentUnixTime()
}

func (r DNSRecord) TTLAdjustedEntry() *dns.Msg {
	newTTL := r.expiry.GetTTL()
	if r.expiry <= 0 {
		return nil
	}
	for _, a := range r.entry.Answer {
		updateTTL(a, newTTL)
	}
	for _, ns := range r.entry.Ns {
		updateTTL(ns, newTTL)
	}
	for _, x := range r.entry.Extra {
		updateTTL(x, newTTL)
	}
	return r.entry
}

func updateTTL(record dns.RR, newTTL uint32) {
	switch rr := record.(type) {
	case *dns.OPT:
		return
	case *dns.SOA:
		rr.Header().Ttl = newTTL
		rr.Minttl = newTTL
	default:
		rr.Header().Ttl = newTTL
	}
}
