package main

import (
	"github.com/miekg/dns"
	"time"
)

type DNSCache interface {
	Insert(*dns.Msg) bool
	Lookup(*dns.Msg) (*dns.Msg, error)
	ForceResp(string)
}

type dnsRecord struct {
	record      *dns.Msg
	ttlDeadline *time.Time
}

type hostBlockedError struct {
	name string
}

func (hbe *hostBlockedError) Error() string {
	return "Host blocked: " + (*hbe).name
}

func NewHostBlockedError(name string) error {
	e := hostBlockedError{name: name}
	return &e
}
