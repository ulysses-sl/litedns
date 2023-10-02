package cache

import (
	"github.com/miekg/dns"
	"time"
)

/*
type LookupResult int

const (
	LookupError LookupResult = iota
	UncachedType
	NotFound
	EntryFound
	Expired
	DomainBlocked
)
*/

type DNSCache interface {
	Lookup(*dns.Msg) (*dns.Msg, error)
	Insert(*dns.Msg) error
	IsCachedType(uint16) bool
}

type DNSRecord struct {
	entry  *dns.Msg
	expiry int64
}

func (dr *DNSRecord) HasExpired() bool {
	now := time.Now().Unix()
	return now > dr.expiry
}
