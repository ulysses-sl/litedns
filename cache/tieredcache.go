package cache

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"litedns/config"
	"strings"
	"time"
)

type tieredCache struct {
	root         *cacheTier
	allowedTypes map[uint16]struct{}
	minTTL       int64
	maxTTL       int64
}

type cacheTier struct {
	name     []string
	nextTier map[string]*cacheTier
	records  map[uint16]*DNSRecord
}

func newCacheTier() *cacheTier {
	ct := &cacheTier{
		name:     nil,
		nextTier: make(map[string]*cacheTier, 0),
		records:  make(map[uint16]*DNSRecord, 0),
	}
	return ct
}

func NewTieredCache(minTTL int64, maxTTL int64) DNSCache {
	qTypes := []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeDNAME,
		dns.TypePTR,
		dns.TypeSRV,
		dns.TypeTXT,
	}
	rootTier := &cacheTier{
		name:     nil,
		nextTier: make(map[string]*cacheTier, 0),
		records:  make(map[uint16]*DNSRecord, 0),
	}
	tc := &tieredCache{
		root:         rootTier,
		allowedTypes: make(map[uint16]struct{}, len(qTypes)),
		minTTL:       minTTL,
		maxTTL:       maxTTL,
	}
	for _, t := range qTypes {
		tc.allowedTypes[t] = struct{}{}
	}
	return tc
}

func (tc *tieredCache) IsCachedType(qType uint16) bool {
	_, isCached := tc.allowedTypes[qType]
	return isCached
}

func (tc *tieredCache) Lookup(msg *dns.Msg) (*dns.Msg, error) {
	if msg == nil {
		panic("nullptr msg passed to tieredCache.Lookup()")
	}
	if tc.root == nil {
		panic("nullptr cache in tieredCache")
	}
	if !tc.IsCachedType(msg.Question[0].Qtype) {
		return nil, nil
	}
	subdomains := config.Subdomains(msg.Question[0].Name)
	if len(subdomains) <= 1 {
		return nil, fmt.Errorf("not a valid domain: %s", msg.Question[0].Name)
	}
	curr := tc.root
	for i := len(subdomains) - 1; i >= 0; i-- {
		next, found := curr.nextTier[subdomains[i]]
		if !found {
			return nil, nil
		}
		curr = next
	}
	r, isCached := curr.records[msg.Question[0].Qtype]
	if !isCached {
		return nil, nil
	}
	now := time.Now().Unix()
	if now < r.expiry {
		return nil, nil
	}
	return r.entry, nil
}

func (tc *tieredCache) Insert(msg *dns.Msg) error {
	if msg == nil {
		panic("nullptr msg passed to tieredCache.Insert()")
	}
	if tc.root == nil {
		panic("nullptr cache in tieredCache")
	}
	if !tc.IsCachedType(msg.Question[0].Qtype) {
		return errors.New("caching not enabled for this type of record")
	}
	subdomains := config.Reverse(config.Subdomains(msg.Question[0].Name))
	curr := tc.root
	var i, j int
	for i < len(subdomains) {
		if j >= len(curr.name) {
			next, ok := curr.nextTier[subdomains[i]]
			if !ok {
				break
			}
			curr = next
			j = 0
		} else if curr.name[j] == subdomains[i] {
			i++
			j++
		} else {
			break
		}
	}
	if j < len(curr.name) {
		// Branch off
		key := curr.name[j]
		newBranchName := curr.name[j:]
		newBranch := &cacheTier{
			name:     newBranchName,
			nextTier: curr.nextTier,
			records:  curr.records,
		}
		curr.name = curr.name[:j]
		curr.nextTier = make(map[string]*cacheTier, 1)
		curr.nextTier[key] = newBranch
		curr.records = make(map[uint16]*DNSRecord, 0)
	}
	if i < len(subdomains) {
		// Create child
		newBranchName := make([]string, 0, len(subdomains)-i)
		for k := i; k < len(subdomains); k++ {
			newBranchName = append(newBranchName, strings.Clone(subdomains[k]))
		}
		newBranch := &cacheTier{
			name:     newBranchName,
			nextTier: make(map[string]*cacheTier, 0),
			records:  make(map[uint16]*DNSRecord, 1),
		}
		curr.nextTier[newBranchName[0]] = newBranch
		curr = newBranch
	}
	/* Critical Section starts */
	r, cached := curr.records[msg.Question[0].Qtype]
	if !cached {
		r = &DNSRecord{}
		curr.records[msg.Question[0].Qtype] = r
	}
	r.entry = msg
	ttl := int64(msg.Answer[0].Header().Ttl)
	if ttl < tc.minTTL {
		ttl = tc.minTTL
	} else if ttl > tc.maxTTL {
		ttl = tc.maxTTL
	}
	r.expiry = time.Now().Unix() + ttl
	/* Critical Section ends */
	return nil
}

func purgeCacheTiers(c *cacheTier) int {
	if c == nil {
		panic("purging a nil cache")
	}
	c.records = nil
	nc := make(map[string]*cacheTier, 0)
	for k, v := range c.nextTier {
		if purgeCacheTiers(v) > 0 {
			nc[k] = v
		}
		delete(c.nextTier, k)
	}
	c.nextTier = nc
	return len(c.nextTier)
}
