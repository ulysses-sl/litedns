package main

import (
	"github.com/miekg/dns"
	"log"
	"sync"
	"time"
)

type trieCache struct {
	validQueryTypeMask uint64
	queryIdx           [34]int
	trie               *suffixTrie
}

type suffixTrie struct {
	nextNodes  [64]*suffixTrie
	dnsRecords [9]*dnsRecord
	isBlocked  bool
	blockedAt  *string
	sync.RWMutex
}

func NewDNSTrieCache() DNSCache {
	return NewTrieCache()
}

func NewTrieCache() DNSCache {
	validTypes := [9]uint16{
		dns.TypeA, dns.TypeNS, dns.TypeCNAME,
		dns.TypeSOA, dns.TypePTR, dns.TypeMX,
		dns.TypeTXT, dns.TypeAAAA, dns.TypeSRV,
	}
	qIdx := [34]int{}
	for i := range qIdx {
		qIdx[i] = -1
	}
	var vqt uint64 = 0
	for i, t := range validTypes {
		vqt |= 1 << t
		qIdx[t] = i
	}
	tc := trieCache{
		validQueryTypeMask: vqt,
		queryIdx:           qIdx,
		trie:               NewSuffixTrie(),
	}
	return &tc
}

func NewSuffixTrie() *suffixTrie {
	return &suffixTrie{
		nextNodes:  [64]*suffixTrie{},
		dnsRecords: [9]*dnsRecord{},
		isBlocked:  false,
		blockedAt:  nil,
	}
}

func (tc *trieCache) Insert(record *dns.Msg) bool {
	rrType := record.Question[0].Qtype
	if tc.validQueryTypeMask&(1<<rrType) == 0 {
		//log.Printf("only valid types are allowed")
		return false
	}
	if len(record.Answer) == 0 {
		return false
	}
	if record.Rcode != dns.RcodeSuccess {
		return false
	}
	return tc.trie.Insert(record, tc.queryIdx[rrType])
}

func (tc *trieCache) Lookup(query *dns.Msg) (*dns.Msg, error) {
	rrType := query.Question[0].Qtype
	if tc.validQueryTypeMask&(1<<rrType) == 0 {
		return nil, nil
	}
	return tc.trie.Lookup(query, tc.queryIdx[rrType])
}

func (tc *trieCache) ForceResp(name string) {
	tc.trie.ForceResp(name)
}

func (st *suffixTrie) getLockedPath(name string) *suffixTrie {
	cname := dns.CanonicalName(name)
	curr := st
	curr.Lock()
	for i := len(cname) - 1; i >= 0; i-- {
		key := ((cname[i] & 64) >> 1) ^ (cname[i] & 63)
		if curr.nextNodes[key] == nil {
			curr.nextNodes[key] = NewSuffixTrie()
		}
		next := curr.nextNodes[key]
		next.Lock()
		curr.Unlock()
		curr = next
	}
	return curr
}

func (st *suffixTrie) getLockedPathAbort(name string) *suffixTrie {
	cname := dns.CanonicalName(name)
	curr := st
	curr.Lock()
	for i := len(cname) - 1; i >= 0; i-- {

		if curr.isBlocked && cname[i] == '.' {
			curr.Unlock()
			return nil
		}
		key := ((cname[i] & 64) >> 1) ^ (cname[i] & 63)
		if curr.nextNodes[key] == nil {
			curr.nextNodes[key] = NewSuffixTrie()
		}
		next := curr.nextNodes[key]
		next.Lock()
		curr.Unlock()
		curr = next
	}
	if curr.isBlocked {
		curr.Unlock()
		return nil
	}
	return curr
}

func (st *suffixTrie) Insert(record *dns.Msg, idxRRType int) bool {
	question := record.Question[0]
	answer := record.Answer[0]
	ttlDeadline := GetTTLDeadline(answer.Header().Ttl)

	curr := st.getLockedPathAbort(question.Name)

	if curr == nil {
		return false
	}

	rc := dnsRecord{
		record:      record,
		ttlDeadline: ttlDeadline,
	}
	curr.dnsRecords[idxRRType] = &rc
	curr.Unlock()

	//cname := dns.CanonicalName(question.Name)
	//qtypeStr := dns.TypeToString[question.Qtype]
	//log.Printf(cname + " " + qtypeStr + " : Cached at %d\n", idxRRType)
	return true
}

func (st *suffixTrie) Lookup(query *dns.Msg, idxRRType int) (*dns.Msg, error) {
	question := query.Question[0]
	cname := dns.CanonicalName(question.Name)
	qtypeStr := dns.TypeToString[question.Qtype]

	curr := st
	curr.RLock()

	for i := len(cname) - 1; i >= 0; i-- {
		if curr.isBlocked {
			if cname[i] == '.' {
				curr.RUnlock()
				//log.Printf("BLOCKED 1: " + cname + " " + qtypeStr + " at %d(%c), ptr %p, by " + *curr.blockedAt, i, cname[i], curr)
				log.Printf("BLOCKED (subdomain): " + cname + " " + qtypeStr)
				return nil, NewHostBlockedError(cname)
			}
		}
		key := ((cname[i] & 64) >> 1) ^ (cname[i] & 63)
		if curr.nextNodes[key] == nil {
			curr.RUnlock()
			//log.Printf(cname + " " + qtypeStr + " : Cache MISS (partial match)\n")
			return nil, nil
		}
		next := curr.nextNodes[key]
		next.RLock()
		curr.RUnlock()
		curr = next
	}

	if curr.isBlocked {
		curr.RUnlock()
		log.Printf("BLOCKED (match): " + cname + " " + qtypeStr)
		return nil, NewHostBlockedError(cname)
	}

	if curr.dnsRecords[idxRRType] == nil {
		curr.RUnlock()
		//log.Printf(cname + " " + qtypeStr + " : Cache MISS at %d (full match)\n", idxRRType)
		return nil, nil
	}

	record := curr.dnsRecords[idxRRType].record
	ttlDeadline := curr.dnsRecords[idxRRType].ttlDeadline

	curr.RUnlock()

	if ttlDeadline == nil {
		panic("ttl for the cached entry should not be empty")
	}
	now := time.Now()
	if now.After(*ttlDeadline) {
		//log.Printf(cname + " " + qtypeStr + " : Stale, past TTL\n")
		return nil, nil
	}
	//log.Printf(cname + " " + qtypeStr + " : Cache HIT at %d\n", idxRRType)
	return record, nil
}

func (st *suffixTrie) ForceResp(name string) {
	curr := st.getLockedPath(name)
	curr.isBlocked = true
	curr.blockedAt = &name
	curr.Unlock()
}
