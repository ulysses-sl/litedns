package main

import (
	"github.com/miekg/dns"
	//"log"
	//"sync"
	//"time"
)

type trieCache struct {
	validQueryTypeMask uint64
	queryIdx           [34]int
	trieRoot           *trie
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
		trieRoot:           NewTrieRoot(),
	}
	return &tc
}

func (tc *trieCache) Lookup(query *dns.Msg) (*dns.Msg, error) {
	rrType := query.Question[0].Qtype
	if tc.validQueryTypeMask&(1<<rrType) == 0 {
		return nil, nil
	}
	question := query.Question[0]
	cname := dns.CanonicalName(question.Name)
	recordIdx := tc.queryIdx[rrType]
	return tc.trieRoot.Lookup(cname, recordIdx)
}

func (tc *trieCache) Insert(record *dns.Msg) bool {
	if record == nil || len(record.Answer) == 0 {
		return false
	}
	rrType := record.Question[0].Qtype
	if tc.validQueryTypeMask & (1<<rrType) == 0 {
		return false
	}
	if record.Rcode != dns.RcodeSuccess {
		return false
	}
	question := record.Question[0]
	cname := dns.CanonicalName(question.Name)
	recordIdx := tc.queryIdx[rrType]
	return tc.trieRoot.Insert(record, cname, recordIdx)
}

func (tc *trieCache) ForceResp(cname string) {
	tc.trieRoot.ForceResp(cname)
}

//func (tc *trieCache) Purge(node *trie, record)

