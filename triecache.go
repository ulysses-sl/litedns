package main

import (
	"github.com/miekg/dns"
	//"log"
	//"sync"
	//"time"
)

type trieCache struct {
	queryIdx []int
	trieRoot *trie
}

func NewDNSTrieCache(queryTypes []uint16) DNSCache {
	return NewTrieCache(queryTypes)
}

func NewTrieCache(queryTypes []uint16) DNSCache {
	var queryIdx []int

	maxQueryType := 0
	for _, qt := range queryTypes {
		if maxQueryType < int(qt) {
			maxQueryType = int(qt)
		}
	}
	for i := 0; i <= maxQueryType; i++ {
		queryIdx = append(queryIdx, -1)
	}
	for i, rrType := range queryTypes {
		queryIdx[rrType] = i
	}
	tc := trieCache{
		queryIdx: queryIdx,
		trieRoot: NewTrieRoot(len(queryTypes)),
	}
	return &tc
}

func (tc *trieCache) IsValidQueryType(query *dns.Msg) bool {
	rrType := query.Question[0].Qtype
	return int(rrType) < len(tc.queryIdx) && tc.queryIdx[rrType] >= 0
}

func (tc *trieCache) Lookup(query *dns.Msg) (*dns.Msg, error) {
	if !(tc.IsValidQueryType(query)) {
		return nil, nil
	}
	rrType := query.Question[0].Qtype
	question := query.Question[0]
	cname := dns.CanonicalName(question.Name)
	recordIdx := tc.queryIdx[rrType]

	retval, err := tc.trieRoot.Lookup(cname, recordIdx)
	return retval, err
}

func (tc *trieCache) Insert(record *dns.Msg) bool {
	if record == nil || len(record.Answer) == 0 {
		return false
	}
	if !(tc.IsValidQueryType(record)) {
		return false
	}
	if record.Rcode != dns.RcodeSuccess {
		return false
	}
	rrType := record.Question[0].Qtype
	question := record.Question[0]
	cname := dns.CanonicalName(question.Name)
	recordIdx := tc.queryIdx[rrType]

	retval := tc.trieRoot.Insert(record, cname, recordIdx)
	return retval
}

func (tc *trieCache) ForceResp(cname string) {
	tc.trieRoot.ForceResp(cname)
}
