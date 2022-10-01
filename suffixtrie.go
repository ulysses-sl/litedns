package main

import (
	//"errors"
	"fmt"
	"github.com/miekg/dns"
	//"log"
	//"sync"
	"sync/atomic"
	//"time"
)

func TrieKey(char byte) byte {
	return ((char & 64) >> 1) ^ (char & 63)
}

type trie struct {
	parent     *trie
	dnsRecords [9]atomic.Pointer[dnsRecord]
	edges      [64]atomic.Pointer[trie]
	//recCount   atomic.Int32
	//edgeCount  atomic.Int32
	depth      int
	char       byte
	isBlocked  bool
	modifyPriv chan struct{}
}

func NewTrieRoot() *trie {
	return NewTrieNode(nil, 0)
}

func NewTrieNode(parent *trie, char byte) *trie {
	pDepth := 0
	if parent != nil {
		pDepth = parent.depth
	}
	c := &(trie{
		parent:     parent,
		dnsRecords: [9]atomic.Pointer[dnsRecord]{},
		edges:      [64]atomic.Pointer[trie]{},
		//recCount:   atomic.Int32{},
		//edgeCount:  atomic.Int32{},
		depth:      (pDepth + 1),
		char:       char,
		isBlocked:  false,
		modifyPriv: make(chan struct{}, 1),
	})

	//recCount.Store(0)
	//edgeCount.Store(0)

	for i := 0; i < len(c.dnsRecords); i++ {
		c.dnsRecords[i] = atomic.Pointer[dnsRecord]{}
	}

	for j := 0; j < len(c.edges); j++ {
		c.edges[j] = atomic.Pointer[trie]{}
	}
	c.modifyPriv <- struct{}{}
	return c
}

func (t *trie) Lookup(cname string, recordIdx int) (*dns.Msg, error) {
	curr := t
	for i := len(cname) - 1; i >= 0; i-- {
		if cname[i] == '.' && curr.isBlocked {
			return nil, fmt.Errorf("(partial) %s", cname)
		}
		key := TrieKey(cname[i])
		curr = curr.edges[key].Load()
		if curr == nil {
			return nil, nil
		}
	}
	if curr.isBlocked {
		return nil, fmt.Errorf("(match) %s", cname)
	}
	r := curr.dnsRecords[recordIdx].Load()
	if r == nil || r.HasExpired() {
		return nil, nil
	}
	return r.entry, nil
}

func (t *trie) Insert(record *dns.Msg, cname string, recIdx int) bool {
	curr := t
	for i := len(cname) - 1; i >= 0; i-- {
		if cname[i] == '.' && curr.isBlocked {
			return false
		}
		key := TrieKey(cname[i])
		<-curr.modifyPriv
		child := curr.edges[key].Load()
		if child == nil {
			child = NewTrieNode(curr, cname[i])
			curr.edges[key].Store(child)
		}
		curr.modifyPriv <- struct{}{}
		curr = child
	}
	if curr.isBlocked {
		return false
	}
	curr.dnsRecords[recIdx].Store(NewDNSRecord(record))
	return true
}

func (t *trie) ForceResp(cname string) {
	curr := t
	for i := len(cname) - 1; i >= 0; i-- {
		key := TrieKey(cname[i])
		<-curr.modifyPriv
		child := curr.edges[key].Load()
		if child == nil {
			child = NewTrieNode(curr, cname[i])
			curr.edges[key].Store(child)
		}
		curr.modifyPriv <- struct{}{}
		curr = child
	}
	curr.isBlocked = true
}
/*
func (t *trie) Purge() {
	curr := t
	<-curr.modifyPriv
	if 
	curr.modifyPriv <- struct{}{}
}*/

