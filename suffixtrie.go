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
	char = char - 45
	key := (char % 31) | ((char & 64) >> 1)
	//key := (((char ^ (char >> 1)) & 32) >> 1) | (char & 31)
	return key
}

type trie struct {
	parent     *trie
	dnsRecords []atomic.Pointer[dnsRecord]
	edges      [64]atomic.Pointer[trie]
	//recCount   atomic.Int32
	//edgeCount  atomic.Int32
	depth      int
	char       byte
	isBlocked  bool
	modifyPriv chan struct{}
}

func NewTrieRoot(recordTypes int) *trie {
	return NewTrieNode(nil, recordTypes, 0)
}

func NewTrieNode(parent *trie, recordTypes int, char byte) *trie {
	pDepth := 0
	if parent != nil {
		pDepth = parent.depth
	}
	c := &(trie{
		parent:     parent,
		dnsRecords: make([]atomic.Pointer[dnsRecord], recordTypes),
		edges:      [64]atomic.Pointer[trie]{},
		//recCount:   atomic.Int32{},
		//edgeCount:  atomic.Int32{},
		depth:      pDepth + 1,
		char:       char,
		isBlocked:  false,
		modifyPriv: make(chan struct{}, 1),
	})

	//recCount.Store(0)
	//edgeCount.Store(0)

	/*
		for i := 0; i < len(c.dnsRecords); i++ {
			c.dnsRecords[i] = atomic.Pointer[dnsRecord]{}
		}

		for j := 0; j < len(c.edges); j++ {
			c.edges[j] = atomic.Pointer[trie]{}
		}
	*/

	c.modifyPriv <- struct{}{}
	return c
}

func (t *trie) Lock() {
	<-t.modifyPriv
}

func (t *trie) Unlock() {
	t.modifyPriv <- struct{}{}
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
	var record *dnsRecord = curr.dnsRecords[recordIdx].Load()
	if record == nil {
		return nil, nil
	}
	if record.HasExpired() {
		return nil, nil
	}
	return record.entry, nil
}

func (t *trie) Insert(record *dns.Msg, cname string, recIdx int) bool {
	curr := t
	for i := len(cname) - 1; i >= 0; i-- {
		if cname[i] == '.' && curr.isBlocked {
			return false
		}
		curr = curr.AddChild(cname[i])
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
		curr = curr.AddChild(cname[i])
	}
	curr.isBlocked = true
}

func (t *trie) AddChild(char byte) *trie {
	key := TrieKey(char)
	t.Lock()
	child := t.edges[key].Load()
	if child == nil {
		child = NewTrieNode(t, len(t.dnsRecords), char)
		t.edges[key].Store(child)
	}
	t.Unlock()
	return child
}
