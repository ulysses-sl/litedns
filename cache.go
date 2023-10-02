package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
	"sync"
	"time"
)

type DNSRecord struct {
	entry  *dns.Msg
	expiry int64
}

func (r DNSRecord) IsExpired() bool {
	return r.expiry < time.Now().Unix()
}

func GetNewExpiry() int64 {
	return time.Now().Unix() + GlobalConfig.CacheTTL
}

type SequentialCache struct {
	records []DNSRecord
	sync.RWMutex
}

func (sc *SequentialCache) Fetch(recType uint16) (*dns.Msg, error) {
	if sc == nil {
		return nil, fmt.Errorf("%w: SequentialCache.Fetch()", NilInvokeError)
	}
	sc.RLock()
	defer sc.RUnlock()
	for i := 0; i < len(sc.records); i++ {
		if sc.records[i].entry == nil {
			return nil, nil
		}
		if sc.records[i].entry.Question[0].Qtype == recType {
			if sc.records[i].IsExpired() {
				return nil, fmt.Errorf(
					"%w: %s",
					ExpiredCacheError, sc.records[i].entry.Question[0].String())
			}
			return sc.records[i].entry, nil
		}
	}
	return nil, nil
}

func (sc *SequentialCache) Store(entry *dns.Msg) error {
	if sc == nil {
		return fmt.Errorf("%w: SequentialCache.Store()", NilInvokeError)
	}
	if entry == nil {
		return fmt.Errorf("%w: SequentialCache.Store()", NilArgumentError)
	}
	if len(entry.Question) != 1 {
		return fmt.Errorf(
			"%w: %d", InvalidQuestionError, len(entry.Question))
	}
	if !entry.Response {
		return fmt.Errorf(
			"%w: %s", NonResponseCachingError, entry.Question[0].String())
	}
	if entry.Rcode != dns.RcodeSuccess {
		return fmt.Errorf(
			"%w: %s", NonSuccessCachingError, entry.Question[0].String())
	}
	if len(entry.Answer) == 0 {
		return fmt.Errorf(
			"%w (%d): %s",
			InvalidAnswerError, len(entry.Answer), entry.Question[0].String())
	}
	sc.Lock()
	defer sc.Unlock()
	expiry := GetNewExpiry()
	if sc.records == nil {
		sc.records = make([]DNSRecord, 1)
		sc.records[0].entry = entry
		sc.records[0].expiry = expiry
		return nil
	}
	recType := entry.Question[0].Qtype
	for i := 0; i < len(sc.records); i++ {
		if sc.records[i].entry == nil {
			sc.records[i].entry = entry
			sc.records[i].expiry = expiry
			return nil
		}
		if sc.records[i].entry.Question[0].Qtype == recType {
			sc.records[i].entry = entry
			sc.records[i].expiry = expiry
			return nil
		}
	}
	sc.records = append(sc.records, DNSRecord{entry: entry, expiry: expiry})
	return nil
}

var BlockedEntry *SequentialCache = nil

// DNSCache is the interface that wraps the DNS cache operations.
type DNSCache interface {
	Query(*dns.Msg) (*dns.Msg, error)
	Update(*dns.Msg) error
	IsBlocked(string) (bool, error)
	Block(string) error
	Unblock(string) error
	Flush(string) error
	FlushAll() error
}

type DNSMapCache struct {
	cacheMap      map[string]*SequentialCache
	purgeQueue    []string
	purgeInterval time.Duration
	forcePurge    chan struct{}
	cacheMaxSize  int
	sync.RWMutex
}

func NewDNSCache(maxSize int, purgeInterval time.Duration) DNSCache {
	/*
		var dummyAddrA net.IP
		var dummyAddrAAAA net.IP
		if len(cachedRecordTypes) == 0 {
			log.Panicf("No DNS record type was specified for caching")
		}

		if dummyAddrA == nil {
			dummyAddrA = net.ParseIP("0.0.0.0")
		} else if dummyAddrA.To4() == nil {
			log.Panicf("Unable to initialize the DNS cache;"+
				"not a valid IPv4 address: %s", dummyAddrA)
		}
		if dummyAddrAAAA == nil {
			dummyAddrAAAA = net.ParseIP("::")
		} else if dummyAddrAAAA.To4() != nil || dummyAddrAAAA.To16() == nil {
			log.Panicf("Unable to initialize the DNS cache;"+
				"not a valid IPv6 address: %s", dummyAddrAAAA)
		}
	*/

	/*
		recIdxMap := make(map[uint16]int, len(cachedRecordTypes))
		for i, rt := range cachedRecordTypes {
			recIdxMap[rt.Value] = i
		}
	*/

	ch := &DNSMapCache{
		cacheMap:      make(map[string]*SequentialCache),
		purgeQueue:    make([]string, 0),
		purgeInterval: purgeInterval,
		forcePurge:    make(chan struct{}, 0),
		cacheMaxSize:  maxSize,
	}
	go ch.PurgeAllExpired()
	return ch
}

func (ch *DNSMapCache) SafeUnlocker() func() {
	if ch != nil {
		log.Panicf("DNSMapCache.SafeUnlocker() was invoked on nil value")
	}
	isThreadLocked := true
	return func() {
		if isThreadLocked {
			isThreadLocked = false
			ch.Unlock()
		}
	}
}

func (ch *DNSMapCache) PurgeAllExpired() {
	if ch == nil {
		panic("Attempted to call *DNSMapCache.PurgeExpired() on a nil value")
	}
	purgeTimer := time.NewTimer(ch.purgeInterval)
	for {
		select {
		case <-purgeTimer.C:
			ch.Lock()
			oldQueue := ch.purgeQueue
			ch.purgeQueue = make([]string, 0)
			ch.Unlock()
			for _, cname := range oldQueue {
				ch.PurgeExpiredDomain(cname)
			}
			purgeTimer.Reset(ch.purgeInterval)
		}
	}
}

func (ch *DNSMapCache) PurgeExpiredDomain(cname string) {
	if ch == nil {
		panic("Attempted to call *DNSMapCache.PurgeExpired() on a nil value")
	}
	ch.Lock()
	defer ch.Unlock()
	if sc, ok := ch.cacheMap[cname]; ok {
		if sc == BlockedEntry {
			delete(ch.cacheMap, cname)
		}
		newRecords := make([]DNSRecord, 0)
		for i := 0; i < len(sc.records); i++ {
			if !sc.records[i].IsExpired() {
				newRecords = append(newRecords, sc.records[i])
			}
		}
		if len(newRecords) > 0 {
			sc.records = newRecords
			ch.purgeQueue = append(ch.purgeQueue, cname)
		} else {
			delete(ch.cacheMap, cname)
		}
	}
}

func (ch *DNSMapCache) Query(q *dns.Msg) (*dns.Msg, error) {
	if ch == nil {
		return nil, fmt.Errorf("%w: DNSMapCache.Query()", NilInvokeError)
	}
	if q == nil {
		return nil, fmt.Errorf("%w: DNSMapCache.Query()", NilArgumentError)
	}
	if len(q.Question) != 1 {
		return nil, fmt.Errorf(
			"%w: %d", InvalidQuestionError, len(q.Question))
	}
	recType := q.Question[0].Qtype
	if recType != dns.TypeA && recType != dns.TypeAAAA {
		return nil, nil
	}
	dname := q.Question[0].Name
	cname := dns.CanonicalName(dname)
	ch.RLock()
	sc, ok := ch.cacheMap[cname]
	ch.RUnlock()
	if !ok {
		return nil, nil
	}
	if sc == BlockedEntry {
		return nil, fmt.Errorf(
			"%w: %s %s", DomainBlockedError, dname, dns.TypeToString[recType])
	}
	return sc.Fetch(recType)
}

func (ch *DNSMapCache) Update(msg *dns.Msg) error {
	if ch == nil {
		return fmt.Errorf("%w: DNSMapCache.Update()", NilInvokeError)
	}
	if msg == nil {
		return fmt.Errorf("%w: DNSMapCache.Update()", NilArgumentError)
	}
	if len(msg.Question) != 1 {
		return fmt.Errorf(
			"%w (%d): DNSMapCache.Update()",
			InvalidQuestionError, len(msg.Question))
	}
	if !msg.Response {
		return fmt.Errorf(
			"%w: DNSMapCache.Update()", NonResponseCachingError)
	}
	if len(msg.Answer) == 0 {
		return fmt.Errorf(
			"%w (%d): DNSMapCache.Update()",
			InvalidAnswerError, len(msg.Question))
	}
	recType := msg.Question[0].Qtype
	if recType != dns.TypeA && recType != dns.TypeAAAA {
		return fmt.Errorf(
			"%w (%s): DNSMapCache.Update()",
			UnsupportedCachingError, msg.Question[0].String())
	}
	dname := msg.Question[0].Name
	cname := dns.CanonicalName(dname)
	if &cname == &dname {
		cname = strings.Clone(cname)
	}
	UnlockOnce := ch.SafeUnlocker()
	ch.Lock()
	defer UnlockOnce()
	sc, ok := ch.cacheMap[cname]
	if !ok {
		sc = new(SequentialCache)
		ch.cacheMap[cname] = sc
		ch.purgeQueue = append(ch.purgeQueue, cname)
	} else if sc == BlockedEntry {
		return fmt.Errorf(
			"cannot update the cache; the domain is blocked: %s",
			dname)
	}
	UnlockOnce()
	return sc.Store(msg)
}

func (ch *DNSMapCache) IsBlocked(dname string) (bool, error) {
	if ch == nil {
		return true, fmt.Errorf("%w: DNSMapCache.IsBlocked()", NilInvokeError)
	}
	cname := dns.CanonicalName(dname)
	ch.RLock()
	sc, ok := ch.cacheMap[cname]
	ch.RUnlock()
	return ok && sc == BlockedEntry, nil
}

func (ch *DNSMapCache) Block(dname string) error {
	if ch == nil {
		return fmt.Errorf("%w: DNSMapCache.Block()", NilInvokeError)
	}
	cname := dns.CanonicalName(dname)
	if &cname == &dname {
		cname = strings.Clone(cname)
	}
	ch.Lock()
	defer ch.Unlock()
	sc, ok := ch.cacheMap[cname]
	if !ok {
		ch.purgeQueue = append(ch.purgeQueue, cname)
	} else if sc == BlockedEntry {
		return fmt.Errorf("domain is already blocked: %s", dname)
	}
	ch.cacheMap[cname] = BlockedEntry
	return nil
}

func (ch *DNSMapCache) Unblock(dname string) error {
	if ch == nil {
		return fmt.Errorf("%w: DNSMapCache.Unblock()", NilInvokeError)
	}
	cname := dns.CanonicalName(dname)
	ch.Lock()
	defer ch.Unlock()
	sc, ok := ch.cacheMap[cname]
	if !ok || sc != BlockedEntry {
		return fmt.Errorf("domain is already unblocked: %s", dname)
	}
	delete(ch.cacheMap, cname)
	newQueue := make([]string, 0)
	for _, s := range ch.purgeQueue {
		if s != cname {
			newQueue = append(newQueue, s)
		}
	}
	ch.purgeQueue = newQueue
	return nil
}

func (ch *DNSMapCache) ReclaimMem() error {
	if ch == nil {
		return fmt.Errorf("%w: DNSMapCache.ReclaimMem()", NilInvokeError)
	}
	ch.Lock()
	defer ch.Unlock()
	cm := make(map[string]*SequentialCache)
	for k, v := range ch.cacheMap {
		cm[k] = v
	}
	ch.cacheMap = cm
	return nil
}

func (ch *DNSMapCache) Flush(dname string) error {
	if ch == nil {
		return fmt.Errorf("%w: DNSMapCache.Flush()", NilInvokeError)
	}
	ch.Lock()
	defer ch.Unlock()
	cname := dns.CanonicalName(dname)
	if _, ok := ch.cacheMap[cname]; ok {
		delete(ch.cacheMap, cname)
		newQueue := make([]string, 0)
		for _, s := range ch.purgeQueue {
			if s != cname {
				newQueue = append(newQueue, s)
			}
		}
		ch.purgeQueue = newQueue
	}
	return nil
}

func (ch *DNSMapCache) FlushAll() error {
	if ch == nil {
		return fmt.Errorf("%w: DNSMapCache.FlushAll()", NilInvokeError)
	}
	ch.Lock()
	defer ch.Unlock()
	ch.cacheMap = make(map[string]*SequentialCache)
	ch.purgeQueue = make([]string, 0)
	return nil
}
