package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"sync"
	"time"
)

type cacheKey struct {
	cname   string
	session string
	recType uint16
}

func asCacheKey(msg *dns.Msg, session string) cacheKey {
	if len(msg.Question) != 1 {
		log.Panicf("Invalid *dns.Msg with %d questions (should be 1)",
			len(msg.Question))
	}
	return cacheKey{
		cname:   dns.CanonicalName(msg.Question[0].Name),
		session: session,
		recType: msg.Question[0].Qtype,
	}
}

// DNSCache is the interface that wraps the DNS cache operations.
type DNSCache interface {
	Query(*dns.Msg, string) (*dns.Msg, error)
	Update(*dns.Msg, string) error
	PurgeDomain(string) int
	PurgeExpired() int
	Flush() int
}

type DNSMapCache struct {
	cacheMap   map[cacheKey]int
	lruCache   *LRUCache[DNSRecord]
	cachedType map[int32]struct{}
	cacheTTL   int64
	ForceFlush chan<- struct{}
	sync.RWMutex
}

func NewDNSCache(cfg *DNSCacheConfig) DNSCache {
	forceFlush := make(chan struct{}, 0)
	ch := &DNSMapCache{
		cacheMap:   make(map[cacheKey]int, cfg.CacheSize),
		lruCache:   NewLRUCache[DNSRecord](cfg.CacheSize),
		cachedType: make(map[int32]struct{}),
		cacheTTL:   cfg.CacheTTL,
		ForceFlush: forceFlush,
	}
	purgingInterval := DefaultCachePurgeInterval * time.Second
	compactInterval := DefaultCacheCompactInterval * time.Second
	go func() {
		pTimer := time.NewTimer(purgingInterval)
		cTimer := time.NewTimer(compactInterval)
		for {
			select {
			case <-forceFlush:
				if !pTimer.Stop() {
					<-pTimer.C
				}
				if !cTimer.Stop() {
					<-cTimer.C
				}
				ch.Compact()
				pTimer.Reset(purgingInterval)
				cTimer.Reset(compactInterval)
			case <-cTimer.C:
				if !pTimer.Stop() {
					<-pTimer.C
				}
				ch.Compact()
				pTimer.Reset(purgingInterval)
				cTimer.Reset(compactInterval)
			case <-pTimer.C:
				ch.PurgeExpired()
				pTimer.Reset(purgingInterval)
			}
		}
	}()
	return ch
}

// Query returns a result if the given query is valid and a cached response
// is available.
func (ch *DNSMapCache) Query(q *dns.Msg, session string) (*dns.Msg, error) {
	if ch == nil {
		panic("Invoked *DNSMapCache.Query() on a nil ptr")
	}
	if q == nil {
		return nil, fmt.Errorf("%w: *DNSMapCache.Query()", NilArgumentError)
	}
	if len(q.Question) != 1 {
		return nil, fmt.Errorf(
			"%w: %d", InvalidQuestionError, len(q.Question))
	}
	if _, ok := ch.cachedType[int32(q.Question[0].Qtype)]; !ok {
		return nil, fmt.Errorf(
			"%w (%s): *DNSMapCache.Query()",
			UnsupportedCachingError, q.Question[0].String())
	}
	ch.RLock()
	defer ch.RUnlock()
	k := asCacheKey(q, session)
	i, keyFound := ch.cacheMap[k]
	if !keyFound {
		return nil, nil
	}
	cached, ok := ch.lruCache.Get(i)
	if !ok {
		return nil, nil
	}
	return cached.TTLAdjustedEntry(), nil
}

// Update returns error if the query question section is invalid,
// if the message is not a valid response, or the query type is not
// allowed to be cached. It substitutes the old entry with the new if present.
// Otherwise, it adds the new entry to the cache.
func (ch *DNSMapCache) Update(msg *dns.Msg, session string) error {
	if ch == nil {
		panic("Invoked *DNSMapCache.Update() on a nil ptr")
	}
	if msg == nil {
		panic("Invoked *DNSMapCache.Update() with a nil *dns.Msg")
	}
	if len(msg.Question) != 1 {
		return fmt.Errorf(
			"%w (%d): *DNSMapCache.Update()",
			InvalidQuestionError, len(msg.Question))
	}
	if !msg.Response {
		return fmt.Errorf(
			"%w: *DNSMapCache.Update()", NonResponseCachingError)
	}
	if _, ok := ch.cachedType[int32(msg.Question[0].Qtype)]; !ok {
		return fmt.Errorf(
			"%w (%s): *DNSMapCache.Update()",
			UnsupportedCachingError, msg.Question[0].String())
	}
	// RFC 6891: OPT pseudo-RR MUST NOT be cached.
	for i := len(msg.Extra) - 1; i >= 0; i-- {
		if msg.Extra[i].Header().Rrtype == dns.TypeOPT {
			msg.Extra = append(msg.Extra[:i], msg.Extra[i+1:]...)
			break
		}
	}
	ttl := ch.cacheTTL
	// RFC 2308: Negative entry MUST be cached, but with limited time
	if msg.Rcode != dns.RcodeSuccess {
		ttl = DefaultNegativeCacheTTL
	}
	expiry := NewExpiry(ttl)
	ch.Lock()
	defer ch.Unlock()
	k := asCacheKey(msg, session)
	if i, ok := ch.cacheMap[k]; ok {
		_, _ = ch.lruCache.Delete(i)
	}
	record := DNSRecord{session: session, entry: msg, expiry: expiry}
	i, overwrite, old := ch.lruCache.Add(record)
	if overwrite {
		oldK := asCacheKey(old.entry, session)
		delete(ch.cacheMap, oldK)
	}
	ch.cacheMap[k] = i
	return nil
}

// PurgeDomain removes all entries that matches the domain name,
// and returns the total number of removed entries.
func (ch *DNSMapCache) PurgeDomain(dname string) int {
	if ch == nil {
		panic("Invoked *DNSMapCache.PurgeDomain() on a nil ptr")
	}
	cname := dns.CanonicalName(dname)
	ch.Lock()
	defer ch.Unlock()
	return ch.purgeIfTrue(func(record DNSRecord) bool {
		cnameOld := dns.CanonicalName(record.entry.Question[0].Name)
		return cname == cnameOld
	})
}

// PurgeExpired removes all entries that have expired, and returns
// the total number of removed entries.
func (ch *DNSMapCache) PurgeExpired() int {
	if ch == nil {
		panic("Invoked *DNSMapCache.PurgeExpired() on a nil ptr")
	}
	ch.Lock()
	defer ch.Unlock()
	return ch.purgeIfTrue(func(record DNSRecord) bool {
		return record.IsExpired()
	})
}

// Flush removes all entries, and returns the total number of removed entries.
func (ch *DNSMapCache) Flush() int {
	if ch == nil {
		panic("Invoked *DNSMapCache.Flush() on a nil ptr")
	}
	ch.Lock()
	defer ch.Unlock()
	ch.cacheMap = make(map[cacheKey]int, ch.lruCache.MaxSize)
	return ch.lruCache.Flush()
}

// Compact purges all expired entries and compact the LRU cache.
func (ch *DNSMapCache) Compact() {
	if ch == nil {
		panic("Invoked *DNSMapCache.Compact() on a nil ptr")
	}
	ch.Lock()
	defer ch.Unlock()
	_ = ch.purgeIfTrue(func(record DNSRecord) bool {
		return record.IsExpired()
	})
	cleanCacheMap := make(map[cacheKey]int, ch.lruCache.MaxSize)
	ch.lruCache.CompactAndSort(func(i int, record DNSRecord) {
		k := asCacheKey(record.entry, record.session)
		cleanCacheMap[k] = i
	})
	ch.cacheMap = cleanCacheMap
}

func (ch *DNSMapCache) purgeIfTrue(pred func(record DNSRecord) bool) int {
	if ch == nil {
		panic("Invoked *DNSMapCache.purgeIfTrue() on a nil ptr")
	}
	purged := ch.lruCache.Purge(pred)
	for _, old := range purged {
		k := asCacheKey(old.entry, old.session)
		delete(ch.cacheMap, k)
	}
	return len(purged)
}
