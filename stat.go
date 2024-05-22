package main

import (
	"github.com/miekg/dns"
	"log"
	"time"
)

type LiteDNSStat struct {
	tLastUpdate      int64
	numCacheHit      [60]int32
	numCacheMiss     [60]int32
	numCacheExpired  [60]int32
	numNeverCached   [60]int32
	numBlocked       [60]int32
	cachedRespTime   [60]int64
	uncachedRespTime [60]int64
}

var GlobalStat *LiteDNSStat

func ClearStat(start, end int) {
	if start > end {
		ClearStat(start, 59)
		ClearStat(0, end)
		return
	}
	for i := start; i < end; i++ {
		GlobalStat.numCacheHit[i] = 0
		GlobalStat.numCacheMiss[i] = 0
		GlobalStat.numCacheExpired[i] = 0
		GlobalStat.numNeverCached[i] = 0
		GlobalStat.numBlocked[i] = 0
		GlobalStat.cachedRespTime[i] = 0
		GlobalStat.uncachedRespTime[i] = 0
	}
}

func AddStat(status CacheStatus, tElapsed int64) {
	now := time.Now().Unix()
	if GlobalStat == nil {
		GlobalStat = &LiteDNSStat{
			tLastUpdate: now,
		}
	} else if tSinceLast := now - GlobalStat.tLastUpdate; tSinceLast == 0 {
		// no-op
	} else if tSinceLast > 3600 {
		ClearStat(0, 60)
	} else {
		start := int((GlobalStat.tLastUpdate + 60) % 3600 / 60)
		end := int((now + 60) % 3600 / 60)
		ClearStat(start, end)
	}
	i := int(now % 3600 / 60)
	switch status {
	case CacheHit:
		GlobalStat.numCacheHit[i]++
		GlobalStat.cachedRespTime[i] += tElapsed
	case BlockedDomain:
		GlobalStat.numBlocked[i]++
		GlobalStat.cachedRespTime[i] += tElapsed
	case CacheMiss:
		GlobalStat.numCacheMiss[i]++
		GlobalStat.uncachedRespTime[i] += tElapsed
	case CacheExpired:
		GlobalStat.numCacheExpired[i]++
		GlobalStat.uncachedRespTime[i] += tElapsed
	case BypassCache:
		GlobalStat.numNeverCached[i]++
		GlobalStat.uncachedRespTime[i] += tElapsed
	}
}

func PrintStat() {
	if GlobalStat == nil {
		return
	}
	var cacheHit, cacheMiss, expired, neverCached, blocked int32
	var cachedResp, uncachedResp, totalResp int32
	var cachedRespTime, uncachedRespTime, totalRespTime int64
	for i := 0; i < 60; i++ {
		cacheHit += GlobalStat.numCacheHit[i]
		cacheMiss += GlobalStat.numCacheMiss[i]
		expired += GlobalStat.numCacheExpired[i]
		neverCached += GlobalStat.numNeverCached[i]
		blocked += GlobalStat.numBlocked[i]
		cachedRespTime += GlobalStat.cachedRespTime[i]
		uncachedRespTime += GlobalStat.uncachedRespTime[i]
	}
	uncachedResp = cacheMiss + expired + neverCached
	cachedResp = cacheHit + blocked
	totalResp = uncachedResp + cachedResp
	totalRespTime = uncachedRespTime + cachedRespTime
	log.Printf("Total responses: %d, Uncached responses: %d",
		totalResp, uncachedResp)
	if totalResp > 0 {
		log.Printf("Mean uncached response time: %d ms",
			totalRespTime/int64(totalResp))
	}
	if uncachedResp > 0 {
		log.Printf("Mean uncached response time: %d ms",
			uncachedRespTime/int64(uncachedResp))
	}
}

type RequestLogEntry struct {
	tStartMillis int64
	cacheStatus  CacheStatus
	rcode        int
	domain       string
	qType        uint16
	isLocalReq   bool
}

func PopulateLogEntry(logEntry *RequestLogEntry, resp *dns.Msg) {
	if !resp.Response {
		panic("Attempted to populate log entry with malformed response")
	}
	if len(resp.Question) == 1 {
		logEntry.domain = resp.Question[0].Name
		logEntry.qType = resp.Question[0].Qtype
	}
	logEntry.rcode = resp.Rcode
}

func StartLogEntry() (func(*RequestLogEntry), *RequestLogEntry) {
	f := func(logEntry *RequestLogEntry) {
		tEndMillis := time.Now().UnixMilli()
		tElapsed := tEndMillis - logEntry.tStartMillis
		AddStat(logEntry.cacheStatus, tElapsed)
		var networkType, cacheStatus, domain, qTypeStr, rcodeStr string
		if logEntry.isLocalReq {
			networkType = LabelLocalQuery
		} else {
			networkType = LabelUpstreamQuery
		}
		switch logEntry.cacheStatus {
		case CacheHit:
			cacheStatus = LabelCacheHit
		case CacheMiss:
			cacheStatus = LabelCacheMiss
		case CacheExpired:
			cacheStatus = LabelCacheExpired
		case BypassCache:
			cacheStatus = LabelNoCaching
		case BlockedDomain:
			cacheStatus = LabelBlocked
		case CacheError:
			cacheStatus = LabelUnknown
		default:
			cacheStatus = LabelUnknown
		}
		if logEntry.domain == "" {
			domain = "UNKNOWN"
			qTypeStr = "???"
		} else {
			domain = logEntry.domain
			qTypeStr = dns.TypeToString[logEntry.qType]
		}
		rcodeStr = dns.RcodeToString[logEntry.rcode]
		log.Printf("[%s][%s] %-6s %s (%s, %d ms)",
			networkType,
			cacheStatus,
			qTypeStr,
			domain,
			rcodeStr,
			tElapsed)
	}

	r := &RequestLogEntry{
		tStartMillis: time.Now().UnixMilli(),
	}
	return f, r
}
