package main

import (
	"github.com/miekg/dns"
	"strings"
	"sync"
)

// InflightSession represents the bundle of ongoing duplicate requests.
type InflightSession struct {
	Cached *dns.Msg
	Wait   chan struct{}
}

// InflightManager represents the lookup table for InflightSession.
type InflightManager struct {
	sessions     map[string]*InflightSession
	requestCount map[string]int
	sync.Mutex
}

// NewInflightManager creates a new inflight session manager.
func NewInflightManager() *InflightManager {
	im := &InflightManager{
		sessions:     make(map[string]*InflightSession),
		requestCount: make(map[string]int),
	}
	return im
}

// InflightSessionKey generates the session key based on the server IP address,
// client IP address, and DNS query.
func InflightSessionKey(w dns.ResponseWriter, req *dns.Msg) string {
	lAddr := w.LocalAddr()
	rAddr := w.RemoteAddr()
	q := req.Question[0]
	key := []string{
		lAddr.String(),
		rAddr.String(),
		dns.CanonicalName(q.Name),
		dns.Class(q.Qclass).String(),
		dns.Type(q.Qtype).String(),
	}
	return strings.Join(key, "\t")
}

// ReserveSession either retrieves the underlying session or creates one.
// It returns true if a new session was created, otherwise false.
func (im *InflightManager) ReserveSession(k string) (*InflightSession, bool) {
	im.Lock()
	defer im.Unlock()
	_, found := im.requestCount[k]
	if !found {
		im.requestCount[k] = 1
		im.sessions[k] = &InflightSession{
			Cached: new(dns.Msg),
			Wait:   make(chan struct{}, 0),
		}
		return im.sessions[k], true
	}
	im.requestCount[k]++
	return im.sessions[k], false
}

// ReleaseSession decrease the reserve count for the session. It returns true if
// there is still an ongoing session, otherwise it returns false.
func (im *InflightManager) ReleaseSession(k string) bool {
	im.Lock()
	defer im.Unlock()
	if n, ok := im.requestCount[k]; !ok {
		return false
	} else if n > 1 {
		im.requestCount[k]--
		return true
	}
	delete(im.requestCount, k)
	delete(im.sessions, k)
	return false
}
