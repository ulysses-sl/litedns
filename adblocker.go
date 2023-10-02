package main

import (
	"fmt"
	"github.com/miekg/dns"
	"hash/fnv"
	"log"
	"net/http"
	"strings"
	"time"
)

type AdBlocker interface {
	IsBlocked(string) bool
	Refresh() error
}

func NewAdBlocker(bootstrap []*ServerConfig,
	selfResolver *ServerConfig,
	filterURL string) AdBlocker {
	if len(bootstrap) == 0 {
		log.Panicf("Bootstrap resolvers are empty: %v", bootstrap)
	}
	for _, r := range bootstrap {
		if r == nil {
			log.Panicf("Bootstrap resolvers supplied as nil: %v", bootstrap)
		}
	}
	if selfResolver == nil {
		panic("Self resolver was supplied as nil")
	}
	ab := &ABPFilterBlocker{
		useSelfResolv:    false,
		selfResolvClient: NewHTTPSClient(selfResolver.String()),
		httpsClients:     make([]*http.Client, len(bootstrap)),
		filterURL:        filterURL,
		filter:           make(map[string]struct{}),
		filterHash:       0,
		lastUpdate:       time.UnixMilli(0),
	}
	for i := 0; i < len(bootstrap); i++ {
		ab.httpsClients[i] = NewHTTPSClient(bootstrap[i].String())
	}
	return ab
}

type ABPFilterBlocker struct {
	useSelfResolv    bool
	selfResolvClient *http.Client
	httpsClients     []*http.Client
	filterURL        string
	filter           map[string]struct{}
	filterHash       uint64
	lastUpdate       time.Time
}

func (ab *ABPFilterBlocker) IsBlocked(dname string) bool {
	cname := dns.CanonicalName(dname)
	for cname != "" {
		if _, found := ab.filter[cname]; found {
			return true
		}
		cnameSplit := strings.SplitAfterN(cname, ".", 2)
		cname = cnameSplit[1]
	}
	return false
}

func (ab *ABPFilterBlocker) Refresh() error {
	var resp *http.Response
	var err error
	if ab.useSelfResolv {
		c := ab.selfResolvClient
		resp, err = c.Get(ab.filterURL)
		c.CloseIdleConnections()
		if err == nil {
			goto CheckResponse
		}
		ab.useSelfResolv = false
	}

	for _, c := range ab.httpsClients {
		resp, err = c.Get(ab.filterURL)
		c.CloseIdleConnections()
		if err == nil {
			break
		}
		time.Sleep(1000 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	ab.useSelfResolv = true

CheckResponse:
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"invalid HTTP status code on fetching list [%s]: %d",
			ab.filterURL,
			resp.StatusCode,
		)
	}
	var respBody string
	respBody, err = ReadAllString(resp.Body)
	if err != nil {
		return err
	}
	h := fnv.New64a()
	_, _ = h.Write(AsSlice(respBody))
	filterHash := h.Sum64()
	if filterHash == ab.filterHash {
		return nil
	}

	var blockList []string
	blockList, err = ParseABPList(respBody)
	if err != nil {
		return err
	}
	newFilter := make(map[string]struct{}, len(blockList))
	for _, entry := range blockList {
		newFilter[entry] = struct{}{}
	}
	ab.filter = newFilter
	ab.filterHash = filterHash
	return nil
}

// ParseABPList returns the slice of slices containing individual subdomain
// components, e.g. "||www.google.com^" -> ["www.google.com."]
func ParseABPList(abpList string) ([]string, error) {
	abpLines := strings.Split(abpList, "\n")
	blockList := make([]string, 0)
	for i, line := range abpLines {
		trimmed := strings.TrimRight(line, " \t")
		if len(trimmed) == 0 {
			continue
		}
		if strings.HasPrefix(trimmed, "!") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			if !strings.HasSuffix(trimmed, "]") {
				goto syntaxError
			}
			continue
		}
		if strings.HasPrefix(trimmed, "||") {
			if !strings.HasSuffix(trimmed, "^") || len(trimmed) <= 3 {
				goto syntaxError
			}
			blockDomain := trimmed[2 : len(trimmed)-1]
			cname := dns.CanonicalName(blockDomain)
			blockList = append(blockList, cname)
			continue
		}

	syntaxError:
		return nil, fmt.Errorf(
			"invalid abp syntax at line %d: %s",
			i+1,
			line,
		)
	}
	return blockList, nil
}
