package main

import (
	"github.com/miekg/dns"
	"log"
	"net/http"
	"slices"
	"time"
)

// AdBlocker represents the component that contains a criteria filter, can tell
// if a host is blocked based on the filter, and may refresh the filter list.
type AdBlocker interface {
	Block(string) error
	IsBlocked(string) bool
	Refresh() error
}

func NewAdBlockerHTTP(resolvers []*ServerConfig, filterURL string) AdBlocker {
	if len(resolvers) == 0 {
		log.Panicf("Bootstrap resolvers are empty: %v", resolvers)
	}
	for _, r := range resolvers {
		if r == nil {
			log.Panicf("Bootstrap resolvers supplied as nil: %v", resolvers)
		}
	}
	clients := make([]*http.Client, len(resolvers))
	for i := 0; i < len(resolvers); i++ {
		clients[i] = NewHTTPSClient(resolvers[i].String())
	}
	filter := NewABTreeFilter(FetchFilterByURL(clients, filterURL))
	return filter
}

// ABTreeFilter is an ABFilter implemented with tree of nodes.
type ABTreeFilter struct {
	rootNode    *ABTreeFilterNode
	fetchFilter func() (string, error)
	filterHash  uint64
	lastUpdate  time.Time
}

// ABTreeFilterNode is a node for ABTreeFilter that uses map for tree structure.
type ABTreeFilterNode struct {
	nextLabels map[string]*ABTreeFilterNode
	isBlocked  bool
}

func NewABTreeFilterNode() *ABTreeFilterNode {
	return &ABTreeFilterNode{
		nextLabels: make(map[string]*ABTreeFilterNode),
		isBlocked:  false,
	}
}

func (rootNode *ABTreeFilterNode) InsertBlockedDomains(domains []string) {
	if rootNode == nil {
		panic("Attempted to insert domains into nil *ABTreeFilterNode")
	}
	for _, dname := range domains {
		curr := rootNode
		cname := dns.CanonicalName(dname)
		labels := dns.SplitDomainName(cname)
		slices.Reverse(labels)
		for _, lbl := range labels {
			if _, ok := curr.nextLabels[lbl]; !ok {
				curr.nextLabels[lbl] = NewABTreeFilterNode()
			}
			curr = curr.nextLabels[lbl]
		}
		curr.isBlocked = true
	}
}

func NewABTreeFilter(fetchFilter func() (string, error)) AdBlocker {
	if fetchFilter == nil {
		panic("No filter source was given for ABTreeFilter")
	}
	abpFilter, ferr := fetchFilter()
	if ferr != nil {
		log.Panicf("Unable to fetch the initial ABP filter string: %v", ferr)
	}
	domains, perr := ParseABPList(abpFilter)
	if perr != nil {
		return nil
	}
	f := &ABTreeFilter{
		rootNode:   NewABTreeFilterNode(),
		filterHash: HashString(abpFilter),
		lastUpdate: time.Now(),
	}
	f.rootNode.InsertBlockedDomains(domains)
	return f
}

func UpdateABTreeFilter(f *ABTreeFilter) error {
	if f == nil {
		panic("Attempted to update nil *ABTreeFilter")
	}
	abpFilter, ferr := f.fetchFilter()
	if ferr != nil {
		return ferr
	}
	domains, perr := ParseABPList(abpFilter)
	if perr != nil {
		return perr
	}
	fh := HashString(abpFilter)
	if f.filterHash == fh {
		return nil
	}
	rNode := NewABTreeFilterNode()
	rNode.InsertBlockedDomains(domains)
	f.lastUpdate = time.Now()
	f.filterHash = fh
	f.rootNode = rNode
	return nil
}

func (f *ABTreeFilter) Refresh() error {
	return UpdateABTreeFilter(f)
}

func (f *ABTreeFilter) Block(dname string) error {
	if cname := dns.CanonicalName(dname); cname != "." {
		f.rootNode.InsertBlockedDomains([]string{cname})
		return nil
	}
	return NewInvalidDomainNameError(dname)
}

func (f *ABTreeFilter) IsBlocked(dname string) bool {
	curr := f.rootNode
	cname := dns.CanonicalName(dname)
	labels := dns.SplitDomainName(cname)
	slices.Reverse(labels)
	for _, lbl := range labels {
		if _, ok := curr.nextLabels[lbl]; !ok {
			return false
		}
		if curr.nextLabels[lbl].isBlocked {
			return true
		}
		curr = curr.nextLabels[lbl]
	}
	return false
}

func FetchFilterByURL(cs []*http.Client, url string) func() (string, error) {
	return func() (string, error) {
		var respBody string
		var err error
		for _, c := range cs {
			if respBody, err = GetBody(c, url); err == nil {
				return respBody, nil
			}
			time.Sleep(1000 * time.Millisecond)
		}
		return "", err
	}
}
