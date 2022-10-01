package main

import (
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"time"
)

type AdBlocker interface {
	BlockDomain(string)
	BlockIfMatch(string) bool
}

type oisdAdBlocker struct {
	resolverIP    string
	resolverProto string
	oisdListUrl   string
	blockList     *[]string
	blockQueue    chan string
	cache         DNSCache
}

func NewAdBlocker(cache DNSCache) AdBlocker {
	bq := make(chan string, 1)

	ab := oisdAdBlocker{
		resolverIP:    "1.1.1.1:853",
		resolverProto: "tcp",
		oisdListUrl:   "https://abp.oisd.nl/",
		blockList:     nil,
		blockQueue:    bq,
		cache:         cache,
	}

	ab.processQueue()
	ab.queueListUpdate()

	return &ab
}

func (ab *oisdAdBlocker) BlockDomain(domainName string) {
	ab.blockQueue <- domainName
}

func (ab *oisdAdBlocker) BlockIfMatch(cname string) bool {
	cnameR := reverse(cname)
	i := 0
	j := len(*ab.blockList) - 1
	for i <= j {
		m := (i + j) / 2
		res := strcmp(cnameR, (*ab.blockList)[m])
		if res < 0 {
			j = m - 1
		} else if res > 0 {
			i = m + 1
		} else {
			domainToBlock := reverse((*ab.blockList)[m])
			ab.BlockDomain(domainToBlock)
			//log.Printf("[WRN] Blocking %s", cname)
			return true
		}
	}
	return false
}

func (ab *oisdAdBlocker) processQueue() {
	go func() {
		for {
			cname := <-ab.blockQueue
			ab.cache.ForceResp(cname)
		}
	}()
}

func (ab *oisdAdBlocker) queueListUpdate() {
	s := ab.updateList()
	go func(success bool) {
		for {
			if success {
				time.Sleep(time.Hour * 12)
			} else {
				time.Sleep(time.Hour * 1)
			}
			success = ab.updateList()
		}
	}(s)
}

func (ab *oisdAdBlocker) updateList() bool {
	client := NewHTTPSClient(ab.resolverProto, ab.resolverIP)
	resp, err := client.Get(ab.oisdListUrl)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	lines := strings.Split(string(body), "\n")

	blockList := []string{}

	for i := range lines {
		cname, err := parseABPSyntax(lines[i])
		if err == nil {
			blockList = append(blockList, reverse(*cname))
		}
	}

	if len(blockList) > 0 {
		sort.Strings(blockList)
		ab.blockList = &blockList
		log.Printf("%d Adblock entries added from oisd.nl", len(*(ab.blockList)))
		return true
	}
	return false
}
