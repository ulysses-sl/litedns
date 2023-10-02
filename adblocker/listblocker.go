package adblocker

import (
	"crypto/rand"
	"fmt"
	"hash/fnv"
	"litedns/client"
	"litedns/config"
	"litedns/unsafeutil"
	"log"
	"net/http"
	"sort"
	"time"
	"unsafe"
)

const BFBitSize = 524288
const BFNumHash = 3   /* Num of hash attempts */
const BFSuffixLen = 8 /* Num of random suffix */

type listAdBlocker struct {
	set           memberSet
	suffix        []byte
	resolvers     []string
	blockListURL  string
	blockList     [][]string
	blockListHash uint64
	refreshOrder  chan chan error
}

func NewListAdBlocker(blockListURL string,
	resolvers []*config.ServerConfig) AdBlocker {
	ab := &listAdBlocker{
		set:          newBloomFilter(BFBitSize, BFNumHash),
		suffix:       make([]byte, BFSuffixLen),
		resolvers:    make([]string, len(resolvers)),
		blockListURL: blockListURL,
		blockList:    make([][]string, 0),
	}
	_, err := rand.Read(ab.suffix)
	if err != nil {
		panic("Unable to create suffix for bloom filter")
	}
	for i := 0; i < len(resolvers); i++ {
		ab.resolvers[i] = resolvers[i].String()
	}

	go ab.scheduleRefresh(24*time.Hour, 1*time.Hour)

	return ab
}

func (ab *listAdBlocker) IsBlocked(dname string) bool {
	// From TLD to subdomain, to determine the subdomain depth
	h := fnv.New64a()
	subdomains := config.Subdomains(dname)
	/* Skip checking TLD alone, since it is too common */
	tld := subdomains[len(subdomains)-1]
	writeHash(h, byteSlice(tld))
	var matchDepth int
	for i := len(subdomains) - 2; i >= 0; i-- {
		sd := subdomains[i]
		if !ab.contains(writeAndSum(h, byteSlice(sd))) {
			matchDepth = i + 1
			break
		}
	}
	if matchDepth >= len(subdomains)-1 {
		/* At most matched TLD; no need to hustle */
		return false
	}
	// From subdomain to TLD, cumulatively summed up
	h = fnv.New64a()
	for i := matchDepth; i < len(subdomains); i++ {
		sd := subdomains[i]
		writeHash(h, byteSlice(sd))
	}
	if !ab.contains(h.Sum64()) {
		return false
	}
	for i := 0; i < BFNumHash; i++ {
		if !ab.contains(writeAndSum(h, ab.suffix)) {
			return false
		}
	}
	return ab.isInBlockList(subdomains[matchDepth:])
}

func (ab *listAdBlocker) isInBlockList(subdomains []string) bool {
	i, j := 0, len(ab.blockList)
	for i <= j {
		m := int(uint(i+j) >> 1)
		switch c := compare(subdomains, ab.blockList[m]); c {
		case -1:
			j = m - 1
		case 1:
			i = m + 1
		case 0:
			return true
		default:
			log.Panicf("Binary search compare() unknown retval: %d", c)
		}
	}
	return false
}

func compare(subdomains []string, blockEntry []string) int {
	i := 0
	for {
		if i >= len(blockEntry) {
			/* if all block entry subdomains matched, it's a match */
			return 0
		}
		if i >= len(subdomains) {
			/* Block entry is longer than the given domain */
			return -1
		}
		if subdomains[i] < blockEntry[i] {
			return -1
		}
		if subdomains[i] > blockEntry[i] {
			return 1
		}
		i++
	}
}

func less(blockList [][]string) func(int, int) bool {
	return func(i, j int) bool {
		maxCompLen := len(blockList[i])
		if len(blockList[j]) < maxCompLen {
			maxCompLen = len(blockList[j])
		}
		for k := 0; k < maxCompLen; k++ {
			if blockList[i][k] < blockList[j][k] {
				return true
			}
			if blockList[i][k] > blockList[j][k] {
				return true
			}
		}
		return maxCompLen == len(blockList[i])
	}
}

func (ab *listAdBlocker) Refresh() error {
	status := make(chan error)
	ab.refreshOrder <- status
	return <-status
}

func (ab *listAdBlocker) doRefresh() error {
	var err error
	for _, r := range ab.resolvers {
		c := client.NewHTTPSClient(r)
		resp, gerr := c.Get(ab.blockListURL)
		c.CloseIdleConnections()
		if gerr != nil {
			err = gerr
			continue
		}
		/* Request was made but application error exists; do not retry */
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf(
				"invalid HTTP status code on fetching list [%s]: %d",
				ab.blockListURL,
				resp.StatusCode,
			)
		}
		respBody, rerr := unsafeutil.ReadAllStr(resp.Body)
		if rerr != nil {
			return rerr
		}
		h := fnv.New64a()
		_, _ = h.Write([]byte(respBody))
		blockListHash := h.Sum64()
		if blockListHash == ab.blockListHash {
			return nil
		}
		blockList, perr := parseABPList(respBody)
		if perr != nil {
			return perr
		}
		sort.Slice(blockList, less(blockList))
		newBF := createBF(blockList, ab.suffix)
		ab.blockList = blockList
		ab.blockListHash = blockListHash

		ab.bloomFilter = newBF
		return nil
	}
	return err
}

func createBF(blockList [][]string, suffix []byte) []byte {
	bf := make([]byte, BFByteSize)
	for _, entry := range blockList {
		/* Everything from the TLD to subdomain, step by step cumulative */
		h := fnv.New64a()
		/* Skip checking TLD alone, since it is too common */
		tld := entry[len(entry)-1]
		_, _ = h.Write(unsafe.Slice(unsafe.StringData(tld), len(tld)))
		for i := len(entry) - 2; i >= 0; i-- {
			sd := entry[i]
			_, _ = h.Write(unsafe.Slice(unsafe.StringData(sd), len(sd)))
			addToBF(bf, h.Sum64())
		}
		/* Subdomain from TLD, cumulative at once */
		h = fnv.New64a()
		for i := 0; i < len(entry); i++ {
			sd := entry[i]
			_, _ = h.Write(unsafe.Slice(unsafe.StringData(sd), len(sd)))
		}
		addToBF(bf, h.Sum64())
		/* Additional hash function calls */
		for i := 0; i < BFNumHash; i++ {
			_, _ = h.Write(suffix)
			addToBF(bf, h.Sum64())
		}
	}
	return bf
}

func (ab *listAdBlocker) listen() {
	for {
		select {
		case statusPipe := <-ab.refreshOrder:
			err := ab.doRefresh()
			if statusPipe != nil {
				statusPipe <- err
			}
		}
	}
}

func (ab *listAdBlocker) scheduleRefresh(onSuccess, onFailure time.Duration) {
	var err error
	var t *time.Timer
	var i time.Duration
	for {
		err = ab.Refresh()
		if err == nil {
			log.Printf("AdBlock list was updated with %d entries.",
				len(ab.blockList))
			i = onSuccess
		} else {
			log.Printf("AdBlock list update has failed: %s", err)
			i = onFailure
		}
		t = time.NewTimer(i)
		<-t.C
	}
}

func (ab *listAdBlocker) contains(val uint64) bool {
	bitPos := val % BFBitSize
	byteOffset := bitPos / 8
	bitOffset := bitPos % 8
	return (1<<bitOffset)&ab.bloomFilter[byteOffset] != 0
}

func addToBF(bloomFilter []byte, val uint64) {
	bitPos := val % BFBitSize
	byteOffset := bitPos / 8
	bitOffset := bitPos % 8
	bloomFilter[byteOffset] |= 1 << bitOffset
}
