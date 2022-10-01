package main

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
	"time"
)

func GetTTLDeadline(ttl uint32) *time.Time {
	now := time.Now()
	ttlDuration := time.Second * time.Duration(ttl)
	deadline := now.Add(ttlDuration)
	return &deadline
}

func isLocalIPLookup(name string) bool {
	if strings.HasSuffix(name, ".in-addr.arpa.") {
		lbls := strings.Split(name, ".")
		numLbls := len(lbls)
		if lbls[numLbls-4] == "127" {
			return true
		}
		if lbls[numLbls-4] == "10" {
			return true
		}
		if lbls[numLbls-4] == "192" && numLbls > 4 && lbls[numLbls-5] == "168" {
			return true
		}
	}
	return false
}

func strcmp(cname string, entry string) int {
	maxLen := len(cname)
	if len(cname) > len(entry) {
		maxLen = len(entry)
	}
	i := 0
	for i < maxLen {
		if cname[i] < entry[i] {
			return -1
		} else if cname[i] > entry[i] { // search for later entry
			return 1
		}
		i++
	}
	if len(cname) == len(entry) {
		return 0
	} else if i >= len(cname) {
		return -1
	} else if cname[i] == '.' {
		return 0
	} else {
		return 1
	}
}

func reverse(s string) string {
	var res []byte
	for i := len(s) - 1; i >= 0; i-- {
		res = append(res, s[i])
	}
	return string(res)
}

func parseABPSyntax(line string) (*string, error) {
	if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
		cname := dns.CanonicalName(line[2 : len(line)-1])
		return &cname, nil
	}
	return nil, errors.New("Not an ABP syntax")
}
