package adblocker

import (
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

// Returns the slice of slices containing individual subdomain components,
// e.g. "||www.google.com^" -> ["www.google.com."]
func parseABPList(abpList string) ([]string, error) {
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
