package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func LatestTLDs(resolvers []*ServerConfig) (map[string]struct{}, error) {
	var resp *http.Response
	var err error
	tlds := make(map[string]struct{})
	for _, r := range resolvers {
		log.Printf("Creating HTTPS client from resolver %v", r.String())
		c := NewHTTPSClient(r.String())
		resp, err = c.Get(TLDListURL)
		c.CloseIdleConnections()
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf(
				"unable to fetch TLD list from IANA: HTTP status code %d",
				resp.StatusCode)
		}
		if tldStr, rerr := ReadAllString(resp.Body); rerr != nil {
			err = rerr
			continue
		} else {
			tldsList := strings.Split(tldStr, "\n")
			for i := 0; i < len(tldsList); i++ {
				if !strings.HasPrefix(tldsList[i], "#") {
					tlds[tldsList[i]] = struct{}{}
				}
			}
			return tlds, nil
		}
	}
	return nil, fmt.Errorf("unable to fetch TLD list from IANA: %w", err)
}
