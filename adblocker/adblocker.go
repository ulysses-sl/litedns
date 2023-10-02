package adblocker

import (
	"fmt"
	"hash/fnv"
	"io"
	"litedns/client"
	"litedns/config"
	"litedns/unsafeutil"
	"net/http"
	"sort"
)

type AdBlocker interface {
	IsBlocked(string) bool
	RefreshList() error
}

type fooAdBlocker struct {
	abpFilterURL   string
	resolvers      []string
	filter         map[string]struct{}
	filterHash     uint64
	refreshRequest chan chan error
}

func NewAdBlocker(abpFilterURL string,
	resolvers []*config.ServerConfig) AdBlocker {
	ab := &fooAdBlocker{
		abpFilterURL: abpFilterURL,
		resolvers:    make([]string, len(resolvers)),
		filter:       nil,
		filterHash:   0,
	}
	for i := 0; i < len(resolvers); i++ {
		ab.resolvers[i] = resolvers[i].String()
	}
	go ab.scheduleRefresh()
	if err := ab.RefreshList(); err != nil {
		panic(err.Error())
	}
	return ab
}

func (ab *fooAdBlocker) IsBlocked(dname string) bool {
	_, blocked := ab.filter[dname]
	return blocked
}

func (ab *fooAdBlocker) RefreshList() error {

}

func (ab *fooAdBlocker) processRefreshReq() {
	for {
		select {
		case refreshError := <-ab.refreshRequest:
			refreshError <- nil
		}
	}
}

func (ab *fooAdBlocker) doRefresh() error {
	var resp *http.Response
	var err error
	for _, r := range ab.resolvers {
		c := client.NewHTTPSClient(r)
		resp, err = c.Get(ab.abpFilterURL)
		c.CloseIdleConnections()
		if err != nil {
			continue
		}
		/* Request was made but application error was found */
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf(
				"unexpected HTTP status code on fetching list [%s]: %d",
				ab.abpFilterURL,
				resp.StatusCode,
			)
		}
		break
	}
	if err != nil {
		return err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return emptyStr, err
	}
	return AsString(b), nil
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

func (ab *fooAdBlocker) scheduleRefresh() {
}
