package adblocker

import (
	"hash"
	"litedns/unsafeutil"
)

func writeStrHash(h hash.Hash64, s string) uint64 {
	_, _ = h.Write(unsafeutil.AsSlice(s))
	return h.Sum64()
}
