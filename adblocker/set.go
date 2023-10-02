package adblocker

type memberSet interface {
	Empty()
	Add(uint64)
	Contains(uint64) bool
}

func newBFSet(bitSize int, numHash int, suffix []byte) memberSet {
	return newBloomFilter(bitSize, numHash, suffix)
}
