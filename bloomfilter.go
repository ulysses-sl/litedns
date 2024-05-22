package main

type BloomFilter struct {
	size      uint32
	numHashes uint32
}

func NewBloomFilter() *BloomFilter {
	bf := BloomFilter{}
	return &bf
}

func (bf *BloomFilter) Contains(dname string) {
	strings.split
}
