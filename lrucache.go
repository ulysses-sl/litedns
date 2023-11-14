package main

import (
	"sync"
)

type cacheData[T any] struct {
	value T
	node  *dlNode
}

type dlNode struct {
	idx  int
	prev *dlNode
	next *dlNode
}

func (node *dlNode) extract() *dlNode {
	if node == nil {
		panic("Attempted to extract nil *dlNode")
	}
	if node.prev != nil {
		node.prev.next = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	}
	node.prev, node.next = nil, nil
	return node
}

func insertNodeAfter(orig, new *dlNode) {
	if orig == nil {
		panic("Attempted to insert a node after a nil *dlNode")
	}
	if new == nil {
		panic("Attempted to insert a nil *dlNode")
	}
	new.prev, new.next = orig, orig.next
	orig.next, orig.next.prev = new, new
}

type LRUCache[T any] struct {
	data    []cacheData[T]
	head    *dlNode
	unused  *dlNode
	MaxSize int
	size    int
	mutex   sync.Mutex
}

func NewLRUCache[T any](maxSize int) *LRUCache[T] {
	head := &dlNode{
		idx: -1,
	}
	c := &LRUCache[T]{
		data:    make([]cacheData[T], 0, maxSize),
		head:    head,
		unused:  nil,
		MaxSize: maxSize,
	}
	return c
}

func (c *LRUCache[T]) Add(x T) (int, bool, T) {
	var node *dlNode
	var overwrite bool
	var oldValue T
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if overwrite = len(c.data) == c.MaxSize; overwrite {
		node = c.head.prev.extract()
		oldValue = c.data[node.idx].value
		c.data[node.idx].value = x
	} else if c.unused != nil {
		node = c.unused
		c.unused = c.unused.next
		node.next = nil
		c.data[node.idx].value = x
		c.size++
	} else {
		node = &dlNode{idx: len(c.data)}
		c.data = append(c.data, cacheData[T]{value: x, node: node})
		c.size++
	}
	insertNodeAfter(c.head, node)
	return node.idx, overwrite, oldValue
}

func (c *LRUCache[T]) Get(i int) (T, bool) {
	var rv T
	var found bool
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if found = i >= 0 && i < len(c.data) && c.data[i].node != nil; found {
		rv = c.data[i].value
	}
	return rv, found
}

func (c *LRUCache[T]) Delete(i int) (T, bool) {
	var rv T
	var found bool
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if found = i >= 0 && i < len(c.data) && c.data[i].node != nil; found {
		rv = c.data[i].value
		node := c.data[i].node.extract()
		c.data[i].node = nil
		node.next = c.unused
		c.unused = node
		c.size--
	}
	return rv, found
}

func (c *LRUCache[T]) Purge(shouldDelete func(T) bool) []T {
	var purged []T
	c.mutex.Lock()
	defer c.mutex.Unlock()
	purged = make([]T, 0)
	for i := 0; i < len(c.data); i++ {
		if shouldDelete(c.data[i].value) {
			purged = append(purged, c.data[i].value)
			node := c.data[i].node.extract()
			c.data[i].node = nil
			node.next = c.unused
			c.unused = node
		}
	}
	c.size -= len(purged)
	return purged
}

func (c *LRUCache[T]) Flush() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.data = make([]cacheData[T], 0, c.MaxSize)
	c.unused = nil
	c.head.prev, c.head.next = c.head, c.head
	flushCount := c.size
	c.size = 0
	return flushCount
}

func (c *LRUCache[T]) CompactAndSort(iterate func(int, T)) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.unused = nil
	for i, curr := 0, c.head.next; curr != c.head; i, curr = i+1, curr.next {
		if curr.idx != i {
			c.data[i].value = c.data[curr.idx].value
			c.data[i].node = curr
			c.data[curr.idx].node = nil
			curr.idx = i
		}
		iterate(i, c.data[i].value)
	}
}
