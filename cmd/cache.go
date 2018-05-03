package main

import (
	"sync"
)

type Cache struct {
	content map[string]bool
	mux     sync.Mutex
}

func CreateCache() *Cache {
	c := Cache{}
	c.content = make(map[string]bool)

	return &c
}

func (c *Cache) IsCached(url string) bool {
	c.mux.Lock()
	defer c.mux.Unlock()

	_, s := c.content[url]
	return s
}

func (c *Cache) IsPhishing(url string) bool {
	c.mux.Lock()
	defer c.mux.Unlock()

	s, _ := c.content[url]
	return s
}

func (c *Cache) SetValue(url string, value bool) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.content[url] = value
}

func (c *Cache) Clear() {
	c.mux.Lock()
	defer c.mux.Unlock()

	for k, _ := range c.content {
		delete(c.content, k)
	}
}
