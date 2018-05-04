package main

import (
	"fmt"
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

func (c *Cache) GetSize() int {
	c.mux.Lock()
	defer c.mux.Unlock()

	return len(c.content)
}

func (c *Cache) GetNumPhishing() int {
	c.mux.Lock()
	defer c.mux.Unlock()

	num := 0
	for _, v := range c.content {
		if v == true {
			num++
		}
	}

	return num
}

func (c *Cache) Print() {
	c.mux.Lock()
	defer c.mux.Unlock()

	for k, v := range c.content {
		fmt.Printf("%v : %v\n", k, v)
	}
}

func (c *Cache) Clear() {
	c.mux.Lock()
	defer c.mux.Unlock()

	for k, _ := range c.content {
		delete(c.content, k)
	}
}
