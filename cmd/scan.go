package main

import (
	"fmt"
	"github.com/glaslos/ssdeep"
	"log"
	"strings"
	"time"
)

const CACHE_CLEAR_INTERVAL = 60 * 60 * 12 // Seconds

var cache map[string]bool

func scannerInit() {
	cache = make(map[string]bool)
	go clearCache()
}

func detectPhishingHTTPs(host string) bool {
	// Check to see if the site is cached
	host = strings.TrimSpace(host)
	if cachedVal, ok := cache[host]; ok {
		return cachedVal
	}

	// Host not cached

	return false
}

func detectPhishingHTTP(domain string, body []byte) (bool, error) {
	if len(body) < 4096 {
		// SSDeep enforced a min length of 4096 bytes
		// It is unlikely that a phishing website will be smaller than this
		return false, nil
	}

	hash, err := ssdeep.FuzzyBytes(body)
	if err != nil {
		return false, err
	}
	fmt.Printf("hash: %s\n", hash)

	switch DomainStatus(domain) {
	case 0: // Domain not in db
		match := HashMatch(domain, hash)
		if match == "" {
			InsertHash(domain, hash, 1)
			return false, nil
		} else {
			fmt.Printf("Fuzzy hash collision found:\n")
			fmt.Printf("%s matches %s\n", domain, match)

			InsertHash(domain, hash, 0)
			return true, nil
		}
	case 1: // Domain was previously marked as unsafe
		UpdateDomainStatus(domain, 0)
		return true, nil
	case 2: // Domain was previously marked as safe
		UpdateDomainStatus(domain, 1)
		return false, nil
	}
	return false, nil
}

// Sends a GET request to the given host over HTTPs
// Returns the body of the request as a string
func probeHTTPs(host string) string {

	return ""
}

func clearCache() {
	for {
		time.Sleep(CACHE_CLEAR_INTERVAL * time.Second)
		log.Printf("Clearing cache...")
		for k, _ := range cache {
			delete(cache, k)
		}
	}
}
