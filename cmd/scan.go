package main

import (
	"fmt"
	"github.com/glaslos/ssdeep"
	"io/ioutil"
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

func detectPhishingHTTP(subdomain string, domain string, path string) (bool, error) {
	url := fmt.Sprintf("%s/%s", domain, path)
	if subdomain != "" {
		url = fmt.Sprintf("%s.%s", subdomain, url)
	}

	// Get the image of the page
	binaryImg, err := getImageFromUrl(url)
	if err != nil {
		log.Printf("wkhtmltoimage error: %s\n", err)
		// Error getting the image of the webpage
		// Try two more times before terminating the connection
		for i := 0; i < 2 || err != nil; i++ {
			binaryImg, err = getImageFromUrl(url)
		}

		if err != nil {
			// Unable to get webpage image
			return false, err
		}
	}

	if len(binaryImg) < 4096 {
		// SSDeep enforced a min length of 4096 bytes
		// It is unlikely that a phishing website will be smaller than this anyway
		cache[url] = false
		return false, nil
	}

	edges, err := getImageEdges(binaryImg)
	if err != nil {
		log.Printf("Image detection error: %s\n", err)
		return false, err
	}

	ioutil.WriteFile(fmt.Sprintf("%s%s.jpg", domain, path), edges, 0644) // Save image for debug purposes

	hash, err := ssdeep.FuzzyBytes(edges)
	if err != nil {
		return false, err
	}

	switch DomainStatus(domain) {
	case 0: // Domain not in db
		match := HashMatch(domain, hash)
		if match == "" {
			InsertHash(subdomain, domain, path, hash, 1)
			return false, nil
		} else {
			UpdateDomainStatus(domain, 0)
			InsertHash(subdomain, domain, path, hash, 0)

			cache[url] = true
			log.Printf("%s was detected as a new potential phishing site.", url)
			return true, nil
		}
	case 1: // Domain was previously marked as unsafe
		{
			cache[url] = true
			return true, nil
		}
	case 2: // Domain was previously marked as safe
		{
			if SiteExistsDB(subdomain, domain, path) {
				cache[url] = false
				return false, nil
			}
			match := HashMatch(domain, hash)
			if match == "" {
				InsertHash(subdomain, domain, path, hash, 1)
				return false, nil
			}
			UpdateDomainStatus(domain, 0)
			InsertHash(subdomain, domain, path, hash, 0)
			cache[url] = true
			log.Printf("%s was detected as a new potential phishing site.", url)
			return true, nil
		}
	}

	return false, nil
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
