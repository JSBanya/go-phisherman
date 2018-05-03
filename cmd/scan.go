package main

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"github.com/glaslos/ssdeep"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	THRESHOLD_HTML  = 25
	THRESHOLD_IMAGE = 25
	THRESHOLD_EDGES = 25

	CACHE_CLEAR_INTERVAL = 60 * 60 * 24 // Seconds
	CACHE_CLEAR_SIZE     = 10000        // Entries

	COLOR_DETECTED = "\u001b[31m\u001b[1m"
	COLOR_ERROR    = "\u001b[33m"
	COLOR_RESET    = "\u001b[0m"
)

type Match struct {
	IsPhishing bool
	URL        string
	HashType   string
	Score      int
}

var cache *Cache

// Detects phishing for the given domain and path
// The domain should contain all subdomains (parsing will be performed internally)
// Path and domain should both be trimmed of '/' by the caller
// The result of this function may impact the status of the cache and the database
// Returns true if the site is detected as phishing, and false otherwise.
func detectPhishing(proto string, domain string, path string) (Match, error) {
	var match Match

	// Split domain into subdomain
	subdomainList := strings.Split(domain, ".")
	if len(subdomainList) < 2 {
		return match, fmt.Errorf("Phisherman: Unprocessable domain name: %s.", domain)
	}

	domain = fmt.Sprintf("%s.%s", subdomainList[len(subdomainList)-2], subdomainList[len(subdomainList)-1])
	subdomainList = subdomainList[0 : len(subdomainList)-2] // Trim whatever is not included in the domain

	if tldlist[domain] {
		// Last two segments are a top level domain (i.e. co.uk)
		// Append the previous segment if it exists
		if len(subdomainList) > 0 {
			domain = fmt.Sprintf("%s.%s", subdomainList[len(subdomainList)-1], domain)
			subdomainList = subdomainList[0 : len(subdomainList)-1]
		}
	}

	subdomain := strings.Join(subdomainList, ".")

	url := fmt.Sprintf("%s/%s", domain, path)
	if subdomain != "" {
		url = fmt.Sprintf("%s.%s", subdomain, url)
	}

	// Get the HTML from the page
	html, err := fetchHTML(fmt.Sprintf("%s%s", proto, url))
	if err != nil && err.Error() == "Non-HTML content" {
		//log.Printf("Non-HTML content for %s\n", url)
		cache.SetValue(url, false)
		return match, nil
	} else if err != nil {
		// Note that we do not return nil in this case
		return match, err
	}

	if len(html) < 4096 {
		// SSDeep enforced a min length of 4096 bytes
		// It is unlikely that a phishing website will be smaller than this anyway
		//log.Printf("HTML too small to process for %s\n", url)
		cache.SetValue(url, false)
		return match, nil
	}

	// Get the image of the page
	binaryImg, err := getImageFromURL(fmt.Sprintf("%s%s", proto, url))
	if err != nil {
		return match, fmt.Errorf("ImageFromURL error: %s", err)
	}

	edges, err := getImageEdges(binaryImg)
	if err != nil {
		return match, fmt.Errorf("GetImageEdges error: %s", err)
	}

	binaryPixels, _ := imageToPixels(binaryImg)
	edgesPixels, _ := imageToPixels(edges)

	//ioutil.WriteFile(fmt.Sprintf("%s.jpg", strings.Replace(url, "/", "", -1)), head, 0644) // Save image for debug purposes

	hash_html, err := ssdeep.FuzzyBytes(html)
	if err != nil {
		hash_html = ""
		log.Printf("Error hashing html: %s\n", err)
	}

	hash_image, err := ssdeep.FuzzyBytes(binaryPixels)
	if err != nil {
		hash_image = ""
		log.Printf("Error hashing image: %s\n", err)
	}

	hash_edges, err := ssdeep.FuzzyBytes(edgesPixels)
	if err != nil {
		hash_edges = ""
		log.Printf("Error hashing edges: %s\n", err)
	}

	switch DomainStatus(domain) {
	case 0: // Domain not in db
		url, hashtype, score := HashMatch(domain, hash_html, hash_image, hash_edges)
		if url == "" {
			InsertHashes(subdomain, domain, path, hash_html, hash_image, hash_edges, 1)
			return match, nil
		} else {
			UpdateDomainStatus(domain, 0)
			InsertHashes(subdomain, domain, path, hash_html, hash_image, hash_edges, 0)

			cache.SetValue(url, true)
			match = Match{
				IsPhishing: true,
				URL:        url,
				HashType:   hashtype,
				Score:      score,
			}
			return match, nil
		}
	case 1: // Domain was previously marked as unsafe
		{
			cache.SetValue(url, true)
			match = Match{
				IsPhishing: true,
				URL:        "(unknown)",
				HashType:   "UNKNOWN",
				Score:      -1,
			}
			return match, nil
		}
	case 2: // Domain was previously marked as safe
		{
			if SiteExistsDB(subdomain, domain, path) {
				cache.SetValue(url, false)
				return match, nil
			}
			url, hashtype, score := HashMatch(domain, hash_html, hash_image, hash_edges)
			if url == "" {
				InsertHashes(subdomain, domain, path, hash_html, hash_image, hash_edges, 1)
				return match, nil
			}
			UpdateDomainStatus(domain, 0)
			InsertHashes(subdomain, domain, path, hash_html, hash_image, hash_edges, 0)
			cache.SetValue(url, true)
			match = Match{
				IsPhishing: true,
				URL:        url,
				HashType:   hashtype,
				Score:      score,
			}
			return match, nil
		}
	}

	return match, nil
}

func fetchHTML(url string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 30,
	}
	response, err := client.Get(url)
	if err != nil {
		return []byte{}, err
	}
	defer response.Body.Close()

	contentType := strings.TrimSpace(strings.Split(response.Header.Get("Content-type"), ";")[0])
	if contentType != "text/html" && contentType != "text/plain" && contentType != "" {
		return []byte{}, fmt.Errorf("Non-HTML content")
	}

	// Handle encoding
	var reader io.Reader
	switch response.Header.Get("Content-Encoding") {
	case "gzip":
		{
			reader, err = gzip.NewReader(response.Body)
			if err != nil {
				return []byte{}, err
			}
		}
	default:
		reader = response.Body
	}

	body, err := ioutil.ReadAll(reader)
	if err != nil {
		return []byte{}, err
	}

	detectedType := strings.TrimSpace(strings.Split(http.DetectContentType(body), ";")[0])
	//log.Printf("Content-Type for %s is %s\n", url, detectedType)
	if detectedType != "text/html" {
		return []byte{}, fmt.Errorf("Non-HTML content")
	}

	return body, nil
}

func logDetection(url string) {
	log.Printf("%s%s was detected as a potential phishing site.%s", COLOR_DETECTED, url, COLOR_RESET)
}

func logError(err string) {
	log.Printf("%s%s%s", COLOR_ERROR, err, COLOR_RESET)
}

// Clears the cache every set interval
func clearCacheOnInterval() {
	for {
		time.Sleep(CACHE_CLEAR_INTERVAL * time.Second)
		log.Printf("Clearing cache (interval)...")
		cache.Clear()
	}
}

// Clears the cache if the cache grows to be greater than a predefined size
func clearCacheOnSize() {
	for {
		time.Sleep(10 * time.Second)
		if cache.GetSize() > CACHE_CLEAR_SIZE {
			log.Printf("Clearing cache (size)...")
			cache.Clear()
		}
	}
}
