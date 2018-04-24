package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func proxyConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		proxyHTTPs(w, r)
	} else {
		proxyHTTP(w, r)
	}
}

func proxyHTTPs(w http.ResponseWriter, r *http.Request) {
	// Establish connection
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("%s", err)
		http.Error(w, "", http.StatusServiceUnavailable)
	}

	// Forward communication in both directions
	go io.Copy(dest_conn, client_conn)
	io.Copy(client_conn, dest_conn)

	dest_conn.Close()
	client_conn.Close()
}

func proxyHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Extract the body
	rawContents, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Printf("%s\n", err)
		http.Error(w, "Phisherman: Error processing request", http.StatusInternalServerError)
		return
	}
	original := ioutil.NopCloser(bytes.NewBuffer(rawContents))

	// Split the URL into subdomain, domain, and path
	subdomainList := strings.Split(req.URL.Hostname(), ".")
	if len(subdomainList) < 2 {
		http.Error(w, "Phisherman: Unprocessable domain name.", http.StatusInternalServerError)
		return
	}

	domain := fmt.Sprintf("%s.%s", subdomainList[len(subdomainList)-2], subdomainList[len(subdomainList)-1])
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
	path := strings.Trim(strings.TrimSpace(req.URL.Path), "/")

	// Check cached status
	url := fmt.Sprintf("%s%s", domain, path)
	isPhishing, isCached := cache[url]

	// If the response contains HTML and is not cached, scan it
	contentType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-type"), ";")[0])
	if contentType == "text/html" && !isCached {
		buffer := bytes.NewBuffer(rawContents)

		// Handle encoding
		var reader io.Reader
		switch resp.Header.Get("Content-Encoding") {
		case "gzip":
			{
				reader, err = gzip.NewReader(buffer)
				if err != nil {
					log.Printf("%s\n", err)
					http.Error(w, "Phisherman: Error handling gzipped request", http.StatusInternalServerError)
					return
				}
			}
		default:
			reader = buffer
		}

		decompressedContent, err := ioutil.ReadAll(reader)
		if err != nil {
			log.Printf("%s\n", err)
			http.Error(w, "Phisherman: Error decommpressing request", http.StatusInternalServerError)
			return
		}

		isPhishing, err = detectPhishingHTTP(subdomain, domain, path, decompressedContent)
		if err != nil {
			log.Printf("%s\n", err)
			http.Error(w, "Phisherman: Error while scanning webpage", http.StatusInternalServerError)
			return
		}
	}

	if isPhishing {
		// Phishing attempt detected
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, original)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
