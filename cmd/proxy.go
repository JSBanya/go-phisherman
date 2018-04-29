package main

import (
	"bytes"
	"fmt"
	"io"
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

	url := fmt.Sprintf("%s/%s", domain, path)
	if subdomain != "" {
		url = fmt.Sprintf("%s.%s", subdomain, url)
	}

	// Check cached status
	isPhishing, isCached := cache[url]

	// If not cached, scan the page (even if it exists in the database)
	if !isCached {
		contentType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-type"), ";")[0])
		if contentType == "text/html" || contentType == "text/plain" || contentType == "" {
			isPhishing, err = detectPhishingHTTP(subdomain, domain, path)
			if err != nil {
				log.Printf("Error: %s\n", err)
				http.Error(w, "Phisherman: Unable to process webpage", http.StatusInternalServerError)
				return
			}
		}
	}

	if isPhishing {
		// Phishing attempt detected
		warning := bytes.NewBuffer([]byte(fmt.Sprintf(WARNING_PAGE, url)))
		w.Header().Set("Content-type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		io.Copy(w, warning)
		return
	}

	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
