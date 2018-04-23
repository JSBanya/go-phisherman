package main

import (
	"bytes"
	"compress/gzip"
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
	//

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

	// Check to see if the site is cached
	host := strings.TrimSpace(req.URL.Hostname())
	isPhishing, isCached := cache[host]

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

		isPhishing, err = detectPhishingHTTP(host, decompressedContent)
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