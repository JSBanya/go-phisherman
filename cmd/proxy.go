package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
)

func proxyConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		proxyHTTPs(w, r)
	} else {
		proxyHTTP(w, r)
	}
}

func proxyHTTPs(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logError(fmt.Sprintf("%s", r))
		}
	}()

	// Establish connection
	dest_conn, err := tls.Dial("tcp", r.Host, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("Error: %s", err)
		return
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Error: %s", err)
		return
	}

	// Enable encryption/decryption of TLS data to/from client
	config := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Here is where we would hook into the SQLite database to retrieve certs
			//log.Printf("Grabbing certificate for %s\n", hello.ServerName)
			// Run cert generation script
			cmd := exec.Command("./gencrt.sh", hello.ServerName)
			cmd.Run()

			crt := fmt.Sprintf("certs/%s.crt", hello.ServerName)
			key := fmt.Sprintf("certs/%s.key", hello.ServerName)
			cert, err := tls.LoadX509KeyPair(crt, key)
			if err != nil {
				log.Printf("Fatal certificate error for %s: %s", hello.ServerName, err)
				return nil, err
			}
			return &cert, nil
		},
	}
	client_tls_conn := tls.Server(client_conn, config)

	defer dest_conn.Close()
	defer client_conn.Close()
	defer client_tls_conn.Close()

	// Intercept and extract header data
	buffer := make([]byte, 1024)
	n, err := client_tls_conn.Read(buffer)
	if err != nil {
		return
	}

	requestLine := regexp.MustCompile(`^\S+\s\S+\sHTTP\/.+`) // GET /tutorials/other/top-20-mysql-best-practices/ HTTP/1.1
	hostLine := regexp.MustCompile(`Host:\s.+`)              // Host: net.tutsplus.com

	reqlines := strings.Split(requestLine.FindString(string(buffer)), " ")
	path := ""
	if len(reqlines) == 3 {
		path = reqlines[1]
	}

	host := strings.Trim(strings.TrimSpace(strings.TrimPrefix(hostLine.FindString(string(buffer)), "Host: ")), "\n")
	host = strings.Trim(host, "/")
	path = strings.Trim(strings.TrimSpace(path), "/")

	pathSplit := strings.Split(path, "?")
	if len(pathSplit) > 1 {
		path = pathSplit[0]
	}

	url := fmt.Sprintf("%s/%s", host, path)

	// Get the HTML from the site if it was a GET request
	var isPhishing bool
	if !cache.IsCached(url) {
		if reqlines[0] == "GET" {
			isPhishing, err = detectPhishing("https://", host, path)
			if err != nil {
				log.Printf("HTTPs Detect Phishing Error: %s", err)
				return
			}
		}
	} else {
		isPhishing = cache.IsPhishing(url)
	}

	if isPhishing {
		// Phishing attempt detected
		logDetection(url)
		warning := bytes.NewBuffer([]byte(fmt.Sprintf(WARNING_PAGE, url)))
		io.Copy(client_tls_conn, warning)
		return
	}

	// Forward the read bytes
	io.Copy(dest_conn, bytes.NewBuffer(buffer[0:n]))

	// Forward communication in both directions
	zero := make([]byte, 0)
	if _, err = client_tls_conn.Read(zero); err == nil {
		// Only continue copying from client->dest if the connection is not already closed
		go io.Copy(dest_conn, client_tls_conn)
	}

	if _, err = dest_conn.Read(zero); err == nil {
		// Only copy from dest->client if the connection is not already closed
		io.Copy(client_tls_conn, dest_conn)
	}
}

func proxyHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logError(fmt.Sprintf("%s", r))
		}
	}()

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	domain := strings.Trim(req.URL.Hostname(), "/")
	path := strings.Trim(strings.TrimSpace(req.URL.Path), "/")
	pathSplit := strings.Split(path, "?")
	if len(pathSplit) > 1 {
		path = pathSplit[0]
	}

	url := fmt.Sprintf("%s/%s", domain, path)

	var isPhishing bool

	// If not cached, scan the page (even if it exists in the database)
	if !cache.IsCached(url) {
		contentType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-type"), ";")[0])
		if contentType == "text/html" || contentType == "text/plain" || contentType == "" {
			isPhishing, err = detectPhishing("http://", domain, path)
			if err != nil {
				log.Printf("Error: %s\n", err)
				http.Error(w, "Phisherman: Unable to process webpage", http.StatusInternalServerError)
				return
			}
		}
	} else {
		isPhishing = cache.IsPhishing(url)
	}

	if isPhishing {
		// Phishing attempt detected
		logDetection(url)
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
