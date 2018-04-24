package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

var publicSufficList string = "public_suffix_list.dat"
var port string = "52078"

var tldlist map[string]bool

func main() {
	if len(os.Args) > 2 {
		usage()
		os.Exit(1)
	} else if len(os.Args) == 2 {
		port = os.Args[1]
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           http.HandlerFunc(proxyConnection),
		ReadHeaderTimeout: 600 * time.Millisecond,                                       // Read timeout
		WriteTimeout:      600 * time.Millisecond,                                       // Write timeout
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // Disable HTTP/2.0 support
	}

	// Load public suffic list
	tldlist = make(map[string]bool)
	loadPublicSuffixList(publicSufficList)

	// Start the serevr
	log.Printf("Starting Phisherman on port %s.", port)

	scannerInit()
	ConnectDB()
	defer CloseDB()

	log.Fatal(server.ListenAndServe())
}

func usage() {
	fmt.Printf("phisherman [port]\n")
	fmt.Printf("Starts the phisherman proxy server on the provided port (default: 52078).\n")
	fmt.Printf("Example: phisherman 8080\n")
}

func loadPublicSuffixList(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) >= 2 && line[0:2] != "//" {
			// Only lines that are not comments
			tldlist[line] = true
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	log.Printf("Loaded %d top level domains from %s\n", len(tldlist), filename)
}
