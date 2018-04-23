package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

var port string = "52078"

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
