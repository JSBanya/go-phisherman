package main

import (
	"database/sql"
	"fmt"
	"github.com/glaslos/ssdeep"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

const (
	DB_PATH   = "./data.db"
	THRESHOLD = 0
)

func ConnectDB() {
	db, _ = sql.Open("sqlite3", DB_PATH)
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS hashes (subdomain VARCHAR(128), domain VARCHAR(128), path VARCHAR(128), hash VARCHAR(128), PRIMARY KEY (subdomain, domain, path))")
	statement.Exec()
}

func CloseDB() {
	db.Close()
}

// Stores hash for the site http(s)://${subdomain}.${domain}/${path}
func InsertHash(subdomain string, domain string, path string, hash string) {
	statement, _ := db.Prepare("INSERT INTO hashes (subdomain, domain, path, hash) VALUES (?, ?, ?, ?)")
	_, err := statement.Exec(subdomain, domain, path, hash)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func UpdateHash(subdomain string, domain string, path string, hash string) {
	statement, _ := db.Prepare("UPDATE hashes SET hash=? WHERE subdomain=? AND domain=? AND path=?")
	statement.Exec(hash, subdomain, domain, path)
}

func GetHashesForDomain(domain string) []string {
	rows, _ := db.Query("SELECT hash FROM hashes WHERE domain=?", domain)
	var hash string
	var hashes []string
	for rows.Next() {
		rows.Scan(&hash)
		hashes = append(hashes, hash)
	}
	return hashes
}

func GetHashesForSubdomain(subdomain string, domain string) []string {
	rows, _ := db.Query("SELECT hash FROM hashes WHERE subdomain=? AND domain=?", subdomain, domain)
	var hash string
	var hashes []string
	for rows.Next() {
		rows.Scan(&hash)
		hashes = append(hashes, hash)
	}
	return hashes
}

func GetHashForPath(subdomain string, domain string, path string) string {
	rows, _ := db.Query("SELECT hash FROM hashes WHERE subdomain=? AND domain=? AND path=?", subdomain, domain, path)
	var hash string
	rows.Next()
	rows.Scan(&hash)
	rows.Close()
	return hash
}

// This function needs to be optimized -- it rechecks hashes already checked in previous group
func HashMatchFound(subdomain string, domain string, path string, hash string) bool {
	// // First try the most specific search (subdomain, domain, and path)
	// h := GetHashForPath(subdomain, domain, path)
	// score, _ := ssdeep.Distance(h, hash)
	// if score > THRESHOLD {
	// 	return true
	// }

	// // Next try searching without path (subdomain, domain)
	// hlist := GetHashesForSubdomain(subdomain, domain)
	// for _, elem := range hlist {
	// 	score, _ := ssdeep.Distance(elem, hash)
	// 	if score > THRESHOLD {
	// 		return true
	// 	}
	// }

	// Finally search the entire domain
	hlist := GetHashesForDomain(domain)
	for _, elem := range hlist {
		score, _ := ssdeep.Distance(elem, hash)
		if score > THRESHOLD {
			return true
		}
	}

	return false
}

func main() {
	ConnectDB()
	defer CloseDB()

	InsertHash("www", "google.com", "somepath", "0123")
	InsertHash("mail", "google.com", "inbox", "4567")
	InsertHash("mail", "google.com", "outbox", "8901")
	InsertHash("www", "facebook.com", "someotherpath", "2345")

	h := GetHashForPath("mail", "google.com", "inbox")
	fmt.Printf("mail.google.com/inbox: %v\n", h)

	hlist := GetHashesForSubdomain("mail", "google.com")
	fmt.Printf("mail.google.com: %v\n", hlist)

	hlist = GetHashesForDomain("google.com")
	fmt.Printf("google.com: %v\n", hlist)

	match := HashMatchFound("mail", "google.com", "inbox", "4567")
	fmt.Printf("Match: %v\n", match)
}
