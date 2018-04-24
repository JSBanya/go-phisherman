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
	THRESHOLD = 80
)

func ConnectDB() {
	db, _ = sql.Open("sqlite3", DB_PATH)
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS hashes (subdomain VARCHAR(128), domain VARCHAR(128), path VARCHAR(128), hash VARCHAR(128), safe INT, PRIMARY KEY (subdomain, domain, path))")
	statement.Exec()
}

func CloseDB() {
	db.Close()
}

// Stores hash for the site http(s)://${subdomain}.${domain}/${path}
func InsertHash(subdomain string, domain string, path string, hash string, safe int) {
	statement, _ := db.Prepare("INSERT INTO hashes (subdomain, domain, path, hash, safe) VALUES (?, ?, ?, ?, ?)")
	_, err := statement.Exec(subdomain, domain, path, hash, safe)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func UpdateHash(subdomain string, domain string, path string, hash string, safe int) {
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

func HashMatch(domain string, hash string) string {
	rows, _ := db.Query("SELECT subdomain, domain, path, hash FROM hashes WHERE domain<>?", domain)
	var sd, d, p, h string
	for rows.Next() {
		rows.Scan(&sd, &d, &p, &h)
		score, _ := ssdeep.Distance(h, hash)
		if score >= THRESHOLD {
			rows.Close()
			return fmt.Sprintf("%s.%s/%s", sd, d, p)
		}
	}
	rows.Close()
	return ""
}

// Returns 0 if domain not in db, 1 if marked as unsafe, and 2 if marked as safe
func DomainStatus(domain string) int {
	rows, _ := db.Query("SELEC safe FROM hashes WHERE domain=?", domain)
	var safe int
	for rows.Next() {
		rows.Scan(&safe)
		if safe == 0 {
			return 1
		}
		return 2
	}
	return 0
}

/*func main() {
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
}*/
