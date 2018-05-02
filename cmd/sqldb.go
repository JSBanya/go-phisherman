package main

import (
	"database/sql"
	"fmt"
	"github.com/glaslos/ssdeep"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

var db *sql.DB

const (
	DB_PATH = "./data.db"
)

func ConnectDB() {
	db, _ = sql.Open("sqlite3", DB_PATH)
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS hashes (subdomain VARCHAR(128), domain VARCHAR(128), path CARCHAR(128), hash VARCHAR(128), safe INT)")
	statement.Exec()
}

func CloseDB() {
	db.Close()
}

// Stores hash for the domain
func InsertHash(subdomain string, domain string, path string, hash string, safe int) {
	rows, _ := db.Query("SELECT hash FROM hashes WHERE subdomain=? AND domain=? AND path=?", subdomain, domain, path)
	defer rows.Close()
	var h string
	for rows.Next() {
		rows.Scan(&h)
		if h == hash {
			return
		}
	}

	statement, _ := db.Prepare("INSERT INTO hashes (subdomain, domain, path, hash, safe) VALUES (?, ?, ?, ?, ?)")
	_, err := statement.Exec(subdomain, domain, path, hash, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}
}

func UpdateDomainStatus(domain string, safe int) {
	statement, _ := db.Prepare("UPDATE hashes SET safe=? WHERE domain=?")
	_, err := statement.Exec(safe, domain)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}
}

func HashMatch(domain string, hash string) string {
	rows, _ := db.Query("SELECT subdomain, domain, path, hash FROM hashes WHERE domain<>?", domain)
	defer rows.Close()
	var sd, d, p, h string
	for rows.Next() {
		rows.Scan(&sd, &d, &p, &h)
		score, _ := ssdeep.Distance(h, hash)
		if score >= THRESHOLD {
			return fmt.Sprintf("%s.%s/%s", sd, d, p)
		}
	}
	return ""
}

// Returns 0 if domain not in db, 1 if marked as unsafe, and 2 if marked as safe
func DomainStatus(domain string) int {
	rows, _ := db.Query("SELECT safe FROM hashes WHERE domain=?", domain)
	defer rows.Close()
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

func SiteStatus(subdomain string, domain string, path string) int {
	rows, _ := db.Query("SELECT safe from hashes WHERE subdomain=? AND domain=? AND path=?", subdomain, domain, path)
	defer rows.Close()
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

func SiteExistsDB(subdomain string, domain string, path string) bool {
	rows, err := db.Query("SELECT * FROM hashes WHERE subdomain=? AND domain=? AND path=?", subdomain, domain, path)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return false
	}
	defer rows.Close()
	for rows.Next() {
		return true
	}
	return false
}
