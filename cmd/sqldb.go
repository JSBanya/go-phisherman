package main

import (
	"database/sql"
	"github.com/glaslos/ssdeep"
	_ "github.com/mattn/go-sqlite3"
	"log"
)

var db *sql.DB

const (
	DB_PATH   = "./data.db"
	THRESHOLD = 80
)

func ConnectDB() {
	db, _ = sql.Open("sqlite3", DB_PATH)
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS hashes (domain VARCHAR(128), hash VARCHAR(128), safe INT)")
	statement.Exec()
}

func CloseDB() {
	db.Close()
}

// Stores hash for the domain
func InsertHash(domain string, hash string, safe int) {
	statement, _ := db.Prepare("INSERT INTO hashes (domain, hash, safe) VALUES (?, ?, ?)")
	_, err := statement.Exec(domain, hash, safe)
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
	rows, _ := db.Query("SELECT domain, hash FROM hashes WHERE domain<>?", domain)
	var d, h string
	for rows.Next() {
		rows.Scan(&d, &h)
		score, _ := ssdeep.Distance(h, hash)
		if score >= THRESHOLD {
			rows.Close()
			return d
		}
	}
	rows.Close()
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
