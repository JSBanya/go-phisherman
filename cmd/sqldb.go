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
	// hashtypes
	HASH_HTML  = 0
	HASH_IMAGE = 1
	HASH_EDGES = 2
)

func ConnectDB() {
	db, _ = sql.Open("sqlite3", DB_PATH)
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS hashes (subdomain VARCHAR(128), domain VARCHAR(128), path CARCHAR(128), hashtype INT, hash VARCHAR(128), safe INT)")
	statement.Exec()
}

func CloseDB() {
	db.Close()
}

// Stores hash for the domain
func InsertHashes(subdomain, domain, path, hash_html, hash_image, hash_edges string, safe int) {
	rows, _ := db.Query("SELECT hashtype, hash FROM hashes WHERE subdomain=? AND domain=? AND path=?", subdomain, domain, path)
	defer rows.Close()
	var t int
	var h string
	for rows.Next() {
		rows.Scan(&t, &h)
		if ((t == HASH_HTML) && (h == hash_html)) ||
			((t == HASH_IMAGE) && (h == hash_image)) ||
			((t == HASH_EDGES) && (h == hash_edges)) {
			return
		}
	}

	statement, _ := db.Prepare("INSERT INTO hashes (subdomain, domain, path, hashtype, hash, safe) VALUES (?, ?, ?, ?, ?, ?)")

	_, err := statement.Exec(subdomain, domain, path, HASH_HTML, hash_html, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_IMAGE, hash_image, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_EDGES, hash_edges, safe)
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

func HashMatch(domain, hash_html, hash_image, hash_edges string) (string, int, int) {
	rows, _ := db.Query("SELECT subdomain, domain, path, hashtype, hash FROM hashes WHERE domain<>?", domain)
	defer rows.Close()
	var sd, d, p, h string
	var t int
	for rows.Next() {
		rows.Scan(&sd, &d, &p, &t, &h)
		switch t {
		case HASH_HTML:
			if hash_html != "" {
				score, _ := ssdeep.Distance(h, hash_html)
				log.Printf("%sScore %s%s vs %s = %v%s", COLOR_ERROR, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_HTML {
					log.Printf("%sMATCH: %v%s", COLOR_ERROR, score, COLOR_RESET)
					return fmt.Sprintf("%s.%s/%s", sd, d, p), HASH_HTML, score
				}
			}
		case HASH_IMAGE:
			if hash_image != "" {
				score, _ := ssdeep.Distance(h, hash_image)
				log.Printf("%sScore %s%s vs %s = %v%s", COLOR_ERROR, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_IMAGE {
					log.Printf("%sMATCH: %v%s", COLOR_ERROR, score, COLOR_RESET)
					return fmt.Sprintf("%s.%s/%s", sd, d, p), HASH_IMAGE, score
				}
			}
		case HASH_EDGES:
			if hash_edges != "" {
				score, _ := ssdeep.Distance(h, hash_edges)
				log.Printf("%sScore %s%s vs %s = %v%s", COLOR_ERROR, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_EDGES {
					log.Printf("%sMATCH: %v%s", COLOR_ERROR, score, COLOR_RESET)
					return fmt.Sprintf("%s.%s/%s", sd, d, p), HASH_EDGES, score
				}
			}
		}
	}
	return "", 0, 0
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
