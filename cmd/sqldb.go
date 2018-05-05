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
	HASH_HTML_SSDEEP   = 0
	HASH_IMAGE_SSDEEP  = 1
	HASH_EDGES_SSDEEP  = 2
	HASH_HEADER_SSDEEP = 3

	HASH_IMAGE_PHASH  = 4
	HASH_EDGES_PHASH  = 5
	HASH_HEADER_PHASH = 6
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
func InsertHashes(subdomain, domain, path, hash_html_ssdeep, hash_image_ssdeep, hash_edges_ssdeep, hash_header_ssdeep, hash_image_phash, hash_edges_phash, hash_header_phash string, safe int) {
	rows, _ := db.Query("SELECT hashtype, hash FROM hashes WHERE subdomain=? AND domain=? AND path=?", subdomain, domain, path)
	defer rows.Close()
	var t int
	var h string
	for rows.Next() {
		rows.Scan(&t, &h)
		if ((t == HASH_HTML_SSDEEP) && (h == hash_html_ssdeep)) ||
			((t == HASH_IMAGE_SSDEEP) && (h == hash_image_ssdeep)) ||
			((t == HASH_EDGES_SSDEEP) && (h == hash_edges_ssdeep)) ||
			((t == HASH_HEADER_SSDEEP) && (h == hash_header_ssdeep)) ||
			((t == HASH_IMAGE_PHASH) && (h == hash_image_phash)) ||
			((t == HASH_EDGES_PHASH) && (h == hash_edges_phash)) ||
			((t == HASH_HEADER_PHASH) && (h == hash_header_phash)) {
			return
		}
	}

	statement, _ := db.Prepare("INSERT INTO hashes (subdomain, domain, path, hashtype, hash, safe) VALUES (?, ?, ?, ?, ?, ?)")

	_, err := statement.Exec(subdomain, domain, path, HASH_HTML_SSDEEP, hash_html_ssdeep, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_IMAGE_SSDEEP, hash_image_ssdeep, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_EDGES_SSDEEP, hash_edges_ssdeep, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_HEADER_SSDEEP, hash_header_ssdeep, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_IMAGE_PHASH, hash_image_phash, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_EDGES_PHASH, hash_edges_phash, safe)
	if err != nil {
		log.Printf("Error: %v\n", err)
	}

	_, err = statement.Exec(subdomain, domain, path, HASH_HEADER_PHASH, hash_header_phash, safe)
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

func HashMatch(domain, hash_html_ssdeep, hash_image_ssdeep, hash_edges_ssdeep, hash_header_ssdeep, hash_image_phash, hash_edges_phash, hash_header_phash string) (string, string, int) {
	rows, _ := db.Query("SELECT subdomain, domain, path, hashtype, hash FROM hashes WHERE domain<>?", domain)
	defer rows.Close()
	var sd, d, p, h string
	var t int
	for rows.Next() {
		rows.Scan(&sd, &d, &p, &t, &h)
		switch t {
		case HASH_HTML_SSDEEP:
			if hash_html_ssdeep != "" {
				score, _ := ssdeep.Distance(h, hash_html_ssdeep)
				log.Printf("%sHTML Score %s/%s vs %s = %v%s", COLOR_SCAN, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_HTML_SSDEEP {
					return fmt.Sprintf("%s.%s/%s", sd, d, p), "HTML_SSDEEP", score
				}
			}
		case HASH_IMAGE_SSDEEP:
			if hash_image_ssdeep != "" {
				score, _ := ssdeep.Distance(h, hash_image_ssdeep)
				log.Printf("%sImage Score %s/%s vs %s = %v%s", COLOR_SCAN, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_IMAGE_SSDEEP {
					return fmt.Sprintf("%s.%s/%s", sd, d, p), "IMAGE_SSDEEP", score
				}
			}
		case HASH_EDGES_SSDEEP:
			if hash_edges_ssdeep != "" {
				score, _ := ssdeep.Distance(h, hash_edges_ssdeep)
				log.Printf("%sEdge Score %s/%s vs %s = %v%s", COLOR_SCAN, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_EDGES_SSDEEP {
					return fmt.Sprintf("%s.%s/%s", sd, d, p), "EDGE_SSDEEP", score
				}
			}
		case HASH_HEADER_SSDEEP:
			if hash_header_ssdeep != "" {
				score, _ := ssdeep.Distance(h, hash_header_ssdeep)
				log.Printf("%sHead Score %s/%s vs %s = %v%s", COLOR_SCAN, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_HEADER_SSDEEP {
					return fmt.Sprintf("%s.%s/%s", sd, d, p), "HEAD_SSDEEP", score
				}
			}
		case HASH_IMAGE_PHASH:
			if hash_image_phash != "" {
				score, _ := ssdeep.Distance(h, hash_image_phash)
				log.Printf("%sHead Score %s/%s vs %s = %v%s", COLOR_SCAN, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_IMAGE_PHASH {
					return fmt.Sprintf("%s.%s/%s", sd, d, p), "HEAD_PHASH", score
				}
			}
		case HASH_EDGES_PHASH:
			if hash_edges_phash != "" {
				score, _ := ssdeep.Distance(h, hash_edges_phash)
				log.Printf("%sHead Score %s/%s vs %s = %v%s", COLOR_SCAN, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_EDGES_PHASH {
					return fmt.Sprintf("%s.%s/%s", sd, d, p), "HEAD_PHASH", score
				}
			}
		case HASH_HEADER_PHASH:
			if hash_header_phash != "" {
				score, _ := ssdeep.Distance(h, hash_header_phash)
				log.Printf("%sHead Score %s/%s vs %s = %v%s", COLOR_SCAN, d, p, domain, score, COLOR_RESET)
				if score >= THRESHOLD_HEADER_PHASH {
					return fmt.Sprintf("%s.%s/%s", sd, d, p), "HEAD_PHASH", score
				}
			}
		}
	}
	return "", "", 0
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
