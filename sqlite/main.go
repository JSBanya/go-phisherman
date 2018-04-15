package main

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

const DB_PATH = "./data.db"

func ConnectDB() {
	db, _ = sql.Open("sqlite3", DB_PATH)
	statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS hashes (url VARCHAR(128) PRIMARY KEY, hash VARCHAR(128))")
	statement.Exec()
}

func CloseDB() {
	db.Close()
}

func InsertHash(url string, hash string) {
	statement, _ := db.Prepare("INSERT INTO hashes (url, hash) VALUES (?, ?)")
	statement.Exec(url, hash)
}

func UpdateHash(url string, hash string) {
	statement, _ := db.Prepare("UPDATE hashes SET hash=? WHERE url=?")
	statement.Exec(hash, url)
}

func GetHash(url string) string {
	rows, _ := db.Query("SELECT hash FROM hashes WHERE url=?", url)
	var hash string
	rows.Next()
	rows.Scan(&hash)
	rows.Close()
	return hash
}

func main() {
	ConnectDB()
	defer CloseDB()
	InsertHash("google.com", "0123")
	InsertHash("facebook.com", "4567")
	hash := GetHash("google.com")
	fmt.Printf("%s\n", hash)
	hash = GetHash("facebook.com")
	fmt.Printf("%s\n", hash)

	UpdateHash("google.com", "9876")
	hash = GetHash("google.com")
	fmt.Printf("%s\n", hash)
}
