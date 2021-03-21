package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"strings"
	"sync"
	"time"
)

type DB struct {
	ptr *sql.DB
	mtx sync.Mutex
}

func NewDB(filename string) *DB {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil
	}
	_, err = db.Exec(`
PRAGMA secure_delete=ON;
CREATE TABLE IF NOT EXISTS connects (
	id      INTEGER,
	host    VARCHAR(255) UNIQUE,
	PRIMARY KEY(id)
);
CREATE TABLE IF NOT EXISTS emails (
	id      INTEGER,
	recv    VARCHAR(255),
	hash    VARCHAR(255) UNIQUE,
	data    TEXT,
	addtime DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(id)
);
`)
	if err != nil {
		return nil
	}
	return &DB{
		ptr: db,
	}
}

func (db *DB) SetEmail(recv, hash, data string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"INSERT INTO emails (recv, hash, data) VALUES ($1, $2, $3)",
		recv,
		hash,
		data,
	)
	return err
}

func (db *DB) GetEmail(id int, recv string) string {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var data string
	row := db.ptr.QueryRow(
		"SELECT data FROM emails WHERE recv=$1 ORDER BY id LIMIT 1 OFFSET $2",
		recv,
		id-1,
	)
	row.Scan(&data)
	return data
}

func (db *DB) DelEmailsByTime(t time.Duration) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"DELETE FROM emails WHERE addtime < datetime('now', '-' || $1 || ' seconds')",
		uint64(t)/1000000000, // seconds
	)
	return err
}

func (db *DB) Size(recv string) int {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var data int
	row := db.ptr.QueryRow(
		"SELECT COUNT(*) FROM emails WHERE recv=$1",
		recv,
	)
	row.Scan(&data)
	return data
}

func (db *DB) GetConns() []string {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		conn     string
		connects []string
	)
	rows, err := db.ptr.Query(
		"SELECT host FROM connects",
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(
			&conn,
		)
		if err != nil {
			break
		}
		connects = append(connects, conn)
	}
	return connects
}

func (db *DB) SetConn(host string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	host = strings.TrimSpace(host)
	if db.connExist(host) {
		return fmt.Errorf("conn already exist")
	}
	_, err := db.ptr.Exec(
		"INSERT INTO connects (host) VALUES ($1)",
		host,
	)
	return err
}

func (db *DB) DelConn(host string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	host = strings.TrimSpace(host)
	_, err := db.ptr.Exec(
		"DELETE FROM connects WHERE host=$1",
		host,
	)
	return err
}

func (db *DB) connExist(host string) bool {
	var (
		hoste string
	)
	row := db.ptr.QueryRow(
		"SELECT host FROM connects WHERE host=$1",
		host,
	)
	row.Scan(&hoste)
	return hoste != ""
}
