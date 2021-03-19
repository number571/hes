package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"sync"
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
CREATE TABLE IF NOT EXISTS emails (
	id INTEGER,
	recv VARCHAR(255),
	hash VARCHAR(255) UNIQUE,
	data TEXT,
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

func (db *DB) DelEmailsByDay(day int) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"DELETE FROM emails WHERE addtime < datetime('now', '-' | $1 | ' days')",
		day,
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
