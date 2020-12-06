package main

import (
	"sync"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	ptr *sql.DB
	mtx sync.Mutex
}

func DBInit(filename string) *DB {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS emails (
	id INTEGER,
	sender VARCHAR(255),
	receiver VARCHAR(255),
	hash VARCHAR(255) UNIQUE,
	data TEXT,
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

func (db *DB) SetEmail(sender, receiver, hash, data string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"INSERT INTO emails (sender, receiver, hash, data) VALUES ($1, $2, $3, $4)", 
		sender,
		receiver,
		hash,
		data,
	)
	return err
}

func (db *DB) GetEmail(id int, receiver string) string {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var data string
	row := db.ptr.QueryRow(
		"SELECT data FROM emails WHERE receiver=$1 ORDER BY id LIMIT 1 OFFSET $2",
		receiver,
		id-1,
	)
	row.Scan(&data)
	return data
}

func (db *DB) Size(receiver string) int {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var data int
	row := db.ptr.QueryRow(
		"SELECT COUNT(*) FROM emails WHERE receiver=$1",
		receiver,
	)
	row.Scan(&data)
	return data
}
