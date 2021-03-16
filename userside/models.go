package userside

import (
	"crypto/rsa"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"sync"
)

type DB struct {
	ptr *sql.DB
	mtx sync.Mutex
}

type User struct {
	Id   int
	Name string
	Pasw []byte
	Salt []byte
	Priv *rsa.PrivateKey
}

type Email struct {
	Id         int
	SenderName string
	SenderPubl string
	Head       string
	Body       string
	Hash       string
}

type Sessions struct {
	mpn map[string]*User
	mtx sync.Mutex
}