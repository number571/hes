package userside

import (
	"database/sql"
	"fmt"
	"bytes"
	"strings"
	"crypto/rsa"
	_ "github.com/mattn/go-sqlite3"
	gp "github.com/number571/gopeer"
)

const (
	DIFF_ENTR   = 20 // bits
	SEPARATOR = "\005\007\001"
)

func NewDB(name string) *DB {
	db, err := sql.Open("sqlite3", name)
	if err != nil {
		return nil
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id   INTEGER,
	name NVARCHAR(255) UNIQUE,
	pasw VARCHAR(255),
	salt VARCHAR(255),
	priv TEXT,
	PRIMARY KEY(id)
);
CREATE TABLE IF NOT EXISTS connects (
	id      INTEGER,
	id_user INTEGER,
	hash    VARCHAR(255) UNIQUE,
	host    VARCHAR(255),
	PRIMARY KEY(id),
	FOREIGN KEY(id_user) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS emails (
	id      INTEGER,
	id_user INTEGER,
	hash    VARCHAR(255) UNIQUE,
	spubl   TEXT,
	sname   VARCHAR(255),
	head    VARCHAR(255),
	body    TEXT,
	PRIMARY KEY(id),
	FOREIGN KEY(id_user) REFERENCES users(id) ON DELETE CASCADE
);
`)
	if err != nil {
		return nil
	}
	return &DB{
		ptr: db,
	}
}

func (db *DB) SetUser(name, pasw string, priv *rsa.PrivateKey) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if db.userExist(name) {
		return fmt.Errorf("user already exist")
	}
	salt := gp.GenerateBytes(32)
	bpasw := RaiseEntropy([]byte(pasw), salt, DIFF_ENTR)
	hpasw := gp.HashSum(bpasw)
	_, err := db.ptr.Exec(
		"INSERT INTO users (name, pasw, salt, priv) VALUES ($1, $2, $3, $4)",
		name,
		gp.Base64Encode(hpasw),
		gp.Base64Encode(salt),
		gp.Base64Encode(gp.EncryptAES(bpasw, gp.PrivateKeyToBytes(priv))),
	)
	return err
}

func (db *DB) GetUser(name, pasw string) *User {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		id   int
		hpasw string
		ssalt string
		spriv string
	)
	row := db.ptr.QueryRow(
		"SELECT id, pasw, salt, priv FROM users WHERE name=$1",
		name,
	)
	row.Scan(&id, &hpasw, &ssalt, &spriv)
	if spriv == "" {
		return nil
	}
	salt := gp.Base64Decode(ssalt)
	bpasw := RaiseEntropy([]byte(pasw), salt, DIFF_ENTR)
	if !bytes.Equal(gp.HashSum(bpasw), gp.Base64Decode(hpasw)) {
		return nil
	}
	priv := gp.BytesToPrivateKey(gp.DecryptAES(bpasw, gp.Base64Decode(spriv)))
	if priv == nil {
		return nil
	}
	return &User{
		Id:   id,
		Name: name,
		Pasw: bpasw,
		Salt: salt,
		Priv: priv,
	}
}

func (db *DB) GetEmails(user *User, start, quan int) []Email {
	var (
		email *Email
		emails []Email
	)
	for i := start; i < start+quan; i++ {
		email = db.GetEmail(user, i)
		if email == nil {
			break
		}
		emails = append(emails, *email)
	}
	return emails 
}

func (db *DB) GetEmail(user *User, id int) *Email {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		spubl string
		sname string
		head  string
		body  string
		hash  string
	)
	row := db.ptr.QueryRow(
		"SELECT spubl, sname, head, body, hash FROM emails WHERE id_user=$1 ORDER BY id DESC LIMIT 1 OFFSET $2",
		user.Id,
		id,
	)
	row.Scan(&spubl, &sname, &head, &body, &hash)
	if spubl == "" {
		return nil
	}
	return &Email{
		Id:         id,
		Hash:       hash,
		SenderPubl: string(gp.DecryptAES(user.Pasw, gp.Base64Decode(spubl))),
		SenderName: string(gp.DecryptAES(user.Pasw, gp.Base64Decode(sname))),
		Head:       string(gp.DecryptAES(user.Pasw, gp.Base64Decode(head))),
		Body:       string(gp.DecryptAES(user.Pasw, gp.Base64Decode(body))),
	}
}

func (db *DB) SetEmail(user *User, pack *gp.Package) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if db.emailExist(user, pack.Body.Hash) {
		return fmt.Errorf("email already exist")
	}
	splited := strings.Split(pack.Head.Title, SEPARATOR)
	if len(splited) != 2 {
		return fmt.Errorf("len.splited != 2")
	}
	_, err := db.ptr.Exec(
		"INSERT INTO emails (id_user, hash, spubl, sname, head, body) VALUES ($1, $2, $3, $4, $5, $6)",
		user.Id,
		hashWithSecret(user, pack.Body.Hash),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(pack.Head.Sender))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(splited[0]))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(splited[1]))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(pack.Body.Data))),
	)
	return err
}

func (db *DB) DelEmail(user *User, hash string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"DELETE FROM emails WHERE id_user=$1 AND hash=$2",
		user.Id,
		hash,
	)
	return err
}

func (db *DB) GetConns(user *User) []string {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		conn     string
		connects []string
	)
	rows, err := db.ptr.Query(
		"SELECT host FROM connects WHERE id_user=$1",
		user.Id,
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
		connects = append(connects, string(gp.DecryptAES(user.Pasw, gp.Base64Decode(conn))))
	}
	return connects
}

func (db *DB) SetConn(user *User, host string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if db.connExist(user, host) {
		return fmt.Errorf("conn already exist")
	}
	_, err := db.ptr.Exec(
		"INSERT INTO connects (id_user, hash, host) VALUES ($1, $2, $3)",
		user.Id,
		hashWithSecret(user, host),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(host))),
	)
	return err
}

func (db *DB) DelConn(user *User, host string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"DELETE FROM connects WHERE id_user=$1 AND hash=$2",
		user.Id,
		hashWithSecret(user, host),
	)
	return err
}

func (db *DB) userExist(name string) bool {
	var (
		namee string
	)
	row := db.ptr.QueryRow(
		"SELECT name FROM users WHERE name=$1",
		name,
	)
	row.Scan(&namee)
	return namee != ""
}

func (db *DB) connExist(user *User, host string) bool {
	var (
		hoste string
	)
	row := db.ptr.QueryRow(
		"SELECT host FROM connects WHERE id_user=$1 AND hash=$2",
		user.Id,
		hashWithSecret(user, host),
	)
	row.Scan(&hoste)
	return hoste != ""
}

func (db *DB) emailExist(user *User, hash string) bool {
	var (
		hashe string
	)
	row := db.ptr.QueryRow(
		"SELECT hash FROM emails WHERE id_user=$1 AND hash=$2",
		user.Id,
		hashWithSecret(user, hash),
	)
	row.Scan(&hashe)
	return hashe != ""
}

func hashWithSecret(user *User, data string) string {
	return gp.Base64Encode(gp.HashSum(bytes.Join(
		[][]byte{
			[]byte(data),
			user.Pasw,
			user.Salt,
		},
		[]byte{},
	)))
}
