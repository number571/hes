package main

import (
	"bytes"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	gp "github.com/number571/gopeer"
	"strings"
	"time"
)

const (
	PASWDIFF = 25 // bits
	IS_EMAIL = "[IS-EMAIL]"
)

func NewDB(name string) *DB {
	db, err := sql.Open("sqlite3", name)
	if err != nil {
		return nil
	}
	_, err = db.Exec(`
PRAGMA foreign_keys=ON;
PRAGMA secure_delete=ON;
CREATE TABLE IF NOT EXISTS users (
	id   INTEGER,
	f2f  BOOLEAN,
	hashn VARCHAR(255) UNIQUE,
	hashp VARCHAR(255),
	salt VARCHAR(255),
	priv TEXT,
	PRIMARY KEY(id)
);
CREATE TABLE IF NOT EXISTS contacts (
	id      INTEGER,
	id_user INTEGER,
	hashn   VARCHAR(255) UNIQUE,
	hashp   VARCHAR(255) UNIQUE,
	name    NVARCHAR(255),
	publ    TEXT,
	PRIMARY KEY(id),
	FOREIGN KEY(id_user) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS connects (
	id      INTEGER,
	id_user INTEGER,
	hash    VARCHAR(255) UNIQUE,
	host    VARCHAR(255),
	pasw    VARCHAR(255),
	PRIMARY KEY(id),
	FOREIGN KEY(id_user) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS emails (
	id      INTEGER,
	id_user INTEGER,
	deleted BOOLEAN DEFAULT 0,
	hash    VARCHAR(255) UNIQUE,
	spubl   TEXT,
	sname   NVARCHAR(255),
	head    NVARCHAR(255),
	body    TEXT,
	addtime TEXT,
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

func (db *DB) StateF2F(user *User) bool {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		f2f bool
	)
	row := db.ptr.QueryRow(
		"SELECT f2f FROM users WHERE hashn=$1",
		gp.Base64Encode(gp.HashSum([]byte(user.Name))),
	)
	row.Scan(&f2f)
	return f2f
}

func (db *DB) SwitchF2F(user *User) error {
	f2f := !db.StateF2F(user)
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"UPDATE users SET f2f=$1 WHERE hashn=$2",
		f2f,
		gp.Base64Encode(gp.HashSum([]byte(user.Name))),
	)
	return err
}

func (db *DB) SetUser(name, pasw string, priv *rsa.PrivateKey) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if priv == nil {
		return fmt.Errorf("private key is null")
	}
	name = strings.TrimSpace(name)
	if len(name) < 6 || len(name) > 64 {
		return fmt.Errorf("need len username >= 6 and <= 64")
	}
	if len(pasw) < 8 {
		return fmt.Errorf("need len password >= 8")
	}
	if db.userExist(name) {
		return fmt.Errorf("user already exist")
	}
	salt := gp.GenerateBytes(gp.Get("RAND_SIZE").(uint))
	bpasw := gp.RaiseEntropy([]byte(pasw), salt, PASWDIFF)
	hpasw := gp.HashSum(bytes.Join(
		[][]byte{
			bpasw,
			[]byte(name),
		},
		[]byte{},
	))
	_, err := db.ptr.Exec(
		"INSERT INTO users (hashn, hashp, salt, priv, f2f) VALUES ($1, $2, $3, $4, 0)",
		gp.Base64Encode(gp.HashSum([]byte(name))),
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
		id    int
		hpasw string
		ssalt string
		spriv string
	)
	name = strings.TrimSpace(name)
	row := db.ptr.QueryRow(
		"SELECT id, hashp, salt, priv FROM users WHERE hashn=$1",
		gp.Base64Encode(gp.HashSum([]byte(name))),
	)
	row.Scan(&id, &hpasw, &ssalt, &spriv)
	if spriv == "" {
		return nil
	}
	salt := gp.Base64Decode(ssalt)
	bpasw := gp.RaiseEntropy([]byte(pasw), salt, PASWDIFF)
	chpasw := gp.HashSum(bytes.Join(
		[][]byte{
			bpasw,
			[]byte(name),
		},
		[]byte{},
	))
	if !bytes.Equal(chpasw, gp.Base64Decode(hpasw)) {
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
		Priv: priv,
	}
}

func (db *DB) DelUser(user *User) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"DELETE FROM users WHERE id=$1",
		user.Id,
	)
	return err
}

func (db *DB) GetEmails(user *User, start, quan int) []Email {
	var (
		email  *Email
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
		atime string
	)
	row := db.ptr.QueryRow(
		"SELECT spubl, sname, head, body, hash, addtime FROM emails WHERE id_user=$1 AND deleted=0 ORDER BY id DESC LIMIT 1 OFFSET $2",
		user.Id,
		id,
	)
	row.Scan(&spubl, &sname, &head, &body, &hash, &atime)
	if spubl == "" {
		return nil
	}
	return &Email{
		Id:         id,
		Hash:       hash,
		SenderPubl: gp.Base64Encode(gp.DecryptAES(user.Pasw, gp.Base64Decode(spubl))),
		SenderName: string(gp.DecryptAES(user.Pasw, gp.Base64Decode(sname))),
		Head:       string(gp.DecryptAES(user.Pasw, gp.Base64Decode(head))),
		Body:       string(gp.DecryptAES(user.Pasw, gp.Base64Decode(body))),
		Time:       string(gp.DecryptAES(user.Pasw, gp.Base64Decode(atime))),
	}
}

func (db *DB) SetEmail(user *User, pack *gp.Package) error {
	pub := gp.BytesToPublicKey(pack.Head.Sender)
	if db.StateF2F(user) && !db.InContacts(user, pub) {
		return fmt.Errorf("sender not in contacts")
	}
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if pack.Head.Title != IS_EMAIL {
		return fmt.Errorf("is not email")
	}
	if db.emailExist(user, gp.Base64Encode(pack.Body.Hash)) {
		return fmt.Errorf("email already exist")
	}
	var email Email
	err := json.Unmarshal([]byte(pack.Body.Data), &email)
	if err != nil {
		return fmt.Errorf("json decode")
	}
	name := strings.TrimSpace(email.SenderName)
	if len(name) < 6 || len(name) > 64 {
		return fmt.Errorf("len username < 6 or > 64")
	}
	head := strings.TrimSpace(email.Head)
	body := strings.TrimSpace(email.Body)
	if head == "" || body == "" {
		return fmt.Errorf("head or body is null")
	}
	heads := strings.Split(head, FSEPARAT)
	bodys := strings.Split(body, FSEPARAT)
	if len(heads) != len(bodys) {
		return fmt.Errorf("len.head != len.body")
	}
	_, err = db.ptr.Exec(
		"INSERT INTO emails (id_user, hash, spubl, sname, head, body, addtime) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		user.Id,
		hashWithSecret(user, pack.Body.Hash),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, pack.Head.Sender)),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(name))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(head))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(body))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(time.Now().Format(time.RFC850)))),
	)
	return err
}

func (db *DB) DelEmail(user *User, hash string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	_, err := db.ptr.Exec(
		"UPDATE emails SET deleted=1, spubl=NULL, sname=NULL, head=NULL, body=NULL, addtime=NULL WHERE id_user=$1 AND hash=$2",
		user.Id,
		hash,
	)
	return err
}

func (db *DB) GetContacts(user *User) map[string]string {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		name     string
		spub     string
		contacts = make(map[string]string)
	)
	rows, err := db.ptr.Query(
		"SELECT name, publ FROM contacts WHERE id_user=$1",
		user.Id,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(
			&name,
			&spub,
		)
		if err != nil {
			break
		}
		name = string(gp.DecryptAES(user.Pasw, gp.Base64Decode(name)))
		spub = gp.Base64Encode(gp.DecryptAES(user.Pasw, gp.Base64Decode(spub)))
		contacts[name] = spub
	}
	return contacts
}

func (db *DB) InContacts(user *User, pub *rsa.PublicKey) bool {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		namee string
	)
	row := db.ptr.QueryRow(
		"SELECT name FROM contacts WHERE id_user=$1 AND hashp=$2",
		user.Id,
		hashWithSecret(user, gp.PublicKeyToBytes(pub)),
	)
	row.Scan(&namee)
	return namee != ""
}

func (db *DB) SetContact(user *User, name string, pub *rsa.PublicKey) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if pub == nil {
		return fmt.Errorf("public key is null")
	}
	name = strings.TrimSpace(name)
	if len(name) == 0 {
		return fmt.Errorf("nickname is null")
	}
	if db.contactExist(user, name, pub) {
		return fmt.Errorf("contact already exist")
	}
	spub := gp.PublicKeyToBytes(pub)
	_, err := db.ptr.Exec(
		"INSERT INTO contacts (id_user, hashn, hashp, name, publ) VALUES ($1, $2, $3, $4, $5)",
		user.Id,
		hashWithSecret(user, []byte(name)),
		hashWithSecret(user, spub),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(name))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, spub)),
	)
	return err
}

func (db *DB) DelContact(user *User, pub *rsa.PublicKey) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	if pub == nil {
		return fmt.Errorf("public key is null")
	}
	_, err := db.ptr.Exec(
		"DELETE FROM contacts WHERE id_user=$1 AND hashp=$2",
		user.Id,
		hashWithSecret(user, gp.PublicKeyToBytes(pub)),
	)
	return err
}

func (db *DB) GetConns(user *User) [][2]string {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	var (
		conn     string
		pasw     string
		connects [][2]string
	)
	rows, err := db.ptr.Query(
		"SELECT host, pasw FROM connects WHERE id_user=$1",
		user.Id,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(
			&conn,
			&pasw,
		)
		if err != nil {
			break
		}
		connects = append(connects, [2]string{
			string(gp.DecryptAES(user.Pasw, gp.Base64Decode(conn))),
			string(gp.DecryptAES(user.Pasw, gp.Base64Decode(pasw))),
		})
	}
	return connects
}

func (db *DB) SetConn(user *User, host, pasw string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	host = strings.TrimSpace(host)
	if len(host) == 0 {
		return fmt.Errorf("host is null")
	}
	if db.connExist(user, host) {
		_, err := db.ptr.Exec(
			"UPDATE connects SET pasw=$1 WHERE id_user=$2 AND hash=$3",
			gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(pasw))),
			user.Id,
			hashWithSecret(user, []byte(host)),
		)
		return err
	}
	_, err := db.ptr.Exec(
		"INSERT INTO connects (id_user, hash, host, pasw) VALUES ($1, $2, $3, $4)",
		user.Id,
		hashWithSecret(user, []byte(host)),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(host))),
		gp.Base64Encode(gp.EncryptAES(user.Pasw, []byte(pasw))),
	)
	return err
}

func (db *DB) DelConn(user *User, host string) error {
	db.mtx.Lock()
	defer db.mtx.Unlock()
	host = strings.TrimSpace(host)
	if len(host) == 0 {
		return fmt.Errorf("host is null")
	}
	_, err := db.ptr.Exec(
		"DELETE FROM connects WHERE id_user=$1 AND hash=$2",
		user.Id,
		hashWithSecret(user, []byte(host)),
	)
	return err
}

func (db *DB) userExist(name string) bool {
	var (
		namee string
	)
	row := db.ptr.QueryRow(
		"SELECT name FROM users WHERE hashn=$1",
		gp.Base64Encode(gp.HashSum([]byte(name))),
	)
	row.Scan(&namee)
	return namee != ""
}

func (db *DB) contactExist(user *User, name string, pub *rsa.PublicKey) bool {
	var (
		namee string
	)
	row := db.ptr.QueryRow(
		"SELECT name FROM contacts WHERE id_user=$1 AND (hashn=$2 OR hashp=$3)",
		user.Id,
		hashWithSecret(user, []byte(name)),
		hashWithSecret(user, gp.PublicKeyToBytes(pub)),
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
		hashWithSecret(user, []byte(host)),
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
		hashWithSecret(user, []byte(hash)),
	)
	row.Scan(&hashe)
	return hashe != ""
}

func hashWithSecret(user *User, data []byte) string {
	return gp.Base64Encode(gp.HashSum(bytes.Join(
		[][]byte{
			data,
			user.Pasw,
		},
		[]byte{},
	)))
}
