# HES

> Hidden email service. Version 1.1.4s.

### Characteristics:
1. End to end encryption;
2. Supported tor connections;
3. Symmetric algorithm: AES-CBC;
4. Asymmetric algorithm: RSA-OAEP, RSA-PSS;
5. Hash function: SHA256;

### Home page:
<img src="/userside/images/HES1.png" alt="HomePage"/>

### Install:
```
$ make install
> go get github.com/number571/gopeer
> go get github.com/mattn/go-sqlite3
> go get github.com/boombuler/barcode
> go get golang.org/x/net/proxy
```

### Account page:
<img src="/userside/images/HES4.png" alt="AccountPage"/>

### Compile and run:
```
$ make
> go build gclient.go
> go build server.go database.go
$ ./server -open="localhost:8080" &
$ ./gclient -open="localhost:7545"
```

### List of emails page:
<img src="/userside/images/HES7.png" alt="ListOfEmailsPage"/>

### SQL Tables (database.db):
> Database files are creates when the application starts.

#### Server side
```sql
CREATE TABLE IF NOT EXISTS connects (
	id      INTEGER,
	host    VARCHAR(255) UNIQUE,
	PRIMARY KEY(id)
);
/* recv = hash(public_key) */
/* hash = hash(data) */
/* data = encrypt(email) */
CREATE TABLE IF NOT EXISTS emails (
	id      INTEGER,
	recv    VARCHAR(255),
	hash    VARCHAR(255) UNIQUE,
	data    TEXT,
	addtime DATETIME DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(id)
);
```

#### Client side
```sql
/* !key_pasw = hash(password, salt)^20 */
/* name      = hash(nickname) */
/* pasw      = hash(!key_pasw, nickname) */
/* priv      = encrypt[!key_pasw](private_key) */
CREATE TABLE IF NOT EXISTS users (
	id   INTEGER,
	f2f  BOOLEAN,
	name NVARCHAR(255) UNIQUE,
	pasw VARCHAR(255),
	salt VARCHAR(255),
	priv TEXT,
	PRIMARY KEY(id)
);
/* hashn = hash(nickname, !key_pasw) */
/* hashp = hash(public_key, !key_pasw) */
/* name  = encrypt[!key_pasw](nickname) */
/* publ  = encrypt[!key_pasw](public_key) */
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
/* hash = hash(host, !key_pasw) */
/* host = encrypt[!key_pasw](host) */
CREATE TABLE IF NOT EXISTS connects (
	id      INTEGER,
	id_user INTEGER,
	hash    VARCHAR(255) UNIQUE,
	host    VARCHAR(255),
	PRIMARY KEY(id),
	FOREIGN KEY(id_user) REFERENCES users(id) ON DELETE CASCADE
);
/* hash    = hash(pack_hash, !key_pasw) */
/* spubl   = encrypt[!key_pasw](public_key) */
/* sname   = encrypt[!key_pasw](nickname) */
/* head    = encrypt[!key_pasw](title) */
/* body    = encrypt[!key_pasw](message) */
/* addtime = encrypt[!key_pasw](time_rec) */
CREATE TABLE IF NOT EXISTS emails (
	id      INTEGER,
	id_user INTEGER,
	deleted BOOLEAN DEFAULT 0,
	hash    VARCHAR(255) UNIQUE,
	spubl   TEXT,
	sname   VARCHAR(255),
	head    VARCHAR(255),
	body    TEXT,
	addtime TEXT,
	PRIMARY KEY(id),
	FOREIGN KEY(id_user) REFERENCES users(id) ON DELETE CASCADE
);
```

### Email page:
<img src="/userside/images/HES8.png" alt="EmailPage"/>
