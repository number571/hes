# HES

> Hidden email service. Gopeer based.

### Characteristics:
1. End to end encryption;
2. Supported tor connections;
3. Symmetric algorithm: AES256-CBC;
4. Asymmetric algorithm: RSA-[OAEP, PSS];
5. Hash function: SHA256;

### Compile and run:
```
$ make
> go build client.go
> go build server.go database.go
$ ./server -address=":8080" &
$ ./client -address="localhost:8080"
```

### Client actions:
```
1. exit - close client;
2. help - commands info;
3. user - actions:
3.1. create - generate private key;
3.2. load - load private key;
3.3. public - print public key;
3.4. private - print private key;
4. send - send email;
5. recv - actions:
5.1. size - print number of emails;
5.2. [number] - print email by number;
```

### SQL Tables (database.db):
> Database file is created when the application starts.
```sql
/* sender, receiver = hash(public_key) */
/* hash = hash(data) */
/* data = encrypt(email) */
CREATE TABLE IF NOT EXISTS emails (
	id INTEGER,
	sender VARCHAR(255),
	receiver VARCHAR(255),
	hash VARCHAR(255) UNIQUE,
	data TEXT,
	PRIMARY KEY(id)
);
```
