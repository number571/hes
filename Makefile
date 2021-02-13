GI=go get
GC=go build
.PHONY: install default build
default: build
install:
	$(GI) github.com/number571/gopeer
	$(GI) github.com/mattn/go-sqlite3
	$(GI) golang.org/x/net/proxy
build: client.go server.go database.go
	$(GC) client.go
	$(GC) server.go database.go
