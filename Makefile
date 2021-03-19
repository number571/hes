GI=go get
GC=go build
.PHONY: install default build clean
default: build
install:
	$(GI) github.com/number571/gopeer
	$(GI) github.com/mattn/go-sqlite3
	$(GI) github.com/boombuler/barcode
	$(GI) golang.org/x/net/proxy
build: gclient.go server.go database.go
	$(GC) gclient.go
	$(GC) server.go database.go
clean:
	rm -f client.db server.db server gclient
