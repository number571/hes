GI=go get
GC=go build
.PHONY: default build clean
default: build
build: gclient.go server.go database.go
	$(GC) gclient.go
	$(GC) server.go database.go config.go
clean:
	rm -f client.db server.db server.cfg server gclient
