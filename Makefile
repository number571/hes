GC=go build
.PHONY: default build
default: build
build: client.go server.go database.go
	$(GC) client.go
	$(GC) server.go database.go
