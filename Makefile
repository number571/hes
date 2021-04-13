GC=go build
GFILES=client.go cdatabase.go cmodels.go csessions.go server.go sdatabase.go sconfig.go
.PHONY: default build clean
default: build
build: $(GFILES)
	$(GC) client.go consts.go cdatabase.go cmodels.go csessions.go
	$(GC) server.go consts.go sdatabase.go sconfig.go
clean:
	rm -f client.db server.db server.cfg server client
