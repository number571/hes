GC=go build
GFILES=client.go cdatabase.go cmodels.go csessions.go gconsts.go server.go sdatabase.go sconfig.go
.PHONY: default build clean
default: build
build: $(GFILES)
	$(GC) client.go gconsts.go cdatabase.go cmodels.go csessions.go
	$(GC) server.go gconsts.go sdatabase.go sconfig.go
clean:
	rm -f client.db server.db server client
