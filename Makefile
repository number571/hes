.PHONY: default build clean
default: build 
build:
	go build -o cmd/client/c-hes cmd/client/*.go
	go build -o cmd/server/s-hes cmd/server/*.go
clean:
	rm -f \
		cmd/client.db cmd/server.db \
		cmd/client.cfg cmd/server.cfg \
		cmd/c-hes cmd/s-hes
