VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build linux windows test clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cypher ./cmd/cypher

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cypher-linux-amd64 ./cmd/cypher

windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cypher-windows-amd64.exe ./cmd/cypher

test:
	go test -race ./...

clean:
	rm -rf bin
