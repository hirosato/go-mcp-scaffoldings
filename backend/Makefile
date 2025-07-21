.PHONY: init-backend clean build test

init-backend:
	go mod tidy

clean:
	rm -rf bin

build: clean
	mkdir -p bin
	go build -o bin/authorizer/bootstrap ./cmd/authorizer
	go build -o bin/oauth/bootstrap ./cmd/oauth
	go build -o bin/mcp/bootstrap ./cmd/mcp

test:
	go test -v ./...