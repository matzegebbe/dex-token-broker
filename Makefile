APP_NAME := dextokenbroker

.PHONY: fmt test build docker-build verify

fmt:
	gofmt -w ./cmd ./internal

test:
	go test ./...

build:
	go build -o bin/$(APP_NAME) ./cmd/dextokenbroker

docker-build:
	docker build -t $(APP_NAME):dev .

verify:
	test -z "$$(gofmt -l ./cmd ./internal)"
	go mod tidy -diff
	go vet ./...
	go test ./...
	go test -race ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
