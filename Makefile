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
	python3 -m unittest discover -s scripts -p '*_test.py'
	go mod tidy -diff
	go -C tools mod tidy -diff
	go vet ./...
	go test ./...
	go test -race ./...
	go tool -modfile=tools/go.mod staticcheck ./...
	go tool -modfile=tools/go.mod govulncheck ./...
