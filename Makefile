.PHONY: build linux test

build:
	go build -o holodex .

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o holodex-linux-amd64 .
	@ls -lh holodex-linux-amd64

test:
	go vet ./...
	go test ./...
