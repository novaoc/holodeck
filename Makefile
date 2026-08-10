.PHONY: build linux test

build:
	go build -o holodeck .

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o holodeck-linux-amd64 .
	@ls -lh holodeck-linux-amd64

test:
	go vet ./...
	go test ./...
