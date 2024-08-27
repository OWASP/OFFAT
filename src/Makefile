run:
	@go run -race ./cmd/offat/ -v

dbuild:
	@docker build -t dmdhrumilmistry/offat .

scan-vulns:
	@trivy image dmdhrumilmistry/offat --scanners vuln

docker: dbuild scan-vulns

build:
	@go build -o bin/offat cmd/offat/*

test:
	@go test -cover -v ./...

bump:
	@go get -u ./...
	@go mod tidy

local: build-local-image scan-vulns
