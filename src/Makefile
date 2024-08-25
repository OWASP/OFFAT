run:
	@go run -race ./cmd/offat/main.go --version

dbuild:
	@docker build -f ./Dockerfile -t dmdhrumilmistry/offat . --no-cache --progress=plain

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
