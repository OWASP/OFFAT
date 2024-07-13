dbuild:
	@docker build -f ./Dockerfile -t dmdhrumilmistry/offat . --no-cache --progress=plain

scan-vulns:
	@trivy image dmdhrumilmistry/offat --scanners vuln

docker: dbuild scan-vulns

run:
	@go run ./cmd/offat/main.go

build:
	@go build -o bin/offat cmd/offat/main.go

test:
	@go test -v ./...

bump:
	@go get -u ./...
	@go mod tidy

local: build-local-image scan-vulns
