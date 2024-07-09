build-slim-local-images:
	@docker build -f DockerFiles/base-Dockerfile -t dmdhrumilmistry/offat-base .
	# @docker build -f DockerFiles/main/cli-Dockerfile -t dmdhrumilmistry/offat .

build-local-image:
	@docker build -f DockerFiles/wolfi-base-Dockerfile -t dmdhrumilmistry/offat-base . --no-cache --progress=plain

scan-vulns:
	@trivy image dmdhrumilmistry/offat-base --scanners vuln

run:
	@go run ./cmd/offat/main.go

local: build-local-image scan-vulns
