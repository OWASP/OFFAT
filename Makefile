SHELL := /bin/bash
BIN := bin
DAST := $(BIN)/offat-dast

.PHONY: all build dast test vet fmt whitebox-install triage-install python-check \
        smoke docker clean help

all: build ## Build everything (default)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: dast ## Build the DAST engine binary

dast: ## Build the Go DAST engine -> bin/offat-dast
	@mkdir -p $(BIN)
	cd dast && go build -o ../$(DAST) ./cmd/offat-dast
	@echo "built $(DAST)"

test: ## Run Go unit tests
	cd dast && go test ./...

vet: ## Run go vet
	cd dast && go vet ./...

fmt: ## Format Go sources
	cd dast && gofmt -w .

triage-install: ## Install the shared Python triager
	pip install ./triager

whitebox-install: triage-install ## Install the white-box pipeline (+ triager)
	pip install ./whitebox

graybox-install: whitebox-install ## Install the gray-box pipeline (+ whitebox + triager)
	pip install ./graybox

python-check: ## Byte-compile the Python packages
	python3 -m compileall -q triager/offat_triage whitebox/offat_wb graybox/offat_gb

smoke: dast ## Quick offline smoke test (spec parse + test generation)
	./$(DAST) --spec examples/vulnshop-openapi.yaml --kb knowledge-base --graph --dry-run
	PYTHONPATH=whitebox:triager python3 -m offat_wb examples/vuln-code --no-ai -o /tmp/offat-smoke >/dev/null && echo "whitebox smoke OK"
	PYTHONPATH=graybox:whitebox:triager python3 -m offat_gb graybox/tests/fixtures/app --no-ai --no-graft -o /tmp/offat-gb-smoke >/dev/null && echo "graybox smoke OK"

docker: ## Build the combined Docker image
	docker build -t offat-ai:latest -f docker/Dockerfile .

clean: ## Remove build artifacts and reports
	rm -rf $(BIN) offat-report /tmp/offat-smoke
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
