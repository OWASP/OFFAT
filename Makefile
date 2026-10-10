SHELL := /bin/bash

.PHONY: all engine engine-test platform-install python-check viz-test smoke docker clean help

all: engine ## Build the execution engine (default)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

engine: ## Build the Rust execution engine -> engine-rs/target/release/offat-engine
	cd engine-rs && cargo build --release

engine-test: ## Run the engine's unit tests
	cd engine-rs && cargo test

platform-install: ## Install the Python platform + its libraries
	pip install ./bundle ./triager ./whitebox ./graybox ./platform ./reporter

python-check: ## Byte-compile the Python packages
	python3 -m compileall -q bundle/offat_bundle triager/offat_triage whitebox/offat_wb \
	  graybox/offat_gb platform/offat_platform reporter/offat_report

viz-test: ## Smoke-test the visualizer render logic
	node viz/tests/dom_smoke.js

smoke: ## Offline end-to-end check (map -> prg -> threat-model -> test-gen)
	PYTHONPATH=platform:graybox:whitebox:triager:bundle:reporter \
	  python3 -m offat_platform map graybox/tests/fixtures/app --no-graft --threat-model \
	  -o /tmp/offat-smoke.offat.json
	PYTHONPATH=platform:graybox:whitebox:triager:bundle:reporter \
	  python3 -m offat_platform test-gen /tmp/offat-smoke.offat.json
	PYTHONPATH=platform:graybox:whitebox:triager:bundle:reporter \
	  python3 -m offat_platform validate /tmp/offat-smoke.offat.json && echo "platform smoke OK"

docker: ## Build the platform image (Rust engine + Python platform)
	docker build -t offat-ai:latest -f docker/Dockerfile .

clean: ## Remove build artifacts and reports
	rm -rf engine-rs/target offat-report /tmp/offat-smoke*.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
