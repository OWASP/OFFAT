---
title: Installation
nav_order: 2
description: "How to install the OFFAT CLI and the OFFAT-AI platform."
---

# Installation
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Classic CLI (`offat`)

### Using pip

```bash
# from PyPI
python3 -m pip install offat        # CLI only
python3 -m pip install offat[api]   # CLI + REST API

# or the latest from the default branch
python3 -m pip install git+https://github.com/OWASP/OFFAT.git
```

> On Termux or Windows use `pip` instead of `pip3`. A few features are
> Linux-only and may need administrator privileges.

### Using Docker

```bash
# CLI
docker run --rm dmdhrumilmistry/offat

# API (POST an OpenAPI doc to /api/v1/scan/ with its type: json|yaml)
docker compose up -d
```

### From source (Poetry)

```bash
sudo apt install git python3 -y          # prerequisites
git clone https://github.com/OWASP/OFFAT.git
cd OFFAT/src
poetry install
```

See [Usage - Classic CLI](usage.html#classic-cli) next.

---

## OFFAT-AI platform

The platform is a set of Python packages plus a Rust execution engine. The
Python side runs anywhere; the engine is only needed to send live traffic.

### Prerequisites

- Python 3.10+
- Rust 1.88+ (only to build the execution engine)
- Optional: `graft`, `semgrep`, and an SBOM/CVE tool (`syft`, `grype`, `trivy`,
  or `osv-scanner`) for richer source analysis - each is used when present.

### Install the Python packages

```bash
git clone https://github.com/OWASP/OFFAT.git
cd OFFAT
pip install ./bundle ./triager ./whitebox ./graybox ./platform ./reporter
```

This installs the CLIs: `offat-platform`, `offat-whitebox`, `offat-graybox`,
`offat-triage`, and `offat-report`.

### Build the execution engine (Rust)

```bash
make engine            # -> engine-rs/target/release/offat-engine
# or with the opt-in HTTP/3 + QUIC transport:
make engine-http3
```

`offat-platform run` auto-finds the engine on `PATH`, at `$OFFAT_ENGINE`, or in
`engine-rs/target/{release,debug}/`. You only need the engine for live runs
(`--url`); source-only runs and the white-box / gray-box modes do not.

### Optional: AI triage backend

Triage works fully offline with a deterministic heuristic. To enable AI triage,
provide one of:

| Provider | Needs |
|---|---|
| `anthropic` | `OFFAT_AI_API_KEY` (or `ANTHROPIC_API_KEY`) |
| `claude-code` | the `claude` CLI, already signed in |
| `codex` | the `codex` CLI, already signed in |

See [Usage - OFFAT-AI platform](usage.html#offat-ai-platform).
