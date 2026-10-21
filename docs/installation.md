---
title: Installation
section: Start
nav_order: 2
description: Install the OFFAT platform, the code-graph extra and the Rust execution engine.
---

# Installation

OFFAT is a set of Python packages that share one data contract (the Bundle),
plus a Rust execution engine. The Python side runs anywhere; the engine is only
needed when you send live traffic to a target.

## Prerequisites

| Need | For |
|---|---|
| Python 3.10+ | every stage |
| Rust 1.88+ | building the execution engine (live runs only) |
| `syft`, `grype`, `trivy` or `osv-scanner` | optional SBOM / dependency CVEs |

## Install the packages

```bash
git clone https://github.com/OWASP/OFFAT.git
cd OFFAT
pip install ./bundle ./triager './whitebox[graph]' ./graybox ./platform ./reporter
```

This puts five CLIs on your `PATH`: `offat-platform`, `offat-whitebox`,
`offat-graybox`, `offat-triage` and `offat-report`.

The `[graph]` extra installs the code-graph taint engine's dependencies
(`networkx` for the graph, `tree-sitter` for JavaScript/TypeScript). Without it
the white-box pipeline falls back to its pattern hunter and records why.

## Build the execution engine

```bash
make engine          # -> engine-rs/target/release/offat-engine
make engine-http3    # same, with the opt-in HTTP/3 + QUIC transport
```

`offat-platform run` finds the engine on `PATH`, at `$OFFAT_ENGINE`, or in
`engine-rs/target/{release,debug}/`. Source-only runs never need it.

## Container

```bash
make docker                          # builds offat:latest from docker/Dockerfile
docker run --rm -v "$PWD:/src" offat:latest run /src -o /src/app.offat.json
```

The image contains the engine and every Python package, and runs as a non-root
user. CI publishes it to the GitHub Container Registry: pull
`ghcr.io/owasp/offat:dev` (or a release tag).

## AI backends (optional)

Everything works offline with a deterministic heuristic. To enable AI triage,
the graph-tool agent and spec inference, provide one of:

| Provider | Needs |
|---|---|
| `anthropic` | `OFFAT_AI_API_KEY` (or `ANTHROPIC_API_KEY`) |
| `claude-code` | the `claude` CLI, already signed in |
| `codex` | the `codex` CLI, already signed in |

Next: [Usage](usage.md).
