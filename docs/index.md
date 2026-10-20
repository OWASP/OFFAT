---
title: OWASP OFFAT
section: Start
nav_order: 1
nav_title: Overview
layout: home
description: Source-aware API security testing. Map your API from code, prove source-to-sink flows on a code graph, execute with a Rust engine, triage with AI.
---

## Quick start

```bash
git clone https://github.com/OWASP/OFFAT.git && cd OFFAT
pip install ./bundle ./triager './whitebox[graph]' ./graybox ./platform ./reporter

# source-only: maps, plans, triages and reports without sending traffic
offat-platform run /path/to/repo -o app.offat.json --report-dir reports
```

Building the [Rust engine](installation.md#build-the-execution-engine) adds
live execution against targets you are authorized to test.

## Where to go next

- [Installation](installation.md) - packages, engine, container, AI backends
- [Usage](usage.md) - the pipeline, stage by stage, identities and CI gates
- [How it works](how-it-works.md) - the Bundle contract and the engine
- [Code graph](code-graph.md) - taint analysis and the AI built on it
- [GitHub Action](github-action.md) - scan every push, publish to code scanning

> **Authorized use only.** Live runs send real requests and require an explicit
> `--yes`. Only test systems and code you own or are authorized to assess.
