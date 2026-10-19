---
title: Home
nav_order: 1
description: "OWASP OFFAT (OFFensive Api Tester) - automated API security testing from an OpenAPI spec or straight from source."
permalink: /
---

# OWASP OFFAT
{: .fs-9 }

OFFensive Api Tester. Automatically test your API for common vulnerabilities -
from an OpenAPI/Swagger spec, or straight from your source code.
{: .fs-6 .fw-300 }

[Get started](installation){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/OWASP/OFFAT){: .btn .fs-5 .mb-4 .mb-md-0 }

---

OWASP OFFAT generates security tests from an API description and runs them for
you - fuzzing inputs and checking common OWASP API Top 10 weaknesses - and now
also maps and tests an API straight from its source code.

There are two ways to use it:

## 1. Classic CLI - spec-driven black-box testing

Point `offat` at an OpenAPI/Swagger file or URL and it generates and runs tests
automatically.

```bash
pip install offat
offat -f swagger_file.json
```

Checks: restricted HTTP methods, SQLi, BOLA, data exposure, BOPLA / mass
assignment, broken access control, basic command injection, and basic XSS /
HTML injection. See [Usage](usage#classic-cli) and the
[GitHub Action](github-action) for CI.

## 2. OFFAT-AI platform - source-aware testing

A staged pipeline that maps the attack surface from source (decorator routes
**and** OpenAPI specs), models threats, generates tests, executes them with a
Rust engine (HTTP/1.1 + HTTP/2, WebSocket, gRPC), and triages the findings - all
over one canonical Bundle file.

```bash
pip install ./bundle ./triager ./whitebox ./graybox ./platform ./reporter
make engine
offat-platform run /path/to/repo --url https://api.example.test --yes -o app.offat.json
```

See [Usage](usage#offat-ai-platform) and [How it works](how-it-works). Two
source-only modes - [white-box and gray-box](source-modes) - need no live
traffic.

---

## Demo

[![asciicast](https://asciinema.org/a/9MSwl7UafIVT3iJn13OcvWXeF.svg)](https://asciinema.org/a/9MSwl7UafIVT3iJn13OcvWXeF)

## Authorized use only
{: .text-red-200 }

OFFAT sends real requests to the target you point it at. The platform's
execution engine sends active attack traffic and requires an explicit `--yes`.
Only test systems and code you own or are explicitly authorized to assess.

## License

OWASP OFFAT is distributed under the [MIT License](https://github.com/OWASP/OFFAT/blob/dev/LICENSE.md).
