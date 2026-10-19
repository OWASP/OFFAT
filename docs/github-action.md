---
title: GitHub Action
nav_order: 6
description: "Run the classic OFFAT scanner in CI with the OWASP/OFFAT action."
---

# GitHub Action

Run the spec-driven scanner in your CI pipeline with the `OWASP/OFFAT` action.

1. Add a repository secret `url` pointing at your OpenAPI/Swagger document.
2. Add a workflow at `.github/workflows/offat.yml`:

{% raw %}
```yaml
name: OWASP OFFAT Sample Workflow

on:
  push:
    branches:
      - dev
      - main

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Download swagger/OAS file
        run: curl ${url} -o /tmp/swagger.json
        env:
          url: ${{ secrets.url }}

      - name: OWASP OFFAT CICD Scanner
        uses: OWASP/OFFAT@main        # or pin a version, e.g. OWASP/OFFAT@v0.17.3
        with:
          file: /tmp/swagger.json     # or ${{ secrets.url }}
          rate_limit: 120
          artifact_retention_days: 1
```
{% endraw %}

> Prefer pinning the action to a specific version (`OWASP/OFFAT@v0.17.3`) rather
> than `@main`, and bump it after testing.

Only run this against an API you own or are explicitly authorized to test.
