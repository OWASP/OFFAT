# OFFAT-AI Knowledge Base

The knowledge base drives **dynamic** attack-vector generation. Instead of a
fixed list of tests, the DAST engine matches every request parameter against
the vectors declared here and instantiates only the ones that *apply* to that
parameter's location, type, name and HTTP method. New attack techniques are
added by dropping a YAML file here — no code changes required.

Two layers ship in this repo:

| Layer | Location | Loaded |
|---|---|---|
| **Built-in defaults** | `dast/internal/kb/data/*.yaml` (embedded in the binary) | always |
| **Extended library** | `knowledge-base/vectors/*.yaml` | `offat-dast --kb knowledge-base` |
| **Bug-bounty patterns** | `knowledge-base/bug-bounty/*.yaml` | `offat-dast --kb knowledge-base` |

## Provenance

Vectors are distilled from:

- **OWASP API Security Top 10 (2023)** — the class taxonomy (BOLA, broken auth,
  BOPLA/mass-assignment, resource consumption, BFLA, SSRF, misconfiguration).
- **OWASP Web Security Testing Guide** and PortSwigger Web Security Academy —
  detection techniques and payload shapes.
- **Patterns observed across public bug-bounty disclosures** (HackerOne
  Hacktivity, disclosed reports, and public write-ups). These are encoded as
  *generic techniques* (e.g. "numeric IDOR enumeration", "JWT `kid` path/SQL
  injection", "SSRF to cloud metadata via redirect") with references to the
  vulnerability class rather than any single report's proprietary content.

> The AI triager can also propose new vectors at runtime from its own knowledge
> of report patterns; see `docs/dast.md`.

## Vector schema

```yaml
vectors:
  - id: unique-id                 # stable identifier (also the SARIF rule id)
    class: sqli                   # vulnerability class
    title: Human readable title
    severity: critical|high|medium|low|info
    cwe: CWE-89
    owasp: "API8:2023 ..."
    description: What it tests and why a hit matters.
    references: [https://...]
    applies_to:                   # generation filter
      locations: [query, path, header, cookie, body]
      types: [string, integer, number, boolean, any]
      name_patterns: ["(?i)regex-on-param-name"]
      methods: [POST, PUT]
    payloads:                     # value-injection vectors
      - {value: "' OR '1'='1", technique: error, encoding: none, note: "..."}
    detection:                    # how a hit is judged
      error_signatures: ["sql syntax"]
      reflect_marker: true        # payload/marker echoed in response
      time_threshold_ms: 4500     # time-based
      status_codes: [301, 302]    # status-based
      body_regex: ["root:.*:0:0:"]
    structural: bola              # OR: a named structural attack (no payloads)
```

`technique` is one of: `error`, `reflection`, `time`, `boolean`, `status`,
`diff`. `structural` is one of: `bola`, `bfla`, `mass_assignment`,
`auth_bypass`, `jwt_none`, `method_tamper`, `rate_limit`, `cors`,
`data_exposure`.

## Adding a vector

1. Add it to a file under `knowledge-base/vectors/` (or a new file).
2. Run `offat-dast --spec api.yaml --kb knowledge-base --dry-run` to confirm it
   is picked up (`KB vectors` count rises and it appears in the plan).
3. Run a real scan against an authorized target.
