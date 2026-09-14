"""Stage 2 — Hunt.

Two complementary hunters:

* ``builtin_hunt`` — a dependency-free, multi-language regex hunter covering
  high-signal sink/secret/misconfig patterns. Always runs.
* ``semgrep_hunt`` — runs ``semgrep --config auto`` when semgrep is installed
  and maps its results into the shared finding schema.

Findings are normalized dicts sharing the DAST/triager schema so a single
triager and reporter serve both pipelines.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List

from . import tools

# --- built-in rule set ------------------------------------------------------
# Each rule: id, class, title, severity, cwe, owasp, pattern (compiled),
# exts (file extensions it applies to; empty = all text files), confidence.

_RAW_RULES = [
    # Secrets
    ("secret-aws-akid", "secrets", "Hardcoded AWS access key id", "high", "CWE-798", "A07",
     r"AKIA[0-9A-Z]{16}", [], 0.9),
    ("secret-private-key", "secrets", "Private key committed to source", "high", "CWE-798", "A07",
     r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", [], 0.95),
    ("secret-slack", "secrets", "Slack token", "high", "CWE-798", "A07",
     r"xox[baprs]-[0-9A-Za-z-]{10,}", [], 0.85),
    ("secret-github", "secrets", "GitHub token", "high", "CWE-798", "A07",
     r"gh[pousr]_[0-9A-Za-z]{30,}", [], 0.85),
    ("secret-generic", "secrets", "Hardcoded credential", "medium", "CWE-798", "A07",
     r"(?i)(api[_-]?key|secret|passwd|password|token|access[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{12,}['\"]",
     [], 0.55),
    # Injection sinks
    ("sink-eval", "command_injection", "Dangerous dynamic evaluation (eval/exec)", "high", "CWE-95", "A03",
     r"(?<![\w.])(eval|exec)\s*\(", [".py", ".js", ".ts", ".rb", ".php"], 0.6),
    ("sink-os-system", "command_injection", "Shell command execution", "high", "CWE-78", "A03",
     r"(os\.system|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|child_process\.exec\(|Runtime\.getRuntime\(\)\.exec\()",
     [], 0.65),
    ("sink-sql-format", "sqli", "SQL query built by string formatting", "high", "CWE-89", "A03",
     r"(?i)(execute|query|cursor\.execute|raw)\s*\(\s*(f['\"]|['\"].*?(select|insert|update|delete|from).*?['\"]\s*(\+|%|\.format|%\s*\())",
     [".py", ".js", ".ts", ".rb", ".php", ".java", ".go"], 0.5),
    # Deserialization
    ("deser-pickle", "deserialization", "Unsafe deserialization (pickle)", "high", "CWE-502", "A08",
     r"pickle\.(loads?|Unpickler)\s*\(", [".py"], 0.7),
    ("deser-yaml", "deserialization", "Unsafe YAML load", "high", "CWE-502", "A08",
     r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)", [".py"], 0.6),
    ("deser-java", "deserialization", "Java native deserialization", "high", "CWE-502", "A08",
     r"new\s+ObjectInputStream\s*\(", [".java"], 0.6),
    # XSS
    ("xss-innerhtml", "xss", "DOM XSS sink (innerHTML)", "medium", "CWE-79", "A03",
     r"\.innerHTML\s*=", [".js", ".ts", ".jsx", ".tsx", ".html"], 0.5),
    ("xss-dangerously", "xss", "React dangerouslySetInnerHTML", "medium", "CWE-79", "A03",
     r"dangerouslySetInnerHTML", [".jsx", ".tsx", ".js", ".ts"], 0.5),
    # Crypto / TLS
    ("crypto-weak-hash", "crypto", "Weak hash algorithm (MD5/SHA1)", "medium", "CWE-327", "A02",
     r"(?i)(hashlib\.(md5|sha1)\(|MessageDigest\.getInstance\(\s*['\"](MD5|SHA-1)|createHash\(\s*['\"](md5|sha1))",
     [], 0.55),
    ("tls-verify-off", "security_misconfig", "TLS verification disabled", "high", "CWE-295", "A02",
     r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false))",
     [], 0.7),
    # Misconfig
    ("misc-flask-debug", "security_misconfig", "Debug mode enabled", "low", "CWE-489", "A05",
     r"(app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)", [".py"], 0.45),
    ("misc-cors-wildcard", "security_misconfig", "Permissive CORS wildcard", "medium", "CWE-942", "A05",
     r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*", [], 0.5),
    # SSRF
    ("ssrf-open-fetch", "ssrf", "Outbound request to a non-constant URL", "medium", "CWE-918", "A10",
     r"(requests\.(get|post|put)\(\s*[a-zA-Z_]|urllib\.request\.urlopen\(\s*[a-zA-Z_]|axios\.(get|post)\(\s*[a-zA-Z_`])",
     [".py", ".js", ".ts"], 0.4),
]

_RULES = [
    dict(id=r[0], vclass=r[1], title=r[2], severity=r[3], cwe=r[4], owasp=r[5],
         regex=re.compile(r[6]), exts=set(r[7]), confidence=r[8])
    for r in _RAW_RULES
]

_SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__",
              ".venv", "venv", ".idea", ".vscode", "target", ".offat-ai", "offat-report"}
_TEXT_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".java",
              ".cs", ".c", ".cpp", ".h", ".rs", ".kt", ".scala", ".swift",
              ".yaml", ".yml", ".json", ".env", ".sh", ".html", ".sql", ".tf", ".xml"}
_MAX_FILE = 1_500_000


def iter_source_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".") or d == ".env"]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in _TEXT_EXTS and name not in (".env", "Dockerfile"):
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > _MAX_FILE:
                    continue
            except OSError:
                continue
            yield path, ext


def builtin_hunt(root: str, classes: List[str] | None = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    want = set(classes or [])
    active = [r for r in _RULES if not want or r["vclass"] in want]
    for path, ext in iter_source_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        rel = os.path.relpath(path, root)
        for rule in active:
            if rule["exts"] and ext not in rule["exts"]:
                continue
            for lineno, line in enumerate(lines, 1):
                if len(line) > 4000:
                    continue
                if rule["regex"].search(line):
                    findings.append(_mk_finding(rule, rel, lineno, line.rstrip(), lines))
    return findings


def _mk_finding(rule, rel, lineno, code, lines) -> Dict[str, Any]:
    start = max(0, lineno - 3)
    end = min(len(lines), lineno + 2)
    snippet = "".join(lines[start:end]).rstrip()
    uid = hashlib.sha1(f"{rule['id']}:{rel}:{lineno}".encode()).hexdigest()[:12]
    return {
        "id": uid,
        "vector_id": rule["id"],
        "class": rule["vclass"],
        "title": rule["title"],
        "severity": rule["severity"],
        "cwe": rule["cwe"],
        "owasp": rule["owasp"],
        "file": rel,
        "line": lineno,
        "technique": "static-pattern",
        "confidence": rule["confidence"],
        "code": snippet,
        "evidence": {"matched_line": code.strip()[:400], "notes": f"pattern rule {rule['id']}"},
        "references": [f"https://cwe.mitre.org/data/definitions/{rule['cwe'].split('-')[1]}.html"],
        "source_tool": "builtin",
    }


# --- semgrep integration ----------------------------------------------------

_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def semgrep_hunt(root: str, config: str = "auto") -> List[Dict[str, Any]]:
    if not tools.have("semgrep"):
        return []
    data = tools.run_json(
        ["semgrep", "--config", config, "--json", "--quiet", "--timeout", "0", root],
        timeout=1800,
    )
    if not data or "results" not in data:
        return []
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        sev = _SEMGREP_SEVERITY.get(extra.get("severity", "WARNING"), "medium")
        cwe = _first(meta.get("cwe"))
        owasp = _first(meta.get("owasp"))
        findings.append({
            "id": hashlib.sha1(json.dumps(r, sort_keys=True).encode()).hexdigest()[:12],
            "vector_id": r.get("check_id", "semgrep"),
            "class": _semgrep_class(r.get("check_id", ""), meta),
            "title": extra.get("message", r.get("check_id", "semgrep finding"))[:120],
            "severity": sev,
            "cwe": cwe or "",
            "owasp": owasp or "",
            "file": os.path.relpath(r.get("path", ""), root),
            "line": r.get("start", {}).get("line", 0),
            "technique": "semgrep",
            "confidence": {"HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4}.get(meta.get("confidence", "MEDIUM"), 0.6),
            "code": extra.get("lines", ""),
            "evidence": {"notes": extra.get("message", "")[:400]},
            "references": meta.get("references", []) or [],
            "source_tool": "semgrep",
        })
    return findings


def _semgrep_class(check_id: str, meta: Dict[str, Any]) -> str:
    text = (check_id + " " + " ".join(str(v) for v in meta.values())).lower()
    mapping = [
        ("sql", "sqli"), ("xss", "xss"), ("ssrf", "ssrf"), ("command", "command_injection"),
        ("path-traversal", "path_traversal"), ("deserial", "deserialization"),
        ("secret", "secrets"), ("crypto", "crypto"), ("xxe", "xxe"),
        ("csrf", "security_misconfig"), ("auth", "broken_auth"),
    ]
    for needle, cls in mapping:
        if needle in text:
            return cls
    return "security_misconfig"


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v
