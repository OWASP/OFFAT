"""Threat taxonomy - OWASP API Security Top 10 (2023), OWASP Top 10 (2021), CWE.

A single source of truth that maps every vulnerability `class` the scanners emit
to its OWASP API Top 10 (2023) category, its OWASP Top 10 (2021) web category,
and a primary CWE, each with human names. The white-box and gray-box pipelines
call `enrich()` so every finding carries a consistent `threat` block and a
normalized `owasp`/`cwe`, and the reporters render a threat-mapping section from
`api_summary()`.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List

# OWASP API Security Top 10 - 2023 (https://owasp.org/API-Security/editions/2023/)
OWASP_API_2023: Dict[str, str] = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

# OWASP Top 10 - 2021 (https://owasp.org/Top10/)
OWASP_WEB_2021: Dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

CWE_NAMES: Dict[str, str] = {
    "CWE-16": "Configuration",
    "CWE-22": "Path Traversal",
    "CWE-74": "Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-213": "Exposure of Sensitive Information Due to Incompatible Policies",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-489": "Active Debug Code",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity Reference",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
    "CWE-1035": "Using Components with Known Vulnerabilities",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
}

# class -> (OWASP API 2023 id, OWASP Web 2021 id, primary CWE)
CLASS_MAP: Dict[str, Dict[str, str]] = {
    "access_control":      {"api": "API1:2023", "web": "A01:2021", "cwe": "CWE-639"},
    "bola":                {"api": "API1:2023", "web": "A01:2021", "cwe": "CWE-639"},
    "bfla":                {"api": "API5:2023", "web": "A01:2021", "cwe": "CWE-285"},
    "mass_assignment":     {"api": "API3:2023", "web": "A04:2021", "cwe": "CWE-915"},
    "data_exposure":       {"api": "API3:2023", "web": "A02:2021", "cwe": "CWE-213"},
    "broken_auth":         {"api": "API2:2023", "web": "A07:2021", "cwe": "CWE-287"},
    "security_misconfig":  {"api": "API8:2023", "web": "A05:2021", "cwe": "CWE-16"},
    "sqli":                {"api": "API8:2023", "web": "A03:2021", "cwe": "CWE-89"},
    "nosqli":              {"api": "API8:2023", "web": "A03:2021", "cwe": "CWE-943"},
    "command_injection":   {"api": "API8:2023", "web": "A03:2021", "cwe": "CWE-78"},
    "ssti":                {"api": "API8:2023", "web": "A03:2021", "cwe": "CWE-1336"},
    "ldap_injection":      {"api": "API8:2023", "web": "A03:2021", "cwe": "CWE-90"},
    "injection":           {"api": "API8:2023", "web": "A03:2021", "cwe": "CWE-74"},
    "xss":                 {"api": "API8:2023", "web": "A03:2021", "cwe": "CWE-79"},
    "path_traversal":      {"api": "API8:2023", "web": "A01:2021", "cwe": "CWE-22"},
    "ssrf":                {"api": "API7:2023", "web": "A10:2021", "cwe": "CWE-918"},
    "open_redirect":       {"api": "API8:2023", "web": "A01:2021", "cwe": "CWE-601"},
    "xxe":                 {"api": "API8:2023", "web": "A05:2021", "cwe": "CWE-611"},
    "deserialization":     {"api": "API8:2023", "web": "A08:2021", "cwe": "CWE-502"},
    "secrets":             {"api": "API8:2023", "web": "A07:2021", "cwe": "CWE-798"},
    "crypto":              {"api": "API8:2023", "web": "A02:2021", "cwe": "CWE-327"},
    "csrf":                {"api": "API8:2023", "web": "A01:2021", "cwe": "CWE-352"},
    "file_upload":         {"api": "API8:2023", "web": "A08:2021", "cwe": "CWE-434"},
    "vulnerable_dependency": {"api": "API8:2023", "web": "A06:2021", "cwe": "CWE-1035"},
}

_DEFAULT = {"api": "API8:2023", "web": "A05:2021", "cwe": "CWE-16"}

_API_RE = re.compile(r"(API\d{1,2}:2023)")
_WEB_RE = re.compile(r"(A\d{1,2}:2021)")
_CWE_RE = re.compile(r"(CWE-\d+)")


def api_label(api_id: str) -> str:
    name = OWASP_API_2023.get(api_id, "")
    return f"{api_id} {name}".strip()


def web_label(web_id: str) -> str:
    name = OWASP_WEB_2021.get(web_id, "")
    return f"{web_id} {name}".strip()


def threat_for(finding: Dict[str, Any]) -> Dict[str, str]:
    """Build a threat block for one finding, honoring any ids it already carries."""
    cls = (finding.get("class") or "").strip().lower()
    base = CLASS_MAP.get(cls, _DEFAULT)
    api, web, cwe = base["api"], base["web"], base["cwe"]

    existing_owasp = str(finding.get("owasp") or "")
    if (m := _API_RE.search(existing_owasp)):
        api = m.group(1)
    if (m := _WEB_RE.search(existing_owasp)):
        web = m.group(1)
    existing_cwe = str(finding.get("cwe") or "")
    if (m := _CWE_RE.search(existing_cwe)):
        cwe = m.group(1)

    return {
        "owasp_api": api,
        "owasp_api_name": OWASP_API_2023.get(api, ""),
        "owasp_web": web,
        "owasp_web_name": OWASP_WEB_2021.get(web, ""),
        "cwe": cwe,
        "cwe_name": CWE_NAMES.get(cwe, ""),
    }


def enrich(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach a `threat` block to each finding and normalize `owasp`/`cwe`."""
    for f in findings:
        t = threat_for(f)
        f["threat"] = t
        f["owasp"] = api_label(t["owasp_api"])
        f["cwe"] = t["cwe"]
    return findings


def api_summary(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Counts per OWASP API Top 10 (2023) category, in canonical order."""
    counts: Counter = Counter()
    for f in findings:
        api = (f.get("threat") or {}).get("owasp_api") or threat_for(f)["owasp_api"]
        counts[api] += 1
    out = []
    for api_id, name in OWASP_API_2023.items():
        if counts.get(api_id):
            out.append({"id": api_id, "name": name, "count": counts[api_id]})
    return out
