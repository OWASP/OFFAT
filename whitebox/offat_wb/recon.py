"""Stage 1 — Recon.

Detects the technology stack, inventories dependency manifests, and (when the
tools are installed) generates an SBOM with syft and CVE findings with grype /
trivy / osv-scanner. Everything degrades gracefully.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any, Dict, List

from . import tools
from .hunt import iter_source_files

_MANIFESTS = {
    "requirements.txt": "python", "pyproject.toml": "python", "Pipfile": "python",
    "package.json": "node", "yarn.lock": "node", "pnpm-lock.yaml": "node",
    "go.mod": "go", "Cargo.toml": "rust", "pom.xml": "java", "build.gradle": "java",
    "Gemfile": "ruby", "composer.json": "php", "Dockerfile": "docker",
}

_EXT_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
    ".tsx": "typescript", ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java",
    ".cs": "c#", ".rs": "rust", ".kt": "kotlin", ".c": "c", ".cpp": "c++",
}


def recon(root: str, status) -> Dict[str, Any]:
    langs: Counter = Counter()
    for _, ext in iter_source_files(root):
        if ext in _EXT_LANG:
            langs[_EXT_LANG[ext]] += 1

    manifests = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "vendor", ".venv", "venv"}]
        for name in filenames:
            if name in _MANIFESTS:
                manifests.append(os.path.relpath(os.path.join(dirpath, name), root))

    info: Dict[str, Any] = {
        "languages": dict(langs.most_common()),
        "manifests": sorted(set(manifests)),
        "sbom_components": 0,
        "dependency_findings": [],
    }

    # SBOM (syft) + CVEs (grype > trivy > osv-scanner), best effort.
    if status.mark("syft"):
        sbom = tools.run_json(["syft", root, "-o", "syft-json"], timeout=600)
        if isinstance(sbom, dict):
            info["sbom_components"] = len(sbom.get("artifacts", []))
    else:
        status.skip("syft", "not installed")

    info["dependency_findings"] = _cve_scan(root, status)
    return info


def _cve_scan(root: str, status) -> List[Dict[str, Any]]:
    if status.mark("grype"):
        data = tools.run_json(["grype", root, "-o", "json"], timeout=900)
        return _map_grype(data)
    status.skip("grype", "not installed")
    if status.mark("trivy"):
        data = tools.run_json(["trivy", "fs", "--quiet", "--format", "json", root], timeout=900)
        return _map_trivy(data)
    status.skip("trivy", "not installed")
    if status.mark("osv-scanner"):
        data = tools.run_json(["osv-scanner", "--format", "json", "-r", root], timeout=900)
        return _map_osv(data)
    status.skip("osv-scanner", "not installed")
    return []


def _sev(s: str) -> str:
    s = (s or "").lower()
    return s if s in ("critical", "high", "medium", "low") else "medium"


def _map_grype(data) -> List[Dict[str, Any]]:
    out = []
    if not isinstance(data, dict):
        return out
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        out.append(_dep_finding(v.get("id", ""), _sev(v.get("severity")),
                                art.get("name", ""), art.get("version", ""),
                                v.get("description", ""), v.get("urls", [])))
    return out


def _map_trivy(data) -> List[Dict[str, Any]]:
    out = []
    if not isinstance(data, dict):
        return out
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            out.append(_dep_finding(v.get("VulnerabilityID", ""), _sev(v.get("Severity")),
                                    v.get("PkgName", ""), v.get("InstalledVersion", ""),
                                    v.get("Title", ""), [v.get("PrimaryURL", "")]))
    return out


def _map_osv(data) -> List[Dict[str, Any]]:
    out = []
    if not isinstance(data, dict):
        return out
    for res in data.get("results", []) or []:
        for pkg in res.get("packages", []) or []:
            name = pkg.get("package", {}).get("name", "")
            ver = pkg.get("package", {}).get("version", "")
            for v in pkg.get("vulnerabilities", []) or []:
                out.append(_dep_finding(v.get("id", ""), "medium", name, ver,
                                        v.get("summary", ""), []))
    return out


def _dep_finding(cve, sev, pkg, ver, desc, urls) -> Dict[str, Any]:
    return {
        "id": f"dep-{cve}-{pkg}",
        "vector_id": cve or "CVE",
        "class": "vulnerable_dependency",
        "title": f"{cve} in {pkg} {ver}".strip(),
        "severity": sev,
        "cwe": "CWE-1035",
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "file": pkg,
        "line": 0,
        "technique": "sca",
        "confidence": 0.8,
        "code": "",
        "evidence": {"notes": (desc or "")[:400]},
        "references": [u for u in (urls or []) if u],
        "source_tool": "sca",
    }
