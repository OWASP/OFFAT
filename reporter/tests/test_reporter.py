"""Offline tests for the reporter (Bundle -> reports)."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("reporter", "triager"):
    sys.path.insert(0, os.path.join(ROOT, p))

from offat_report import render  # noqa: E402


def bundle():
    return {
        "schema_version": "1.0",
        "meta": {"version": "2.0.0", "run_id": "r1", "generated_at": "2026-01-01T00:00:00Z",
                 "target": {"source_path": "./repo"},
                 "stages": [{"name": "map"}, {"name": "triage"}]},
        "threat_model": {"dfd_mermaid": "graph LR\n  client --> ep_1"},
        "summary": {"endpoints": 2, "test_cases": 5, "executions": 5, "threats": 3,
                    "findings": 2, "by_severity": {"high": 1, "medium": 1},
                    "by_owasp_api": {"API8:2023": 1, "API1:2023": 1}},
        "findings": [
            {"id": "f1", "class": "sqli", "vector_id": "sqli-error", "title": "SQLi on GET /search",
             "severity": "high", "endpoint": "ep-1", "payload": "'", "source_mode": "dast",
             "threat": {"owasp_api": "API8:2023", "owasp_api_name": "Security Misconfiguration",
                        "cwe": "CWE-89", "cwe_name": "SQL Injection"},
             "evidence": {"matched_signature": "sql error signature"},
             "triage": {"verdict": "confirmed", "cvss": 8.1, "remediation": "Use parameterized queries."}},
            {"id": "f2", "class": "bola", "vector_id": "sast-bola", "title": "IDOR",
             "severity": "medium", "file": "views.py", "line": 10, "source_mode": "sast",
             "threat": {"owasp_api": "API1:2023", "owasp_api_name": "Broken Object Level Authorization",
                        "cwe": "CWE-639", "cwe_name": "Authorization Bypass"},
             "triage": {"verdict": "likely", "cvss": 6.5}},
        ],
    }


class TestRender(unittest.TestCase):
    def test_sarif(self):
        doc = render.sarif(bundle())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 2)
        self.assertTrue(doc["runs"][0]["tool"]["driver"]["rules"])

    def test_markdown(self):
        md = render.markdown(bundle())
        self.assertIn("SQLi on GET /search", md)
        self.assertIn("OWASP API Top 10", md)

    def test_html_has_dfd_and_findings(self):
        h = render.html_report(bundle())
        self.assertTrue(h.startswith("<!doctype html>"))
        self.assertIn("class='mermaid'", h)
        self.assertIn("SQLi on GET /search", h)

    def test_compliance_lists_all_categories(self):
        c = render.compliance(bundle())
        self.assertIn("API1:2023", c)
        self.assertIn("API10:2023", c)
        self.assertIn("FAIL", c)  # API8 + API1 have findings

    def test_cli_writes_files(self):
        from offat_report import cli
        with tempfile.TemporaryDirectory() as d:
            bpath = os.path.join(d, "b.offat.json")
            with open(bpath, "w") as fh:
                json.dump(bundle(), fh)
            out = os.path.join(d, "reports")
            rc = cli.main([bpath, "-o", out, "--formats", "sarif,md,html,compliance"])
            self.assertEqual(rc, 0)
            for name in ("results.sarif", "report.md", "report.html", "compliance.md"):
                self.assertTrue(os.path.exists(os.path.join(out, name)), name)


if __name__ == "__main__":
    unittest.main()
