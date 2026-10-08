"""Offline tests for the white-box upgrades: JUnit, fail-on, cache, trace no-op."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in ("whitebox", "triager"):
    sys.path.insert(0, os.path.join(ROOT, p))

from offat_wb import report, trace  # noqa: E402
from offat_wb.tools import ToolStatus  # noqa: E402
from offat_triage import tiered_triage  # noqa: E402


def _findings():
    return [
        {"id": "1", "vector_id": "sink-sql", "class": "sqli", "title": "SQLi",
         "severity": "high", "cwe": "CWE-89", "owasp": "A03", "file": "a.py",
         "line": 8, "confidence": 0.9, "evidence": {}},
        {"id": "2", "vector_id": "secret", "class": "secrets", "title": "Secret",
         "severity": "medium", "cwe": "CWE-798", "owasp": "A07", "file": "b.py",
         "line": 2, "confidence": 0.3, "evidence": {}},
    ]


class TestReportParity(unittest.TestCase):
    def _report(self):
        findings = _findings()
        tiered_triage(findings, tempfile.mkdtemp(), use_ai=False)
        return report.build_report(".", findings, {"languages": {"python": 1},
                                   "manifests": [], "sbom_components": 0},
                                   "heuristic", ToolStatus())

    def test_junit_written_and_valid(self):
        rep = self._report()
        with tempfile.TemporaryDirectory() as out:
            report.write_all(out, rep)
            p = os.path.join(out, "report.junit.xml")
            self.assertTrue(os.path.exists(p))
            import xml.dom.minidom as md
            md.parse(p)  # valid XML

    def test_count_at_or_above(self):
        rep = self._report()
        self.assertGreaterEqual(report.count_at_or_above(rep, "high"), 1)
        self.assertEqual(report.count_at_or_above(rep, ""), 0)
        self.assertEqual(report.count_at_or_above(rep, "bogus"), 0)


class TestCache(unittest.TestCase):
    def test_second_run_is_cached(self):
        findings = _findings()
        with tempfile.TemporaryDirectory() as out:
            s1 = tiered_triage(findings, out, use_ai=False, cache_enabled=True)
            self.assertEqual(s1, "heuristic")
            findings2 = _findings()
            s2 = tiered_triage(findings2, out, use_ai=False, cache_enabled=True)
            self.assertTrue(s2.startswith("cached"), s2)


class TestTraceNoGraft(unittest.TestCase):
    def test_noop_without_graft(self):
        findings = _findings()
        status = ToolStatus()
        orig = trace.tools.have
        trace.tools.have = lambda name: False  # force graft absent
        try:
            out = trace.trace(".", findings, status)
        finally:
            trace.tools.have = orig
        self.assertEqual(len(out), 2)
        self.assertFalse(status.available.get("graft", True) and status.available.get("graft") is True)
        for f in out:
            self.assertNotIn("traced", f)  # untouched when graft absent


if __name__ == "__main__":
    unittest.main()
