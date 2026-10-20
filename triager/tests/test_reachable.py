"""The shared reachable-only triage policy (gray-box / whitebox --reachable-only)."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

from offat_triage import reachable_triage  # noqa: E402


def _findings():
    return [
        {"id": "1", "class": "sqli", "severity": "high", "confidence": 0.9,
         "reachable": True, "reachable_from": ["GET /search"], "evidence": {}},
        {"id": "2", "class": "deserialization", "severity": "critical", "confidence": 0.9,
         "reachable": False, "evidence": {}},
    ]


class TestReachableTriage(unittest.TestCase):
    def test_unreachable_capped_reachable_triaged(self):
        findings = _findings()
        with tempfile.TemporaryDirectory() as out:
            label = reachable_triage(findings, out, use_ai=False, note="Nothing reaches this.")
        self.assertIn("[reachable 1/2]", label)
        reach, unreach = findings[0], findings[1]
        # Reachable: triaged by the heuristic (no AI), verdict not forced to inconclusive.
        self.assertEqual(reach["triage"]["source"], "heuristic")
        # Unreachable: triaged offline, capped, and annotated.
        self.assertEqual(unreach["triage"]["source"], "heuristic:unreachable")
        self.assertIn(unreach["triage"]["verdict"], ("inconclusive", "false_positive", "info"))
        self.assertIn("Nothing reaches this.", unreach["triage"]["rationale"])

    def test_all_unreachable_spends_nothing(self):
        findings = [dict(f, reachable=False) for f in _findings()]
        with tempfile.TemporaryDirectory() as out:
            label = reachable_triage(findings, out, use_ai=False)
        self.assertIn("[reachable 0/2]", label)
        self.assertTrue(all(f["triage"]["source"] == "heuristic:unreachable" for f in findings))


if __name__ == "__main__":
    unittest.main()


class TestComplete(unittest.TestCase):
    def test_no_backend_returns_none(self):
        from offat_triage import complete
        self.assertIsNone(complete("anything", use_ai=False))
        self.assertIsNone(complete("anything", provider="heuristic"))

    def test_cli_backend_returns_text(self):
        import offat_triage.triager as T
        from offat_triage import complete
        import subprocess

        class _CLI:
            base_cmd = ["claude", "-p"]
            timeout = 60
        orig_make, orig_run = T.make_triager, subprocess.run
        T.make_triager = lambda provider=None, use_ai=True: _CLI()
        subprocess.run = lambda *a, **k: type("P", (), {"returncode": 0, "stdout": "OK-RESULT"})()
        try:
            self.assertEqual(complete("gen", provider="claude-code"), "OK-RESULT")
        finally:
            T.make_triager, subprocess.run = orig_make, orig_run
