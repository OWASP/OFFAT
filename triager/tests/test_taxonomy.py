"""Tests for the shared threat taxonomy (OWASP API/Web Top 10 + CWE)."""

import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "triager"))

from offat_triage import taxonomy  # noqa: E402


class TestTaxonomy(unittest.TestCase):
    def test_all_api_categories_present(self):
        self.assertEqual(len(taxonomy.OWASP_API_2023), 10)
        self.assertEqual(len(taxonomy.OWASP_WEB_2021), 10)
        for i in range(1, 11):
            self.assertIn(f"API{i}:2023", taxonomy.OWASP_API_2023)

    def test_enrich_sets_threat_and_normalizes(self):
        findings = [
            {"class": "sqli", "severity": "high"},
            {"class": "ssrf", "severity": "high"},
            {"class": "access_control", "severity": "high"},
        ]
        taxonomy.enrich(findings)
        sqli = findings[0]
        self.assertEqual(sqli["threat"]["owasp_api"], "API8:2023")
        self.assertEqual(sqli["threat"]["owasp_web"], "A03:2021")
        self.assertEqual(sqli["cwe"], "CWE-89")
        self.assertTrue(sqli["owasp"].startswith("API8:2023 "))
        self.assertEqual(findings[1]["threat"]["owasp_api"], "API7:2023")
        self.assertEqual(findings[2]["threat"]["owasp_api"], "API1:2023")

    def test_existing_ids_are_honored(self):
        # A DAST finding that already carries API5 + CWE-285 keeps them.
        f = {"class": "access_control", "owasp": "API5:2023 Broken Function Level Authorization",
             "cwe": "CWE-285"}
        t = taxonomy.threat_for(f)
        self.assertEqual(t["owasp_api"], "API5:2023")
        self.assertEqual(t["cwe"], "CWE-285")

    def test_api_summary_orders_and_counts(self):
        findings = [{"class": "sqli"}, {"class": "ssrf"}, {"class": "bola"}]
        taxonomy.enrich(findings)
        summary = taxonomy.api_summary(findings)
        ids = [row["id"] for row in summary]
        # Canonical order: API1 before API7 before API8.
        self.assertEqual(ids, ["API1:2023", "API7:2023", "API8:2023"])
        self.assertTrue(all(row["count"] == 1 for row in summary))

    def test_unknown_class_defaults(self):
        t = taxonomy.threat_for({"class": "totally_unknown"})
        self.assertIn(t["owasp_api"], taxonomy.OWASP_API_2023)
        self.assertIn(t["owasp_web"], taxonomy.OWASP_WEB_2021)


if __name__ == "__main__":
    unittest.main()
