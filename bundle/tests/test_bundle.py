"""Tests for the OFFAT Bundle package (offline, stdlib)."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "bundle"))

import offat_bundle as ob  # noqa: E402


def sample():
    b = ob.new_bundle(target={"source_path": "./repo"})
    ep = ob.add_endpoint(b, ob.endpoint("GET", "/users/{id}", handler="get_user",
                                        params=[ob.param("id", "path", type="integer")]))
    ob.add_sink(b, ob.sink("sqli", symbol="get_user", file="views.py", line=8, cwe="CWE-89"))
    ob.add_source(b, ob.source("request_param", symbol="get_user", file="views.py", line=7))
    pn = ob.add_prg_node(b, ob.prg_node("producer", ep, "id", "response", "integer"))
    cn = ob.add_prg_node(b, ob.prg_node("consumer", ep, "id", "path", "integer"))
    ob.add_prg_edge(b, ob.prg_edge(pn, cn, confidence=0.9, basis="exact-name", resource="user"))
    ob.add_threat(b, ob.threat("IDOR on get_user", stride="Tampering", endpoint_id=ep,
                               owasp_api="API1:2023", cwe="CWE-639", risk="high"))
    tc = ob.add_test_case(b, ob.test_case(ep, param="id", location="path", vclass="sqli",
                                          technique="error", payload="'", origin="rule"))
    ob.add_execution(b, ob.execution(tc, protocol="http/2",
                                     request={"method": "GET", "url": "/users/1'"},
                                     response={"status": 500}, latency_ms=12.3))
    ob.add_finding(b, {"id": "f1", "class": "sqli", "severity": "high", "endpoint": ep})
    ob.record_stage(b, "map", tool="offat-graybox", version="1.0.0")
    return b, ep, tc


class TestModel(unittest.TestCase):
    def test_ids_are_stable_and_prefixed(self):
        a = ob.endpoint("GET", "/x")
        c = ob.endpoint("GET", "/x")
        self.assertEqual(a["id"], c["id"])
        self.assertTrue(a["id"].startswith("ep-"))
        self.assertNotEqual(ob.sink("sqli", file="a", line=1)["id"],
                            ob.sink("sqli", file="a", line=2)["id"])

    def test_sections_populated(self):
        b, ep, tc = sample()
        self.assertEqual(len(b["asm"]["endpoints"]), 1)
        self.assertEqual(len(b["prg"]["nodes"]), 2)
        self.assertEqual(len(b["prg"]["edges"]), 1)
        self.assertEqual(len(b["results"]["executions"]), 1)
        self.assertEqual(b["meta"]["stages"][0]["name"], "map")


class TestValidate(unittest.TestCase):
    def test_valid_bundle(self):
        b, _, _ = sample()
        self.assertEqual(ob.validate_bundle(b), [])
        self.assertTrue(ob.is_valid(b))

    def test_missing_required(self):
        self.assertTrue(ob.validate_bundle({}))  # no schema_version/meta
        bad = {"schema_version": "1.0", "meta": {}}
        self.assertTrue(ob.validate_bundle(bad))  # meta missing run_id/generated_at

    def test_bad_section_shape(self):
        b, _, _ = sample()
        b["asm"]["endpoints"][0].pop("method")
        probs = ob.validate_bundle(b)
        self.assertTrue(any("method" in p for p in probs), probs)

    def test_cross_refs(self):
        b, _, _ = sample()
        self.assertEqual(ob.cross_refs(b), [])
        b["test_plan"]["cases"][0]["endpoint"] = "ep-does-not-exist"
        self.assertTrue(ob.cross_refs(b))


class TestIO(unittest.TestCase):
    def test_save_load_roundtrip(self):
        b, _, _ = sample()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "run.offat.json")
            ob.save(b, p)
            back = ob.load(p)
            self.assertEqual(back["schema_version"], ob.SCHEMA_VERSION)
            self.assertEqual(len(back["asm"]["endpoints"]), 1)

    def test_merge_unions_by_id_and_concats_stages(self):
        base = ob.new_bundle()
        ob.add_endpoint(base, ob.endpoint("GET", "/a"))
        ob.record_stage(base, "map")
        other = ob.new_bundle()
        ob.add_endpoint(other, ob.endpoint("GET", "/a"))   # same id -> dedup
        ob.add_endpoint(other, ob.endpoint("POST", "/b"))  # new
        ob.record_stage(other, "engine")
        merged = ob.merge(base, other)
        self.assertEqual(len(merged["asm"]["endpoints"]), 2)
        self.assertEqual([s["name"] for s in merged["meta"]["stages"]], ["map", "engine"])


class TestSchemaFile(unittest.TestCase):
    def test_schema_is_valid_json(self):
        s = ob.validate.schema()
        self.assertEqual(s["title"], "OFFAT Bundle")
        self.assertIn("schema_version", s["required"])


if __name__ == "__main__":
    unittest.main()
