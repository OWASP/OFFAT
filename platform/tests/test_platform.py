"""Offline tests for the platform mapping + PRG stages."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("bundle", "triager", "whitebox", "graybox", "platform"):
    sys.path.insert(0, os.path.join(ROOT, p))

import offat_bundle as ob  # noqa: E402
from offat_platform import mapping, prg, threat_model  # noqa: E402

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/users": {
            "post": {
                "operationId": "create_user",
                "responses": {"201": {"content": {"application/json": {
                    "schema": {"type": "object", "properties": {
                        "id": {"type": "integer"}, "name": {"type": "string"}}}}}}},
            }
        },
        "/users/{id}": {
            "get": {
                "operationId": "get_user",
                "parameters": [{"name": "id", "in": "path", "required": True,
                                "schema": {"type": "integer"}}],
                "responses": {"200": {"content": {"application/json": {
                    "schema": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}},
            }
        },
    },
}

VIEWS = ("def get_user(id):\n"
         "    cur.execute(\"SELECT * FROM users WHERE id='%s'\" % id)  # sqli\n")


def _fixture(d):
    with open(os.path.join(d, "openapi.json"), "w") as fh:
        json.dump(SPEC, fh)
    with open(os.path.join(d, "views.py"), "w") as fh:
        fh.write(VIEWS)


class TestMapping(unittest.TestCase):
    def test_asm_inventory_and_params(self):
        with tempfile.TemporaryDirectory() as d:
            _fixture(d)
            b = ob.new_bundle(target={"source_path": d})
            mapping.map_target(b, d, use_graft=False)
            eps = b["asm"]["endpoints"]
            self.assertEqual(len(eps), 2)
            get_user = next(e for e in eps if e["path"] == "/users/{id}")
            self.assertTrue(any(p["name"] == "id" and p["location"] == "path"
                                for p in get_user["params"]))
            self.assertTrue(get_user["responses"])  # response fields captured
            self.assertTrue(b["inventory"]["sinks"])      # SQLi sink
            self.assertTrue(b["inventory"]["sources"])    # request params as sources
            self.assertEqual(b["meta"]["stages"][-1]["name"], "map")


class TestPRG(unittest.TestCase):
    def test_producer_consumer_edge(self):
        with tempfile.TemporaryDirectory() as d:
            _fixture(d)
            b = ob.new_bundle(target={"source_path": d})
            mapping.map_target(b, d, use_graft=False)
            stats = prg.build(b)
            self.assertGreater(stats["producers"], 0)
            self.assertGreater(stats["consumers"], 0)
            # POST /users returns id -> GET /users/{id} consumes id: at least one edge.
            self.assertGreater(stats["edges"], 0)
            bases = {e["basis"] for e in b["prg"]["edges"]}
            self.assertTrue({"exact-name", "resource-id"} & bases)

    def test_bundle_valid_after_map_and_prg(self):
        with tempfile.TemporaryDirectory() as d:
            _fixture(d)
            b = ob.new_bundle(target={"source_path": d})
            mapping.map_target(b, d, use_graft=False)
            prg.build(b)
            self.assertEqual(ob.validate_bundle(b), [])
            self.assertEqual(ob.cross_refs(b), [])


class TestThreatModel(unittest.TestCase):
    def test_threats_assets_dfd(self):
        with tempfile.TemporaryDirectory() as d:
            _fixture(d)
            b = ob.new_bundle(target={"source_path": d})
            mapping.map_target(b, d, use_graft=False)
            prg.build(b)
            stats = threat_model.build(b)
            tm = b["threat_model"]
            self.assertGreater(stats["threats"], 0)
            self.assertTrue(tm["assets"])
            self.assertTrue(tm["dfd_mermaid"].startswith("graph LR"))
            # the SQLi sink yields a Tampering threat mapped to an OWASP API cat + CWE.
            sqli = next(t for t in tm["threats"] if "sqli" in t["title"])
            self.assertEqual(sqli["stride"], "Tampering")
            self.assertTrue(sqli["owasp_api"].startswith("API"))
            self.assertIn(sqli["risk"], ("critical", "high", "medium", "low"))
            self.assertEqual(ob.validate_bundle(b), [])


if __name__ == "__main__":
    unittest.main()
