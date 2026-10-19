"""Offline tests for the gray-box pipeline. No network, no AI, no graft needed."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in ("graybox", "whitebox", "triager"):
    sys.path.insert(0, os.path.join(ROOT, p))

from offat_gb import analyze, cache, graph_map, reachability, report  # noqa: E402
from offat_wb.tools import ToolStatus  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "app")


class TestEndpointMapping(unittest.TestCase):
    def test_native_map_flask(self):
        eps = graph_map.native_map(FIXTURE)
        paths = {(e["method"], e["path"]) for e in eps}
        self.assertIn(("GET", "/users/<uid>"), paths)
        self.assertIn(("GET", "/echo"), paths)
        handlers = {e["handler"] for e in eps}
        self.assertIn("get_user", handlers)

    def test_no_graft_uses_native(self):
        status = ToolStatus()
        eps = graph_map.map_endpoints(FIXTURE, status, use_graft=False)
        self.assertTrue(eps)
        self.assertFalse(status.available.get("graft"))

    def test_express_patterns(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "server.js"), "w") as fh:
                fh.write("app.get('/health', (req,res)=>res.send('ok'));\n"
                         "router.post('/login', loginHandler);\n")
            eps = graph_map.native_map(d)
            paths = {(e["method"], e["path"]) for e in eps}
            self.assertIn(("GET", "/health"), paths)
            self.assertIn(("POST", "/login"), paths)


class TestSpecMapping(unittest.TestCase):
    def test_openapi_json_spec_endpoints(self):
        import json
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}": {"get": {"operationId": "api.users.get_user"}},
                "/books": {"post": {"operationId": "add_book"}},
            },
        }
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "openapi.json"), "w") as fh:
                json.dump(spec, fh)
            eps = graph_map.native_map(d)
            paths = {(e["method"], e["path"]) for e in eps}
            self.assertIn(("GET", "/users/{id}"), paths)
            self.assertIn(("POST", "/books"), paths)
            handlers = {e["handler"] for e in eps}
            self.assertIn("get_user", handlers)  # operationId last segment

    def test_regex_fallback_spec(self):
        text = ("swagger: '2.0'\npaths:\n  /ping:\n    get:\n      summary: x\n"
                "  /echo:\n    post:\n      summary: y\n")
        eps = graph_map._spec_endpoints_regex(text, "api.yaml")
        paths = {(e["method"], e["path"]) for e in eps}
        self.assertEqual(paths, {("GET", "/ping"), ("POST", "/echo")})


class TestHandlerReachability(unittest.TestCase):
    def test_spec_handler_links_to_sink(self):
        status = ToolStatus()
        with tempfile.TemporaryDirectory() as d:
            # Handler function with a SQLi sink, and a spec that exposes it.
            with open(os.path.join(d, "views.py"), "w") as fh:
                fh.write("def get_user(uid):\n"
                         "    cur.execute(\"SELECT * FROM u WHERE id='%s'\" % uid)\n")
            import json
            with open(os.path.join(d, "openapi.json"), "w") as fh:
                json.dump({"openapi": "3.0.0", "paths": {
                    "/users/{uid}": {"get": {"operationId": "views.get_user"}}}}, fh)
            from offat_wb import hunt
            eps = graph_map.map_endpoints(d, status, use_graft=False)
            findings = hunt.builtin_hunt(d, None)
            findings = reachability.link(d, findings, eps, status)
            sink = next(f for f in findings if f["file"].endswith("views.py"))
            self.assertTrue(sink["reachable"])
            self.assertIn("GET /users/{uid}", sink["reachable_from"])


class TestReachability(unittest.TestCase):
    def test_same_file_reachable_and_orphan_unreachable(self):
        from offat_wb import hunt
        status = ToolStatus()
        eps = graph_map.map_endpoints(FIXTURE, status, use_graft=False)
        findings = hunt.builtin_hunt(FIXTURE, None)
        findings = reachability.link(FIXTURE, findings, eps, status)
        by_file = {f["file"]: f for f in findings}
        # api.py has routes -> its sink is reachable.
        api = next(f for f in findings if f["file"].endswith("api.py"))
        self.assertTrue(api["reachable"])
        self.assertTrue(api["reachable_from"])
        # helpers.py has no routes -> its sink is not reachable.
        helper = next(f for f in findings if f["file"].endswith("helpers.py"))
        self.assertFalse(helper["reachable"])
        self.assertEqual(helper["reachable_from"], [])


class TestAnalyzeHeuristic(unittest.TestCase):
    def test_unreachable_capped_and_cache(self):
        from offat_wb import hunt
        status = ToolStatus()
        eps = graph_map.map_endpoints(FIXTURE, status, use_graft=False)
        findings = hunt.builtin_hunt(FIXTURE, None)
        findings = reachability.link(FIXTURE, findings, eps, status)
        with tempfile.TemporaryDirectory() as out:
            src = analyze.analyze(findings, out, provider=None, use_ai=False, cache_enabled=True)
            self.assertTrue(src.startswith("graybox:"))
            helper = next(f for f in findings if f["file"].endswith("helpers.py"))
            # Unreachable sinks are never confirmed/likely.
            self.assertIn(helper["triage"]["verdict"],
                          ("inconclusive", "false_positive"))
            self.assertEqual(helper["triage"]["source"], "heuristic:unreachable")
            # Cache file written.
            self.assertTrue(os.path.exists(os.path.join(out, ".offat-gb-cache.json")))


class TestCache(unittest.TestCase):
    def test_key_stable_and_roundtrip(self):
        f = {"class": "sqli", "vector_id": "x", "file": "a.py", "line": 3,
             "code": "cur.execute(q)", "reachable_from": ["GET /a"]}
        k1 = cache.finding_key(f)
        k2 = cache.finding_key(dict(f))
        self.assertEqual(k1, k2)
        with tempfile.TemporaryDirectory() as out:
            c = cache.VerdictCache(out, enabled=True)
            self.assertIsNone(c.get(f))
            c.put(f, {"verdict": "confirmed"})
            c.save()
            c2 = cache.VerdictCache(out, enabled=True)
            self.assertEqual(c2.get(f)["verdict"], "confirmed")


class TestReport(unittest.TestCase):
    def _report(self):
        from offat_wb import hunt
        status = ToolStatus()
        eps = graph_map.map_endpoints(FIXTURE, status, use_graft=False)
        findings = hunt.builtin_hunt(FIXTURE, None)
        findings = reachability.link(FIXTURE, findings, eps, status)
        analyze.analyze(findings, tempfile.mkdtemp(), provider=None, use_ai=False)
        return report.build_report(FIXTURE, findings, eps, {"languages": {"python": 1}},
                                   "graybox:heuristic", status)

    def test_build_and_write(self):
        rep = self._report()
        self.assertEqual(rep["mode"], "graybox")
        self.assertEqual(rep["summary"]["endpoints"], len(rep["endpoints"]))
        with tempfile.TemporaryDirectory() as out:
            report.write_all(out, rep)
            for name in ("report.json", "findings.jsonl", "endpoints.json",
                         "results.sarif", "report.md", "report.html", "report.junit.xml"):
                self.assertTrue(os.path.exists(os.path.join(out, name)), name)
            import xml.dom.minidom as md
            md.parse(os.path.join(out, "report.junit.xml"))  # must be valid XML

    def test_fail_on(self):
        rep = self._report()
        # There is at least one high sqli finding (reachable), so high gate fires.
        self.assertGreater(report.count_at_or_above(rep, "high"), 0)
        self.assertEqual(report.count_at_or_above(rep, ""), 0)
        self.assertEqual(report.count_at_or_above(rep, "bogus"), 0)


if __name__ == "__main__":
    unittest.main()
