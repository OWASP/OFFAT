"""Code-graph taint engine: recall on planted vulns, silence on their safe twins."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in ("whitebox", "triager"):
    sys.path.insert(0, os.path.join(ROOT, p))

from offat_wb import cpg  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "taint_app")

HAVE_TS = importlib.util.find_spec("tree_sitter_language_pack") is not None


@unittest.skipUnless(cpg.AVAILABLE, "networkx not installed")
class TestTaintEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.res = cpg.analyze(FIXTURE)
        cls.hits = {(f["file"], f["line"], f["class"]) for f in cls.res.findings}
        cls.by_route = {}
        for f in cls.res.findings:
            for r in f.get("reachable_from", []):
                cls.by_route.setdefault(r, set()).add(f["class"])

    def assertRoute(self, route, cls):
        self.assertIn(cls, self.by_route.get(route, set()), f"{cls} not found for {route}")

    def assertNoRoute(self, route):
        self.assertNotIn(route, self.by_route, f"unexpected finding for safe route {route}")

    def test_python_interprocedural_flows(self):
        self.assertIn(("pkg/db.py", 19, "sqli"), self.hits)          # two calls from the route
        self.assertRoute("GET /search", "sqli")
        self.assertIn(("pkg/shell.py", 10, "command_injection"), self.hits)   # via self.host field
        self.assertRoute("POST /ping", "command_injection")

    def test_python_sink_classes(self):
        for route, cls in [("GET /files/<name>", "path_traversal"), ("GET /fetch", "ssrf"),
                           ("GET /next", "open_redirect"), ("GET /hello", "ssti"),
                           ("POST /import", "deserialization"), ("POST /users", "mass_assignment"),
                           ("GET /lookup", "sqli"), ("POST /config", "deserialization")]:
            self.assertRoute(route, cls)

    def test_safe_twins_are_silent(self):
        for route in ("GET /search-safe", "GET /files-safe/<name>", "GET /count/<int:n>", "GET /calc",
                      "GET /strip", "GET /my-orders/<order_id>", "GET /receipts/<order_id>",
                      "GET /items/{item_id}", "POST /config-safe", "POST /convert"):
            self.assertNoRoute(route)

    def test_matched_call_return(self):
        # lookup() is called with tainted data and with a constant; only the constant result
        # reaches os.system, so a context-insensitive engine would false-positive here.
        self.assertFalse([f for f in self.res.findings if f["file"] == "flask_app.py" and f["line"] == 85])

    def test_bola_needs_missing_ownership(self):
        bola = [f for f in self.res.findings if f["class"] == "bola"]
        self.assertEqual([f["reachable_from"] for f in bola], [["GET /orders/<order_id>"]])
        self.assertTrue(bola[0]["evidence"]["authz"]["auth"])

    def test_finding_carries_path_and_param(self):
        f = next(f for f in self.res.findings if f["file"] == "pkg/db.py")
        kinds = [h["kind"] for h in f["evidence"]["path"]]
        self.assertEqual(kinds[0], "source")
        self.assertEqual(kinds[-1], "arg")
        self.assertEqual(f["param"], "q")
        self.assertEqual(f["technique"], "taint-graph")

    @unittest.skipUnless(HAVE_TS, "tree-sitter not installed")
    def test_javascript(self):
        for route, cls in [("GET /ping", "command_injection"), ("GET /file", "path_traversal"),
                           ("GET /user", "sqli"), ("GET /proxy", "ssrf"), ("GET /greet", "xss")]:
            self.assertRoute(route, cls)
        self.assertNoRoute("GET /file-safe")
        self.assertNoRoute("GET /greet-num")
        self.assertIn(("jsdb.js", 5, "sqli"), self.hits)   # cross-module require()


@unittest.skipUnless(cpg.AVAILABLE, "networkx not installed")
class TestSpecsAndPatterns(unittest.TestCase):
    def test_custom_spec_adds_sink(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.py"), "w") as fh:
                fh.write("from flask import Flask, request\nfrom internal import dbx\napp = Flask(__name__)\n\n"
                         "@app.get('/q')\ndef q():\n    return dbx.raw_exec(request.args['s'])\n")
            self.assertFalse(cpg.analyze(d).findings)
            spec = os.path.join(d, "specs.json")
            with open(spec, "w") as fh:
                json.dump({"sinks": [{"vclass": "sqli", "cwe": "CWE-89", "names": ["internal.dbx.raw_exec"]}]}, fh)
            res = cpg.analyze(d, spec_file=spec)
            self.assertEqual([f["class"] for f in res.findings], ["sqli"])

    def test_pattern_merge_dedupes_and_demotes(self):
        res = cpg.analyze(FIXTURE)
        proven = next(f for f in res.findings if f["file"] == "pkg/db.py")
        dup = {"vector_id": "sink-sql-format", "class": "sqli", "file": "pkg/db.py",
               "line": proven["line"], "confidence": 0.5, "source_tool": "builtin", "evidence": {}}
        with open(os.path.join(FIXTURE, "flask_app.py")) as fh:
            dead_line = next(i for i, ln in enumerate(fh, 1) if "pickle.loads(fh.read())" in ln)
        orphan = {"vector_id": "deser-pickle", "class": "deserialization", "file": "flask_app.py",
                  "line": dead_line, "confidence": 0.7, "source_tool": "builtin", "evidence": {}}
        merged = cpg.merge_with_patterns(res.graph, res.findings, [dup, orphan])
        self.assertNotIn(dup, merged)
        self.assertIn(orphan, merged)
        self.assertLess(orphan["confidence"], 0.7)
        self.assertFalse(orphan["reachable"])

    def test_frontier_and_spec_file(self):
        from offat_wb.cpg import infer
        res = cpg.analyze(FIXTURE)
        items = infer.frontier(res.graph)
        self.assertTrue(any(i["callee"] == "os.path.join" for i in items))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.json")
            spec = infer.to_spec_file([{"callee": "x.run", "role": "sink", "class": "command_injection",
                                        "confidence": 0.9, "arg_positions": [0], "lang": "py"},
                                       {"callee": "x.clean", "role": "sanitizer", "sanitizes": ["xss"],
                                        "confidence": 0.3}], p)
            self.assertEqual(len(spec["sinks"]), 1)
            self.assertEqual(spec["sanitizers"], [])   # below the confidence floor
            from offat_wb.cpg import specs
            self.assertEqual(specs.load_extra_specs(p)["sinks"][0].names, ("x.run",))


@unittest.skipUnless(cpg.AVAILABLE, "networkx not installed")
class TestAgent(unittest.TestCase):
    def test_tools_are_confined_to_repo(self):
        from offat_wb.cpg.agent import GraphTools
        res = cpg.analyze(FIXTURE)
        t = GraphTools(res.graph, FIXTURE)
        self.assertIn("outside", t.dispatch("read_lines", {"file": "../../../etc/passwd", "start": 1, "end": 5}))
        self.assertIn("def find_user_by_name", t.dispatch("get_function", {"name": "find_user_by_name"}))
        self.assertIn("ENTRY", t.dispatch("callers", {"name": "find_user_by_name"}))
        self.assertIn("request.args", t.dispatch("flows_into", {"file": "pkg/db.py", "line": 11}))

    def test_tool_loop_with_fake_transport(self):
        from offat_wb.cpg.agent import AgentVerifier, agent_verify
        res = cpg.analyze(FIXTURE)
        calls = []

        def transport(payload):
            calls.append(payload)
            if len(calls) == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "t1", "name": "get_function", "input": {"name": "run_query"}}]}
            # the tool result must have been sent back before the verdict
            last = payload["messages"][-1]["content"][0]
            assert last["type"] == "tool_result" and "def run_query" in last["content"]
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t2", "name": "submit_verdict", "input": {
                    "verdict": "confirmed", "confidence": 0.9, "severity": "high", "rationale": "r",
                    "remediation": "use parameters", "poc": {"method": "GET", "path": "/search",
                                                             "query": "q=' OR 1=1--", "body": ""}}}]}

        v = AgentVerifier(res.graph, FIXTURE, api_key="k", transport=transport)
        target = [f for f in res.findings if f["file"] == "pkg/db.py"]
        self.assertEqual(agent_verify(target, v, limit=1), 1)
        self.assertEqual(target[0]["triage"]["verdict"], "confirmed")
        self.assertEqual(target[0]["poc"]["path"], "/search")
        self.assertEqual(calls[0]["model"], "claude-opus-5-5")


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(cpg.AVAILABLE, "networkx not installed")
class TestCLIAgent(unittest.TestCase):
    def _finding(self):
        res = cpg.analyze(FIXTURE)
        return res, next(f for f in res.findings if f["file"] == "pkg/db.py")

    def test_cli_verifier_parses_verdict(self):
        from offat_wb.cpg.agent import CLIAgentVerifier
        res, finding = self._finding()
        calls = {}

        def runner(cmd, cwd):
            calls["cwd"] = cwd
            calls["prompt"] = cmd[-1]
            # A real CLI often wraps JSON in prose / fences.
            return 0, ('Here is my verdict:\n```json\n'
                       '{"verdict":"confirmed","confidence":0.9,"severity":"high",'
                       '"rationale":"concatenated SQL","remediation":"parameterize",'
                       '"poc":{"method":"GET","path":"/search","query":"q=1","body":""}}\n```')

        v = CLIAgentVerifier(res.graph, FIXTURE, ["claude", "-p"], "claude-code", runner=runner)
        verdict = v.verify(finding)
        self.assertEqual(verdict["verdict"], "confirmed")
        self.assertEqual(verdict["source"], "agent:claude-code")
        self.assertEqual(verdict["poc"]["path"], "/search")
        self.assertEqual(os.path.realpath(calls["cwd"]), os.path.realpath(FIXTURE))
        self.assertIn("pkg/db.py", calls["prompt"])  # the proven path reached the CLI

    def test_cli_verifier_nonzero_exit_is_none(self):
        from offat_wb.cpg.agent import CLIAgentVerifier
        res, finding = self._finding()
        v = CLIAgentVerifier(res.graph, FIXTURE, ["claude", "-p"], "claude-code",
                             runner=lambda cmd, cwd: (1, "error"))
        self.assertIsNone(v.verify(finding))

    def test_factory_prefers_api_then_cli_then_none(self):
        from offat_wb.cpg.agent import AgentVerifier, make_agent_verifier
        res, _ = self._finding()
        # heuristic disables the agent regardless of environment.
        self.assertIsNone(make_agent_verifier(res.graph, FIXTURE, provider="heuristic"))
        # With no API key and no CLI available, auto yields nothing.
        orig = AgentVerifier.from_env
        AgentVerifier.from_env = classmethod(lambda cls, cg, root: None)
        try:
            # claude-code requested but (in CI) not installed -> None, no crash.
            v = make_agent_verifier(res.graph, FIXTURE, provider="claude-code")
            self.assertTrue(v is None or v.__class__.__name__ == "CLIAgentVerifier")
        finally:
            AgentVerifier.from_env = orig


@unittest.skipUnless(cpg.AVAILABLE, "networkx not installed")
class TestCLIInfer(unittest.TestCase):
    def test_classify_cli_parses_array(self, ):
        from offat_wb.cpg import infer
        import subprocess
        items = [{"callee": "dbx.raw", "lang": "py", "examples": ["a.py:1 dbx.raw(x)"], "arg_positions": [0]}]
        fake = '[{"callee":"dbx.raw","role":"sink","class":"sqli","cwe":"CWE-89","severity":"high","arg_positions":[0],"confidence":0.9}]'

        class _Avail:
            base_cmd = ["claude", "-p"]
            def available(self): return True
        orig_run, orig_cc = subprocess.run, infer.__dict__.get
        import offat_triage.cli_providers as clip
        oc, ox = clip.ClaudeCodeTriager, clip.CodexTriager
        clip.ClaudeCodeTriager = _Avail
        subprocess.run = lambda *a, **k: type("P", (), {"returncode": 0, "stdout": fake})()
        try:
            out = infer.classify(items, provider="claude-code")
        finally:
            subprocess.run = orig_run
            clip.ClaudeCodeTriager, clip.CodexTriager = oc, ox
        self.assertEqual(out[0]["callee"], "dbx.raw")
        self.assertEqual(out[0]["role"], "sink")


@unittest.skipUnless(cpg.AVAILABLE, "networkx not installed")
class TestClassLevelAuth(unittest.TestCase):
    def _graph(self, perm_line):
        from offat_wb.cpg.graph import CodeGraph
        cg = CodeGraph()
        cg.lines["v.py"] = [
            "class OrderViewSet(GenericViewSet):\n",
            f"    {perm_line}\n",
            "    def retrieve(self, request, pk=None):\n",
            "        return Order.objects.get(id=pk)\n",
        ]
        cg.node("fn:v:OrderViewSet.retrieve", "function", name="retrieve",
                qualname="OrderViewSet.retrieve", file="v.py", line=3, end_line=4,
                cls="OrderViewSet", fn="fn:v:OrderViewSet.retrieve", decorators=[])
        cg.node("a:x", "arg", file="v.py", line=4, fn="fn:v:OrderViewSet.retrieve")
        return cg

    def test_permission_classes_counts_as_auth(self):
        from offat_wb.cpg import taint
        cg = self._graph("permission_classes = [HasAPIKey]")
        self.assertIn("permission_classes", taint._class_auth_text(cg, "fn:v:OrderViewSet.retrieve"))
        ctx = taint._authz_context(cg, {"sink_node": "a:x", "sources": []}, ["fn:v:OrderViewSet.retrieve"])
        self.assertTrue(ctx["class_guarded"])
        self.assertTrue(ctx["auth"])

    def test_allow_any_is_not_a_guard(self):
        from offat_wb.cpg import taint
        cg = self._graph("permission_classes = [AllowAny]")
        ctx = taint._authz_context(cg, {"sink_node": "a:x", "sources": []}, ["fn:v:OrderViewSet.retrieve"])
        self.assertFalse(ctx["class_guarded"])

    def test_custom_permission_class(self):
        from offat_wb.cpg import taint
        cg = self._graph("permission_classes = [IsAuthenticated, IsOrgMember]")
        ctx = taint._authz_context(cg, {"sink_node": "a:x", "sources": []}, ["fn:v:OrderViewSet.retrieve"])
        self.assertTrue(ctx["class_guarded"])
