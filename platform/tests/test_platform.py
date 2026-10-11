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
from offat_platform import consolidate, mapping, prg, testgen, threat_model  # noqa: E402

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


class TestTestGen(unittest.TestCase):
    def test_rule_cases_and_chain(self):
        with tempfile.TemporaryDirectory() as d:
            _fixture(d)
            b = ob.new_bundle(target={"source_path": d})
            mapping.map_target(b, d, use_graft=False)
            prg.build(b)
            stats = testgen.build(b, use_ai=False)
            cases = b["test_plan"]["cases"]
            self.assertGreater(stats["rule"], 0)
            self.assertEqual(stats["ai"], 0)
            # the id path param should produce sqli cases.
            self.assertTrue(any(c["class"] == "sqli" for c in cases))
            # every case references a real endpoint.
            ep_ids = {e["id"] for e in b["asm"]["endpoints"]}
            self.assertTrue(all(c["endpoint"] in ep_ids for c in cases))
            self.assertEqual(ob.validate_bundle(b), [])
            self.assertEqual(ob.cross_refs(b), [])

    def test_name_hint_selects_ssrf(self):
        with tempfile.TemporaryDirectory() as d:
            import json as _json
            spec = {"openapi": "3.0.0", "paths": {"/fetch": {"get": {
                "operationId": "fetch", "parameters": [
                    {"name": "callback_url", "in": "query", "schema": {"type": "string"}}]}}}}
            with open(os.path.join(d, "openapi.json"), "w") as fh:
                _json.dump(spec, fh)
            b = ob.new_bundle()
            mapping.map_target(b, d, use_graft=False)
            prg.build(b)
            testgen.build(b, use_ai=False)
            classes = {c["class"] for c in b["test_plan"]["cases"]}
            self.assertIn("ssrf", classes)
            self.assertIn("open_redirect", classes)


class TestConsolidate(unittest.TestCase):
    def _bundle_with_result(self):
        b = ob.new_bundle()
        ep = ob.add_endpoint(b, ob.endpoint("GET", "/search",
                                            params=[ob.param("q", "query")]))
        tc = ob.add_test_case(b, ob.test_case(ep, param="q", location="query",
                                              vclass="sqli", technique="error", payload="'"))
        ob.add_execution(b, ob.execution(
            tc, request={"method": "GET", "url": "http://t/search?q='"},
            response={"status": 500, "body_snippet": "You have an error in your SQL syntax"}))
        # a SAST sink too
        ob.add_sink(b, ob.sink("secrets", symbol="cfg", file="config.py", line=3, cwe="CWE-798"))
        return b

    def test_dast_detection_and_sast_merge(self):
        with tempfile.TemporaryDirectory() as out:
            b = self._bundle_with_result()
            summary = consolidate.build(b, out, use_ai=False)
            self.assertGreaterEqual(summary["findings"], 2)  # sqli (dast) + secrets (sast)
            classes = {f["class"] for f in b["findings"]}
            self.assertIn("sqli", classes)
            self.assertIn("secrets", classes)
            sqli = next(f for f in b["findings"] if f["class"] == "sqli")
            self.assertEqual(sqli["source_mode"], "dast")
            self.assertTrue(sqli["threat"]["owasp_api"].startswith("API"))
            self.assertIn("verdict", sqli["triage"])
            self.assertIn("by_owasp_api", summary)
            self.assertEqual(ob.validate_bundle(b), [])

    def test_no_signal_no_finding(self):
        with tempfile.TemporaryDirectory() as out:
            b = ob.new_bundle()
            ep = ob.add_endpoint(b, ob.endpoint("GET", "/ping"))
            tc = ob.add_test_case(b, ob.test_case(ep, vclass="sqli", technique="error", payload="'"))
            ob.add_execution(b, ob.execution(tc, response={"status": 200, "body_snippet": "pong"}))
            summary = consolidate.build(b, out, use_ai=False)
            self.assertEqual(summary["findings"], 0)


if __name__ == "__main__":
    unittest.main()


class TestAccessControlGen(unittest.TestCase):
    def _bundle_and_ids(self):
        b = ob.new_bundle()
        # object endpoint with an id path param, a privileged DELETE, a money param
        ob.add_endpoint(b, ob.endpoint("GET", "/users/{id}", handler="get_user",
                                       params=[ob.param("id", "path", type="integer")]))
        ob.add_endpoint(b, ob.endpoint("DELETE", "/admin/users/{id}", handler="admin_delete",
                                       params=[ob.param("id", "path", type="integer")]))
        ob.add_endpoint(b, ob.endpoint("POST", "/checkout", handler="checkout",
                                       params=[ob.param("price", "body", type="number"),
                                               ob.param("role", "body", type="string")]))
        ids = [
            {"name": "admin", "role": "admin", "headers": {"Authorization": "Bearer A"}, "owns": {}},
            {"name": "userA", "role": "user", "headers": {"Authorization": "Bearer B"}, "owns": {"id": "1"}},
            {"name": "userB", "role": "user", "headers": {"Authorization": "Bearer C"}, "owns": {"id": "2"}},
        ]
        return b, ids

    def test_generates_authz_auth_business_cases(self):
        b, ids = self._bundle_and_ids()
        testgen.build(b, use_ai=False, identities=ids)
        cases = b["test_plan"]["cases"]
        classes = {c["class"] for c in cases}
        for expect in ("broken_auth", "bola", "bfla", "business_logic"):
            self.assertIn(expect, classes, f"missing {expect}")
        # BOLA cases carry a target identity and an owner baseline
        bola = [c for c in cases if c["class"] == "bola"]
        self.assertTrue(bola)
        self.assertTrue(all(c.get("identity") and c.get("baseline_identity") for c in bola))
        # a BOLA case uses an owner's object id as payload
        self.assertTrue(any(c["payload"] in ("1", "2") for c in bola))
        # business logic includes a negative price tamper and a priv-field escalation
        biz = [c for c in cases if c["class"] == "business_logic"]
        self.assertTrue(any(c["param"] == "price" and c["payload"] == "-1" for c in biz))
        self.assertTrue(any(c["technique"] == "priv-field" and c["param"] == "role" for c in biz))

    def test_no_identities_still_generates_noauth(self):
        b, _ = self._bundle_and_ids()
        testgen.build(b, use_ai=False, identities=[])
        classes = {c["class"] for c in b["test_plan"]["cases"]}
        self.assertIn("broken_auth", classes)  # missing-auth needs no creds


class TestAccessControlDetect(unittest.TestCase):
    def test_bola_differential_detected(self):
        import tempfile
        b = ob.new_bundle()
        ep = ob.add_endpoint(b, ob.endpoint("GET", "/users/{id}",
                                            params=[ob.param("id", "path")]))
        tc = ob.add_test_case(b, ob.test_case(ep, param="id", location="path", vclass="bola",
                                              technique="authz-diff", payload="1",
                                              identity="userB", baseline_identity="userA"))
        ob.add_execution(b, ob.execution(
            tc, request={"method": "GET", "url": "http://t/users/1",
                         "identity": "userB", "baseline_identity": "userA"},
            response={"status": 200, "body_snippet": "{\"ssn\":\"secret\"}"}))
        # attach a matching baseline (owner also 200, same body) -> strong BOLA signal
        b["results"]["executions"][0]["baseline"] = {"status": 200, "body_snippet": "{\"ssn\":\"secret\"}"}
        with tempfile.TemporaryDirectory() as out:
            consolidate.build(b, out, use_ai=False)
        bola = [f for f in b["findings"] if f["class"] == "bola"]
        self.assertTrue(bola)
        self.assertEqual(bola[0]["source_mode"], "dast")
        self.assertIn("same", bola[0]["evidence"]["matched_signature"].lower())
        # ownership-dependent -> heuristic must not blindly "confirm"
        self.assertNotEqual(bola[0]["triage"]["verdict"], "confirmed")
        self.assertEqual(bola[0]["threat"]["owasp_api"], "API1:2023")

    def test_broken_auth_detected(self):
        import tempfile
        b = ob.new_bundle()
        ep = ob.add_endpoint(b, ob.endpoint("GET", "/account"))
        tc = ob.add_test_case(b, ob.test_case(ep, vclass="broken_auth", technique="no-auth",
                                              identity="anon"))
        ob.add_execution(b, ob.execution(tc, request={"method": "GET", "url": "http://t/account", "identity": "anon"},
                                         response={"status": 200, "body_snippet": "{\"balance\":100}"}))
        with tempfile.TemporaryDirectory() as out:
            consolidate.build(b, out, use_ai=False)
        ba = [f for f in b["findings"] if f["class"] == "broken_auth"]
        self.assertTrue(ba)
        self.assertEqual(ba[0]["threat"]["owasp_api"], "API2:2023")


class TestMultiProtocolMapping(unittest.TestCase):
    """WebSocket + gRPC surfaces are mapped with the right protocol tag."""

    def test_ws_and_grpc_endpoints(self):
        from offat_gb import graph_map
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "ws_app.py"), "w") as fh:
                fh.write("@app.websocket('/ws/chat')\n"
                         "async def chat(ws):\n    pass\n"
                         "@socketio.on('message')\n"
                         "def on_msg(data):\n    pass\n")
            with open(os.path.join(d, "svc.proto"), "w") as fh:
                fh.write("syntax = \"proto3\";\npackage shop.v1;\n"
                         "service AdminService {\n"
                         "  rpc DeleteUser (Req) returns (Reply);\n"
                         "  rpc GetStats (Req) returns (stream Reply);\n}\n")
            eps = graph_map.native_map(d)
        protos = {e["protocol"] for e in eps}
        self.assertIn("ws", protos)
        self.assertIn("grpc", protos)
        ws_paths = {e["path"] for e in eps if e["protocol"] == "ws"}
        self.assertIn("/ws/chat", ws_paths)
        self.assertIn("/message", ws_paths)
        grpc = {e["path"]: e for e in eps if e["protocol"] == "grpc"}
        self.assertIn("/shop.v1.AdminService/DeleteUser", grpc)
        self.assertEqual(grpc["/shop.v1.AdminService/GetStats"]["method"], "STREAM")


class TestMultiProtocolTestGen(unittest.TestCase):
    def test_ws_and_grpc_cases(self):
        b = ob.new_bundle()
        ob.add_endpoint(b, ob.endpoint("WS", "/ws/chat", protocol="ws"))
        ob.add_endpoint(b, ob.endpoint("UNARY", "/shop.AdminService/DeleteUser", protocol="grpc"))
        idents = [{"name": "admin", "role": "admin", "headers": {"authorization": "a"}},
                  {"name": "user", "role": "user", "headers": {"authorization": "u"}}]
        stats = testgen.build(b, use_ai=False, identities=idents)
        self.assertGreater(stats["websocket"], 0)
        self.assertGreater(stats["grpc"], 0)
        cases = b["test_plan"]["cases"]
        ws = [c for c in cases if c.get("protocol") == "ws"]
        grpc = [c for c in cases if c.get("protocol") == "grpc"]
        self.assertTrue(any(c["class"] == "broken_auth" for c in ws))
        self.assertTrue(any(c["class"] == "xss" for c in ws))
        self.assertTrue(any(c["class"] == "broken_auth" for c in grpc))
        # AdminService + DeleteUser are privileged -> a BFLA case for the user.
        self.assertTrue(any(c["class"] == "bfla" and c.get("identity") == "user" for c in grpc))


class TestMultiProtocolDetect(unittest.TestCase):
    def test_ws_handshake_without_auth(self):
        case = {"id": "tc", "endpoint": "ep", "class": "broken_auth",
                "technique": "no-auth", "protocol": "ws"}
        ex = {"id": "ex", "protocol": "ws", "request": {"url": "wss://t/ws", "identity": "anon"},
              "response": {"connected": True, "handshake_status": 101}}
        f = consolidate._detect(case, ex)
        self.assertIsNotNone(f)
        self.assertEqual(f["protocol"], "ws")
        # a rejected handshake is healthy -> no finding
        ex2 = {"id": "ex", "protocol": "ws", "request": {}, "response": {"connected": False}}
        self.assertIsNone(consolidate._detect(case, ex2))

    def test_grpc_no_auth_and_denied(self):
        case = {"id": "tc", "endpoint": "ep", "class": "broken_auth",
                "technique": "no-auth", "protocol": "grpc"}
        ok = {"id": "ex", "protocol": "grpc", "request": {"method": "/s/M", "identity": "anon"},
              "response": {"connected": True, "grpc_status": "OK", "grpc_code": 0}}
        f = consolidate._detect(case, ok)
        self.assertIsNotNone(f)
        self.assertEqual(f["protocol"], "grpc")
        denied = {"id": "ex", "protocol": "grpc", "request": {},
                  "response": {"connected": True, "grpc_status": "Unauthenticated", "grpc_code": 16}}
        self.assertIsNone(consolidate._detect(case, denied))
        unimpl = {"id": "ex", "protocol": "grpc", "request": {},
                  "response": {"connected": True, "grpc_status": "Unimplemented", "grpc_code": 12}}
        self.assertIsNone(consolidate._detect(case, unimpl))


class TestRunPipeline(unittest.TestCase):
    """The one-shot `run` subcommand chains the whole pipeline."""

    FIX = os.path.join(ROOT, "graybox", "tests", "fixtures", "app")

    def test_source_only_run_produces_findings(self):
        from offat_platform import cli
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "b.offat.json")
            rc = cli.main(["run", self.FIX, "--no-graft", "--no-ai", "--no-report", "-o", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))
            b = json.load(open(out))
            # map -> test-gen -> triage all ran into one bundle
            self.assertGreaterEqual(b["summary"]["endpoints"], 2)
            self.assertIn("test_plan", b)
            self.assertIn("findings", b)

    def test_live_url_requires_authorization(self):
        from offat_platform import cli
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "b.offat.json")
            rc = cli.main(["run", self.FIX, "--no-graft", "--url", "http://localhost:9",
                           "--no-report", "-o", out])
            self.assertEqual(rc, 3)  # gated: no --yes

    def test_fail_on_gate(self):
        from offat_platform import cli
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "b.offat.json")
            rc = cli.main(["run", self.FIX, "--no-graft", "--no-ai", "--no-report",
                           "--fail-on", "high", "-o", out])
            # the fixture yields high-severity SAST findings -> non-zero
            self.assertEqual(rc, 1)
