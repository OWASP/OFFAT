"""Go frontend: tree-sitter -> CodeGraph.

Same graph model as the other frontends (versioned locals, call-site-labelled
arg->param / return->call edges). Go has no exceptions and a clean call/selector
grammar, which suits taint analysis:

* **routes** - ``http.HandleFunc("/p", h)`` / ``mux.HandleFunc`` and router verbs
  ``r.GET("/p", h)`` (gin / echo / chi / fiber) mark their handler as an entry.
* **sources** - request accessors on ``*http.Request`` / the framework context
  (``r.URL.Query().Get``, ``r.FormValue``, ``c.Query``, ``mux.Vars``, ...),
  matched against the flattened selector chain of the call.
* string concatenation (``"..." + x``) propagates taint; ``strconv.Atoi`` and the
  other coercions/sanitizers neutralize it.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Set, Tuple

import tree_sitter_language_pack as tslp

from . import specs
from .graph import CodeGraph

_ROUTE_VERBS = {"handlefunc", "handle", "get", "post", "put", "delete", "patch", "head",
                "options", "any", "all", "add", "method"}


class _GoModule:
    def __init__(self, rel: str, tree: Any, src: bytes) -> None:
        self.rel = rel
        self.tree = tree
        self.src = src
        self.functions: Dict[str, str] = {}       # name -> fid
        self.fn_by_span: Dict[Tuple[int, int], str] = {}
        self.imports: Dict[str, str] = {}          # alias/last -> import path


class GoFrontend:
    lang = "go"

    def __init__(self, root: str, cg: CodeGraph,
                 extra_sinks: Optional[List[specs.SinkSpec]] = None,
                 extra_sanitizers: Optional[List[specs.SanitizerSpec]] = None,
                 extra_sources: Optional[List[str]] = None) -> None:
        self.root = root
        self.cg = cg
        self.sinks = specs.GO_SINKS + [s for s in (extra_sinks or []) if s.lang in ("*", "go")]
        self.sanitizers = specs.GO_SANITIZERS + [s for s in (extra_sanitizers or []) if s.lang in ("*", "go")]
        self.sources = tuple(specs.GO_SOURCES) + tuple(extra_sources or ())
        self.modules: Dict[str, _GoModule] = {}
        self.method_index: Dict[str, List[str]] = {}
        self.fn_nodes: Dict[str, Tuple[_GoModule, Any]] = {}
        self.built: Set[str] = set()
        self.parse_errors: List[str] = []

    # --- parse / index ------------------------------------------------------
    def add_file(self, path: str) -> None:
        rel = os.path.relpath(path, self.root)
        try:
            with open(path, "rb") as fh:
                src = fh.read()
            tree = tslp.get_parser("go").parse(src)
        except Exception as exc:  # noqa: BLE001
            self.parse_errors.append(f"{rel}: {exc}")
            return
        self.cg.lines[rel] = src.decode("utf-8", "ignore").splitlines(keepends=True)
        mod = _GoModule(rel, tree, src)
        self.modules[rel] = mod
        self._index(mod)

    def t(self, mod: _GoModule, n: Any) -> str:
        return mod.src[n.start_byte:n.end_byte].decode("utf-8", "ignore") if n is not None else ""

    def dotted(self, mod: _GoModule, n: Any) -> str:
        """Flatten a selector / identifier / call chain: ``r.URL.Query().Get``."""
        if n is None:
            return ""
        if n.type == "identifier" or n.type == "type_identifier" or n.type == "field_identifier" \
                or n.type == "package_identifier":
            return self.t(mod, n)
        if n.type == "selector_expression":
            op = self.dotted(mod, n.child_by_field_name("operand"))
            fld = self.t(mod, n.child_by_field_name("field"))
            return f"{op}.{fld}" if op else fld
        if n.type == "call_expression":
            return self.dotted(mod, n.child_by_field_name("function")) + "()"
        if n.type == "parenthesized_expression" and n.named_children:
            return self.dotted(mod, n.named_children[0])
        return ""

    def _index(self, mod: _GoModule) -> None:
        root = mod.tree.root_node

        def walk(n: Any) -> None:
            if n.type == "import_spec":
                p = n.child_by_field_name("path") or (n.named_children[-1] if n.named_children else None)
                name_node = n.child_by_field_name("name")
                path = self.t(mod, p).strip('"')
                alias = self.t(mod, name_node) if name_node is not None else path.rsplit("/", 1)[-1]
                mod.imports[alias] = path
            elif n.type in ("function_declaration", "method_declaration"):
                name_node = n.child_by_field_name("name")
                name = self.t(mod, name_node)
                recv = ""
                if n.type == "method_declaration":
                    recv = "(recv)."
                fid = f"fn:{mod.rel}:{name}@{n.start_point[0] + 1}"
                params = self._params(mod, n)
                line = n.start_point[0] + 1
                self.cg.node(fid, "function", name=name, qualname=recv + name, module=mod.rel,
                             file=mod.rel, line=line, end_line=n.end_point[0] + 1, params=params,
                             lang="go", fn=fid, code=self.cg.code_at(mod.rel, line), entry=False,
                             route=None, decorators=[])
                self.cg.node(f"ret:{fid}", "return", fn=fid, file=mod.rel, line=line,
                             code=f"return of {name}()")
                mod.fn_by_span[(n.start_byte, n.end_byte)] = fid
                self.fn_nodes[fid] = (mod, n)
                mod.functions.setdefault(name, fid)
                if n.type == "method_declaration":
                    self.method_index.setdefault(name, []).append(fid)
            for c in n.named_children:
                walk(c)
        walk(root)

    def _params(self, mod: _GoModule, fn: Any) -> List[str]:
        ps = fn.child_by_field_name("parameters")
        out: List[str] = []
        if ps is None:
            return out
        for p in ps.named_children:
            if p.type != "parameter_declaration":
                continue
            names = [self.t(mod, c) for c in p.named_children if c.type == "identifier"]
            out.extend(names or [f"_p{len(out)}"])
        return out

    def _param_type(self, mod: _GoModule, fn: Any, name: str) -> str:
        ps = fn.child_by_field_name("parameters")
        if ps is None:
            return ""
        for p in ps.named_children:
            if p.type != "parameter_declaration":
                continue
            names = [self.t(mod, c) for c in p.named_children if c.type == "identifier"]
            if name in names:
                ty = p.child_by_field_name("type")
                return self.t(mod, ty)
        return ""

    # --- routes -------------------------------------------------------------
    def _mark_routes(self, mod: _GoModule) -> None:
        def walk(n: Any) -> None:
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                if fn is not None and fn.type == "selector_expression" and args is not None:
                    verb = self.t(mod, fn.child_by_field_name("field"))
                    if verb.lower() in _ROUTE_VERBS:
                        a = [c for c in args.named_children]
                        path = ""
                        handler = None
                        for x in a:
                            if x.type in ("interpreted_string_literal", "raw_string_literal") and not path:
                                path = self.t(mod, x).strip('"`')
                            elif x.type in ("identifier", "selector_expression") and handler is None:
                                handler = x
                            elif x.type == "func_literal" and handler is None:
                                handler = x
                        if handler is not None and (path or verb.lower() in ("handlefunc", "handle")):
                            method = "ANY" if verb.lower() in ("handlefunc", "handle") else verb.upper()
                            self._bind_route(mod, handler, method, path)
            for c in n.named_children:
                walk(c)
        walk(mod.tree.root_node)

    def _bind_route(self, mod: _GoModule, handler: Any, method: str, path: str) -> None:
        fid = None
        if handler.type == "func_literal":
            fid = mod.fn_by_span.get((handler.start_byte, handler.end_byte))
            if fid is None:   # inline handler not indexed as a decl: index it now
                fid = f"fn:{mod.rel}:<handler>@{handler.start_point[0] + 1}"
                line = handler.start_point[0] + 1
                self.cg.node(fid, "function", name="<handler>", qualname="<handler>", module=mod.rel,
                             file=mod.rel, line=line, end_line=handler.end_point[0] + 1,
                             params=self._params(mod, handler), lang="go", fn=fid,
                             code=self.cg.code_at(mod.rel, line), decorators=[])
                self.cg.node(f"ret:{fid}", "return", fn=fid, file=mod.rel, line=line)
                mod.fn_by_span[(handler.start_byte, handler.end_byte)] = fid
                self.fn_nodes[fid] = (mod, handler)
        else:
            name = self.dotted(mod, handler).split(".")[-1]
            fid = mod.functions.get(name)
        if fid and fid in self.cg.g:
            d = self.cg.g.nodes[fid]
            d["entry"] = True
            d["route"] = {"method": method, "path": path, "framework": "go"}

    # --- build --------------------------------------------------------------
    def build(self) -> None:
        for mod in self.modules.values():
            self._mark_routes(mod)
        for fid, (mod, n) in list(self.fn_nodes.items()):
            if fid not in self.built:
                _GoBuilder(self, mod, fid, n).run()

    def resolve(self, mod: _GoModule, callee: Any) -> Tuple[List[str], bool]:
        """Resolve a call target to project function node ids."""
        if callee is None:
            return [], False
        if callee.type == "identifier":
            fid = mod.functions.get(self.t(mod, callee))
            return ([fid] if fid else []), False
        if callee.type == "selector_expression":
            meth = self.t(mod, callee.child_by_field_name("field"))
            # same-file method/function first
            fid = mod.functions.get(meth)
            if fid:
                return [fid], False
            cands = self.method_index.get(meth, [])
            return (cands, True) if 0 < len(cands) <= 3 else ([], False)
        return [], False


class _GoBuilder:
    def __init__(self, fe: GoFrontend, mod: _GoModule, fid: str, node: Any) -> None:
        self.fe = fe
        self.cg = fe.cg
        self.mod = mod
        self.fid = fid
        self.node = node
        self.defs: Dict[str, Set[str]] = {}
        self.counter: Dict[str, int] = {}
        self.ret = f"ret:{fid}"
        self._n = 0

    def t(self, n: Any) -> str:
        return self.fe.t(self.mod, n)

    def line(self, n: Any) -> int:
        return n.start_point[0] + 1

    def code(self, ln: int) -> str:
        return self.cg.code_at(self.mod.rel, ln)

    def new_var(self, name: str, ln: int) -> str:
        k = self.counter.get(name, 0) + 1
        self.counter[name] = k
        return self.cg.node(f"v:{self.fid}:{name}#{k}", "var", name=name, fn=self.fid,
                            file=self.mod.rel, line=ln, code=self.code(ln))

    def source(self, label: str, n: Any, param: str = "") -> str:
        ln = self.line(n)
        return self.cg.node(f"src:{self.fid}:{ln}:{n.start_point[1]}:{label}", "source", label=label,
                            fn=self.fid, file=self.mod.rel, line=ln, code=self.code(ln), trust="remote",
                            coerced=False, param=param)

    # --- entry --------------------------------------------------------------
    def run(self) -> None:
        self.fe.built.add(self.fid)
        for p in self.cg.g.nodes[self.fid].get("params", []):
            self.defs[p] = {self.cg.node(f"p:{self.fid}:{p}", "param", name=p, fn=self.fid,
                                         file=self.mod.rel, line=self.cg.g.nodes[self.fid].get("line"),
                                         code="")}
        body = self.node.child_by_field_name("body")
        if body is not None:
            self.walk(body)

    def walk(self, n: Any) -> None:
        for c in n.named_children:
            self.stmt(c)

    def _branch(self, bodies: List[Any], loop: bool = False) -> None:
        before = {k: set(v) for k, v in self.defs.items()}
        merged = {k: set(v) for k, v in before.items()}
        for b in bodies:
            self.defs = {k: set(v) for k, v in before.items()}
            for _ in range(2 if loop else 1):
                if b is not None:
                    self.stmt(b)
            for k, v in self.defs.items():
                merged.setdefault(k, set()).update(v)
        self.defs = merged

    def stmt(self, n: Any) -> None:
        t = n.type
        if t in ("block", "statement_list"):
            self.walk(n)
        elif t == "short_var_declaration":
            self._assign_lists(n.child_by_field_name("left"), n.child_by_field_name("right"))
        elif t == "assignment_statement":
            self._assign_lists(n.child_by_field_name("left"), n.child_by_field_name("right"))
        elif t == "var_declaration":
            for spec in n.named_children:
                if spec.type == "var_spec":
                    val = spec.child_by_field_name("value")
                    name_node = spec.child_by_field_name("name")
                    if val is not None and name_node is not None:
                        vals = set()
                        for e in val.named_children:
                            vals |= self.eval(e)
                        self._bind_name(self.t(name_node), vals, self.line(spec))
        elif t == "expression_statement":
            for c in n.named_children:
                self.eval(c)
        elif t == "return_statement":
            for c in n.named_children:
                for v in self.eval(c):
                    self.cg.flow(v, self.ret)
        elif t == "if_statement":
            init = n.child_by_field_name("initializer")
            if init is not None:
                self.stmt(init)
            self.eval(n.child_by_field_name("condition"))
            self._branch([n.child_by_field_name("consequence"), n.child_by_field_name("alternative")])
        elif t in ("for_statement", "range_clause"):
            for f in ("initializer", "condition", "update"):
                c = n.child_by_field_name(f)
                if c is not None:
                    self.stmt(c) if c.type.endswith("declaration") or c.type.endswith("statement") else self.eval(c)
            self._branch([n.child_by_field_name("body")], loop=True)
        elif t in ("expression_switch_statement", "type_switch_statement"):
            self._branch(list(n.named_children))
        elif t in ("expression_case", "default_case", "communication_case", "type_case"):
            for c in n.named_children:
                self.stmt(c) if c.type.endswith(("statement", "declaration", "list")) else self.eval(c)
        elif t in ("go_statement", "defer_statement", "labeled_statement"):
            for c in n.named_children:
                self.stmt(c) if c.type.endswith(("statement", "list", "block")) else self.eval(c)
        else:
            for c in n.named_children:
                if c.type.endswith(("expression", "literal", "_statement")):
                    self.eval(c) if c.type.endswith(("expression", "literal")) else self.stmt(c)

    def _assign_lists(self, left: Any, right: Any) -> None:
        if left is None or right is None:
            return
        lnodes = [c for c in left.named_children]
        rnodes = [c for c in right.named_children]
        rvals = [self.eval(r) for r in rnodes]
        ln = self.line(left)
        if len(lnodes) == len(rnodes):
            for lnode, vals in zip(lnodes, rvals):
                self._assign_target(lnode, vals, ln)
        else:
            merged: Set[str] = set()
            for v in rvals:
                merged |= v
            for lnode in lnodes:
                self._assign_target(lnode, merged, ln)

    def _assign_target(self, lnode: Any, vals: Set[str], ln: int) -> None:
        if lnode.type == "identifier":
            name = self.t(lnode)
            if name == "_":
                return
            self._bind_name(name, vals, ln)
        elif lnode.type in ("selector_expression", "index_expression"):
            root = lnode
            while root is not None and root.type in ("selector_expression", "index_expression"):
                root = root.child_by_field_name("operand") or root.child_by_field_name("object") \
                    or (root.named_children[0] if root.named_children else None)
            if root is not None and root.type == "identifier" and vals:
                nm = self.t(root)
                old = self.defs.get(nm, set())
                nid = self.new_var(nm, ln)
                for v in old | vals:
                    self.cg.flow(v, nid)
                self.defs[nm] = {nid}

    def _bind_name(self, name: str, vals: Set[str], ln: int) -> None:
        nid = self.new_var(name, ln)
        for v in vals:
            self.cg.flow(v, nid)
        self.defs[name] = {nid}

    # --- expressions --------------------------------------------------------
    def eval(self, n: Any) -> Set[str]:
        if n is None:
            return set()
        t = n.type
        if t == "identifier":
            return set(self.defs.get(self.t(n), set()))
        if t in ("interpreted_string_literal", "raw_string_literal", "int_literal", "float_literal",
                 "true", "false", "nil", "rune_literal", "imaginary_literal"):
            return set()
        if t == "binary_expression":
            op = n.child_by_field_name("operator")
            l = self.eval(n.child_by_field_name("left"))
            r = self.eval(n.child_by_field_name("right"))
            # only concatenation / bitwise-or style ops carry a payload; comparisons do not
            if op is not None and self.t(op) in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return set()
            return l | r
        if t in ("parenthesized_expression", "unary_expression"):
            inner = n.child_by_field_name("operand") or (n.named_children[0] if n.named_children else None)
            return self.eval(inner)
        if t == "selector_expression":
            raw = self.fe.dotted(self.mod, n)
            if specs.any_match(self.fe.sources, raw):
                return {self.source(raw, n)}
            return self.eval(n.child_by_field_name("operand"))
        if t == "index_expression":
            # mux.Vars(r)["id"] - the operand call is already the source
            obj = n.child_by_field_name("operand")
            vals = self.eval(obj)
            self.eval(n.child_by_field_name("index"))
            return vals
        if t == "call_expression":
            return self.call(n)
        if t in ("composite_literal", "func_literal"):
            if t == "func_literal":
                fid = self.mod.fn_by_span.get((n.start_byte, n.end_byte))
                if fid and fid not in self.fe.built:
                    _GoBuilder(self.fe, self.mod, fid, n).run()
                return set()
            out: Set[str] = set()
            for c in n.named_children:
                out |= self.eval(c)
            return out
        out = set()
        for c in n.named_children:
            out |= self.eval(c)
        return out

    def call(self, n: Any) -> Set[str]:
        self._n += 1
        fn = n.child_by_field_name("function")
        args_node = n.child_by_field_name("arguments")
        raw = self.fe.dotted(self.mod, fn)
        ln = self.line(n)
        cid = self.cg.node(f"c:{self.fid}:{ln}:{n.start_point[1]}:{self._n}", "call", callee=raw or "<dyn>",
                           raw=raw, fn=self.fid, file=self.mod.rel, line=ln, code=self.code(ln))
        self.cg.flow(self.fid, cid, kind="contains")

        # receiver (operand of a selector call)
        recv: Set[str] = set()
        if fn is not None and fn.type == "selector_expression":
            recv = self.eval(fn.child_by_field_name("operand"))

        args: List[Tuple[int, str, Set[str]]] = []
        if args_node is not None:
            for i, a in enumerate(c for c in args_node.named_children):
                vals = self.eval(a)
                aid = self.cg.node(f"a:{cid}:{i}", "arg", pos=i, fn=self.fid, file=self.mod.rel,
                                   line=self.line(a), code=self.code(ln), call=cid)
                for v in vals:
                    self.cg.flow(v, aid)
                args.append((i, aid, vals))

        # source call (request accessor)
        if specs.any_match(self.fe.sources, raw):
            p = ""
            if args and args_node.named_children and args_node.named_children[0].type.endswith("literal"):
                p = self.t(args_node.named_children[0]).strip('"`')
            self.cg.flow(self.source(f"{raw}", n, param=p), cid)

        # sinks
        for spec in specs.find_sinks(self.fe.sinks, raw):
            for key, aid, _ in args:
                if spec.any_arg or key in spec.args:
                    self._add_sink(aid, spec, raw)

        # resolve project target
        targets, weak = self.fe.resolve(self.mod, fn)
        san = specs.sanitizer_classes(self.fe.sanitizers, raw)
        if targets:
            for tgt in targets:
                self._bind(cid, tgt, args, weak)
        elif san is not None:
            if specs.ALL not in san:
                for _, aid, _ in args:
                    self.cg.flow(aid, cid, sanitizes=san)
                for r in recv:
                    self.cg.flow(r, cid, sanitizes=san)
        else:
            for _, aid, _ in args:
                self.cg.flow(aid, cid)
            for r in recv:
                self.cg.flow(r, cid)
        return {cid}

    def _add_sink(self, aid: str, spec: specs.SinkSpec, name: str) -> None:
        d = self.cg.g.nodes[aid]
        lst = d.setdefault("sinks", [])
        if not any(x["class"] == spec.vclass for x in lst):
            lst.append({"class": spec.vclass, "cwe": spec.cwe, "severity": spec.severity,
                        "owasp": spec.owasp, "title": spec.title, "sink": name})

    def _bind(self, cid: str, target: str, args, weak: bool) -> None:
        self.cg.flow(self.fid, target, kind="calls", weak=weak)
        td = self.cg.g.nodes[target]
        params = td.get("params", [])
        for key, aid, _ in args:
            if isinstance(key, int) and key < len(params):
                pid = self.cg.node(f"p:{target}:{params[key]}", "param", name=params[key], fn=target,
                                   file=td.get("file"), line=td.get("line"), code=td.get("code"))
                self.cg.flow(aid, pid, kind="call", site=cid, weak=weak)
        self.cg.flow(f"ret:{target}", cid, kind="ret", site=cid, weak=weak)
