"""JavaScript / TypeScript frontend: tree-sitter -> CodeGraph.

Same graph model as the Python frontend (versioned locals, call-site labelled
arg->param / return->call edges), driven by the tree-sitter JS/TS grammars:

* modules are linked through ``require('./x')`` / ``import ... from './x'`` and
  ``module.exports`` / ``exports.f`` / ``export`` declarations;
* Express-style routes (``app.get('/p', handler)``, ``router.post(...)``) mark
  their handler functions as entry points, and the handler's first two params
  are normalized to ``req`` / ``res`` so sources and sinks match whatever the
  author named them;
* inline callbacks are built as closures over the enclosing scope, and an
  unknown library call passes its receiver/args into callback params
  (``rows.map(r => ...)``, ``p.then(v => ...)``).
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import tree_sitter_language_pack as tslp

from . import specs
from .graph import CodeGraph

_FN_TYPES = {"function_declaration", "function_expression", "function", "arrow_function",
             "method_definition", "generator_function_declaration", "generator_function"}
_ROUTE_VERBS = {"get", "post", "put", "delete", "patch", "all", "options", "head"}
_ROUTER_OBJS = re.compile(r"^(app|router|r|api|server|routes|route|v\d|\w*[Rr]outer|\w*[Aa]pp)$")
_CMP_OPS = {"==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in"}
_LITERALS = {"string", "number", "true", "false", "null", "undefined", "regex", "this_type",
             "template_literal_type", "comment"}
_WHOLE_BODY = {"req.body", "request.body", "ctx.request.body", "event.body"}
_RESOLVE_EXTS = ("", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", "/index.js", "/index.ts")


def _lang_for(ext: str) -> str:
    return {".ts": "typescript", ".tsx": "tsx"}.get(ext, "javascript")


class _JSModule:
    def __init__(self, rel: str, tree: Any, src: bytes) -> None:
        self.rel = rel
        self.tree = tree
        self.src = src
        self.imports: Dict[str, Tuple[str, Optional[str]]] = {}  # local -> (module spec, name|None)
        self.functions: Dict[str, str] = {}                       # name -> fid
        self.exports: Dict[str, str] = {}                         # exported name -> fid ("default")
        self.fn_by_span: Dict[Tuple[int, int], str] = {}
        self.classes: Dict[str, Dict[str, str]] = {}              # class -> {method: fid}


class JSFrontend:
    lang = "js"

    def __init__(self, root: str, cg: CodeGraph,
                 extra_sinks: Optional[List[specs.SinkSpec]] = None,
                 extra_sanitizers: Optional[List[specs.SanitizerSpec]] = None,
                 extra_sources: Optional[List[str]] = None) -> None:
        self.root = root
        self.cg = cg
        self.sinks = specs.JS_SINKS + [s for s in (extra_sinks or []) if s.lang in ("*", "js")]
        self.sanitizers = specs.JS_SANITIZERS + [s for s in (extra_sanitizers or []) if s.lang in ("*", "js")]
        self.source_attrs = tuple(specs.JS_SOURCE_ATTRS) + tuple(extra_sources or ())
        self.source_calls = tuple(specs.JS_SOURCE_CALLS)
        self.modules: Dict[str, _JSModule] = {}
        self.method_index: Dict[str, List[str]] = {}
        self.fn_nodes: Dict[str, Tuple[_JSModule, Any, Optional[str]]] = {}
        self.built: Set[str] = set()
        self.parse_errors: List[str] = []

    # --- index ----------------------------------------------------------------
    def add_file(self, path: str) -> None:
        rel = os.path.relpath(path, self.root)
        try:
            with open(path, "rb") as fh:
                src = fh.read()
            tree = tslp.get_parser(_lang_for(os.path.splitext(path)[1].lower())).parse(src)
        except Exception as exc:  # noqa: BLE001 - a broken file must not stop the run
            self.parse_errors.append(f"{rel}: {exc}")
            return
        self.cg.lines[rel] = src.decode("utf-8", "ignore").splitlines(keepends=True)
        mod = _JSModule(rel, tree, src)
        self.modules[rel] = mod
        self._index(mod, tree.root_node, cls=None)
        self._index_imports_exports(mod)

    def text(self, mod: _JSModule, n: Any) -> str:
        return mod.src[n.start_byte:n.end_byte].decode("utf-8", "ignore")

    def _fn_name(self, mod: _JSModule, n: Any, cls: Optional[str]) -> str:
        name_node = n.child_by_field_name("name")
        if name_node is not None:
            name = self.text(mod, name_node)
            return f"{cls}.{name}" if cls and n.type == "method_definition" else name
        p = n.parent
        if p is not None and p.type == "variable_declarator":
            nm = p.child_by_field_name("name")
            if nm is not None and nm.type == "identifier":
                return self.text(mod, nm)
        if p is not None and p.type == "pair":
            key = p.child_by_field_name("key")
            if key is not None:
                return self.text(mod, key).strip("'\"")
        if p is not None and p.type == "assignment_expression":
            left = p.child_by_field_name("left")
            if left is not None:
                return self.text(mod, left).split(".")[-1]
        return f"<anon>@{n.start_point[0] + 1}:{n.start_point[1]}"

    def _index(self, mod: _JSModule, n: Any, cls: Optional[str]) -> None:
        if n.type in ("class_declaration", "class"):
            nm = n.child_by_field_name("name")
            cls = self.text(mod, nm) if nm is not None else cls
            if cls:
                mod.classes.setdefault(cls, {})
        if n.type in _FN_TYPES:
            name = self._fn_name(mod, n, cls)
            fid = f"fn:{mod.rel}:{name}"
            if fid in self.cg.g and self.cg.g.nodes[fid].get("line") != n.start_point[0] + 1:
                fid = f"fn:{mod.rel}:{name}@{n.start_point[0] + 1}"
            params = self._params(mod, n)
            line = n.start_point[0] + 1
            self.cg.node(fid, "function", name=name.split(".")[-1], qualname=name, module=mod.rel,
                         file=mod.rel, line=line, end_line=n.end_point[0] + 1, params=params,
                         cls=cls if n.type == "method_definition" else None, lang="js", fn=fid,
                         code=self.cg.code_at(mod.rel, line), entry=False, route=None, decorators=[])
            self.cg.node(f"ret:{fid}", "return", fn=fid, file=mod.rel, line=line, code=f"return of {name}()")
            mod.fn_by_span[(n.start_byte, n.end_byte)] = fid
            self.fn_nodes[fid] = (mod, n, cls if n.type == "method_definition" else None)
            if not name.startswith("<anon>"):
                mod.functions.setdefault(name, fid)
                if n.type == "method_definition" and cls:
                    mod.classes.setdefault(cls, {})[name.split(".")[-1]] = fid
                    self.method_index.setdefault(name.split(".")[-1], []).append(fid)
        for c in n.named_children:
            self._index(mod, c, cls)

    def _params(self, mod: _JSModule, fn: Any) -> List[str]:
        ps = fn.child_by_field_name("parameters")
        if ps is None:
            single = fn.child_by_field_name("parameter")
            return [self.text(mod, single)] if single is not None else []
        out = []
        for p in ps.named_children:
            if p.type in ("identifier",):
                out.append(self.text(mod, p))
            elif p.type in ("required_parameter", "optional_parameter", "assignment_pattern", "rest_pattern"):
                ident = p.child_by_field_name("pattern") or p.child_by_field_name("left") or \
                    (p.named_children[0] if p.named_children else None)
                out.append(self.text(mod, ident) if ident is not None and ident.type == "identifier"
                           else f"_p{len(out)}")
            else:
                out.append(f"_p{len(out)}")   # destructured: handled at build time
        return out

    def _index_imports_exports(self, mod: _JSModule) -> None:
        def walk(n: Any) -> None:
            t = n.type
            if t == "variable_declarator":
                val = n.child_by_field_name("value")
                name = n.child_by_field_name("name")
                spec = self._require_spec(mod, val)
                if spec is not None and name is not None:
                    if name.type == "identifier":
                        mod.imports[self.text(mod, name)] = (spec, None)
                    elif name.type == "object_pattern":
                        for c in name.named_children:
                            if c.type == "shorthand_property_identifier_pattern":
                                nm = self.text(mod, c)
                                mod.imports[nm] = (spec, nm)
                            elif c.type == "pair_pattern":
                                k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                                if k is not None and v is not None:
                                    mod.imports[self.text(mod, v)] = (spec, self.text(mod, k))
            elif t == "import_statement":
                src = n.child_by_field_name("source")
                spec = self._spec(mod, self.text(mod, src).strip("'\"`")) if src is not None else None
                for clause in n.named_children:
                    if clause.type != "import_clause" or spec is None:
                        continue
                    for c in clause.named_children:
                        if c.type == "identifier":
                            mod.imports[self.text(mod, c)] = (spec, "default")
                        elif c.type == "namespace_import":
                            ids = [x for x in c.named_children if x.type == "identifier"]
                            if ids:
                                mod.imports[self.text(mod, ids[0])] = (spec, None)
                        elif c.type == "named_imports":
                            for s in c.named_children:
                                if s.type == "import_specifier":
                                    nm = s.child_by_field_name("name")
                                    al = s.child_by_field_name("alias") or nm
                                    mod.imports[self.text(mod, al)] = (spec, self.text(mod, nm))
            elif t == "assignment_expression":
                left = self.text(mod, n.child_by_field_name("left"))
                right = n.child_by_field_name("right")
                if left in ("module.exports", "exports"):
                    if right.type == "object":
                        for c in right.named_children:
                            if c.type == "shorthand_property_identifier":
                                nm = self.text(mod, c)
                                if nm in mod.functions:
                                    mod.exports[nm] = mod.functions[nm]
                            elif c.type == "pair":
                                k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                                fid = self._fid_for_value(mod, v)
                                if k is not None and fid:
                                    mod.exports[self.text(mod, k)] = fid
                    else:
                        fid = self._fid_for_value(mod, right)
                        if fid:
                            mod.exports["default"] = fid
                elif left.startswith(("module.exports.", "exports.")):
                    fid = self._fid_for_value(mod, right)
                    if fid:
                        mod.exports[left.split(".")[-1]] = fid
            elif t == "export_statement":
                for c in n.named_children:
                    if c.type in ("function_declaration", "generator_function_declaration"):
                        nm = c.child_by_field_name("name")
                        if nm is not None:
                            mod.exports[self.text(mod, nm)] = mod.functions.get(self.text(mod, nm), "")
                    elif c.type in ("lexical_declaration", "variable_declaration"):
                        for d in c.named_children:
                            nm = d.child_by_field_name("name")
                            if nm is not None and self.text(mod, nm) in mod.functions:
                                mod.exports[self.text(mod, nm)] = mod.functions[self.text(mod, nm)]
                    elif c.type in _FN_TYPES or c.type == "identifier":
                        fid = self._fid_for_value(mod, c)
                        if fid:
                            mod.exports["default"] = fid
            for c in n.named_children:
                walk(c)
        walk(mod.tree.root_node)

    def _fid_for_value(self, mod: _JSModule, v: Any) -> str:
        if v is None:
            return ""
        if v.type in _FN_TYPES:
            return mod.fn_by_span.get((v.start_byte, v.end_byte), "")
        if v.type == "identifier":
            return mod.functions.get(self.text(mod, v), "")
        return ""

    def _require_spec(self, mod: _JSModule, val: Any) -> Optional[str]:
        while val is not None and val.type in ("await_expression", "member_expression"):
            val = val.named_children[0] if val.named_children else None
        if val is None or val.type != "call_expression":
            return None
        fn = val.child_by_field_name("function")
        if fn is None or self.text(mod, fn) != "require":
            return None
        args = val.child_by_field_name("arguments")
        if args is None or not args.named_children:
            return None
        return self._spec(mod, self.text(mod, args.named_children[0]).strip("'\"`"))

    def _spec(self, mod: _JSModule, raw: str) -> str:
        """Relative specifiers -> project-relative file path; packages stay as-is."""
        if not raw.startswith("."):
            return raw
        base = os.path.normpath(os.path.join(os.path.dirname(mod.rel), raw))
        return "./" + base

    def _module_for(self, spec: str) -> Optional[_JSModule]:
        if not spec.startswith("./"):
            return None
        base = spec[2:]
        for ext in _RESOLVE_EXTS:
            m = self.modules.get(base + ext)
            if m:
                return m
        return None

    # --- routes -----------------------------------------------------------------
    def _mark_routes(self, mod: _JSModule) -> None:
        def walk(n: Any) -> None:
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                args = n.child_by_field_name("arguments")
                if fn is not None and fn.type == "member_expression" and args is not None:
                    prop = fn.child_by_field_name("property")
                    obj = fn.child_by_field_name("object")
                    verb = self.text(mod, prop) if prop is not None else ""
                    objt = self.text(mod, obj) if obj is not None else ""
                    if verb in _ROUTE_VERBS and _ROUTER_OBJS.match(objt.split(".")[-1]):
                        a = args.named_children
                        if a and a[0].type in ("string", "template_string"):
                            path = self.text(mod, a[0]).strip("'\"`")
                            for h in a[1:]:
                                fid = self._handler_fid(mod, h)
                                if fid:
                                    d = self.cg.g.nodes[fid]
                                    d["entry"] = True
                                    d["route"] = {"method": verb.upper() if verb != "all" else "ANY",
                                                  "path": path, "framework": "express"}
            for c in n.named_children:
                walk(c)
        walk(mod.tree.root_node)

    def _handler_fid(self, mod: _JSModule, h: Any) -> str:
        if h.type in _FN_TYPES:
            return mod.fn_by_span.get((h.start_byte, h.end_byte), "")
        if h.type == "call_expression":
            # app.get('/x', login()) - a factory whose *returned* function is the handler
            # asyncHandler(login()) / wrap(handler): the wrapped argument is the handler...
            args = h.child_by_field_name("arguments")
            for a in (args.named_children if args is not None else []):
                if a.type in _FN_TYPES or a.type in ("call_expression", "identifier", "member_expression"):
                    fid = self._handler_fid(mod, a)
                    if fid:
                        return fid
            # ...otherwise login() is a factory whose returned function is the handler.
            fn = h.child_by_field_name("function")
            factory = self._handler_fid(mod, fn) if fn is not None else ""
            return self._returned_fn(factory) if factory else ""
        name = self.text(mod, h)
        if h.type == "identifier":
            if name in mod.functions:
                return mod.functions[name]
            imp = mod.imports.get(name)
            if imp:
                target = self._module_for(imp[0])
                if target:
                    return target.exports.get(imp[1] or "default", "")
        if h.type == "member_expression":
            head, _, attr = name.partition(".")
            imp = mod.imports.get(head)
            if imp:
                target = self._module_for(imp[0])
                if target:
                    return target.exports.get(attr, "") or target.functions.get(attr, "")
        return ""

    def _returned_fn(self, fid: str) -> str:
        mod, n, _ = self.fn_nodes.get(fid, (None, None, None))
        if n is None:
            return ""
        body = n.child_by_field_name("body")
        if body is None:
            return ""
        if body.type in _FN_TYPES:                      # () => (req, res) => ...
            return mod.fn_by_span.get((body.start_byte, body.end_byte), "")
        for st in body.named_children:
            if st.type == "return_statement" and st.named_children:
                r = st.named_children[0]
                while r.type == "parenthesized_expression" and r.named_children:
                    r = r.named_children[0]
                if r.type in _FN_TYPES:
                    return mod.fn_by_span.get((r.start_byte, r.end_byte), "")
                if r.type == "identifier":
                    return mod.functions.get(self.text(mod, r), "")
        return ""

    # --- build --------------------------------------------------------------------
    def build(self) -> None:
        for mod in self.modules.values():
            self._mark_routes(mod)
        for mod in self.modules.values():
            fid = f"fn:{mod.rel}:<module>"
            self.cg.node(fid, "function", name="<module>", qualname="<module>", module=mod.rel,
                         file=mod.rel, line=1, end_line=1, params=[], lang="js", fn=fid, entry=False)
            b = _JSBuilder(self, mod, fid, None, None, {})
            b.walk(mod.tree.root_node)
        for fid, (mod, n, cls) in list(self.fn_nodes.items()):
            if fid not in self.built:
                _JSBuilder(self, mod, fid, n, cls, {}).run()

    def resolve(self, mod: _JSModule, cls: Optional[str], callee: Any) -> Tuple[List[str], bool]:
        if callee.type == "identifier":
            name = self.text(mod, callee)
            if name in mod.functions:
                return [mod.functions[name]], False
            imp = mod.imports.get(name)
            if imp:
                target = self._module_for(imp[0])
                if target:
                    fid = target.exports.get(imp[1] or "default") or target.functions.get(imp[1] or "")
                    return ([fid] if fid else []), False
            return [], False
        if callee.type == "member_expression":
            obj = callee.child_by_field_name("object")
            prop = callee.child_by_field_name("property")
            if obj is None or prop is None:
                return [], False
            meth = self.text(mod, prop)
            if obj.type == "this" and cls:
                fid = mod.classes.get(cls, {}).get(meth)
                return ([fid] if fid else []), False
            if obj.type == "identifier":
                imp = mod.imports.get(self.text(mod, obj))
                if imp:
                    target = self._module_for(imp[0])
                    if target:
                        fid = target.exports.get(meth) or target.functions.get(meth)
                        return ([fid] if fid else []), False
                    return [], False
                if self.text(mod, obj) in mod.classes:
                    fid = mod.classes[self.text(mod, obj)].get(meth)
                    return ([fid] if fid else []), False
            if meth in specs.GENERIC_METHODS:
                return [], False
            cands = self.method_index.get(meth, [])
            return (cands, True) if 0 < len(cands) <= 3 else ([], False)
        return [], False


class _JSBuilder:
    def __init__(self, fe: JSFrontend, mod: _JSModule, fid: str, node: Any, cls: Optional[str],
                 outer: Dict[str, Set[str]]) -> None:
        self.fe = fe
        self.cg = fe.cg
        self.mod = mod
        self.fid = fid
        self.node = node
        self.cls = cls
        self.defs: Dict[str, Set[str]] = dict(outer)
        self.counter: Dict[str, int] = {}
        self.ret = f"ret:{fid}"
        d = self.cg.g.nodes.get(fid, {})
        self.is_entry = bool(d.get("entry"))
        self.alias: Dict[str, str] = {}
        self._n = 0

    def t(self, n: Any) -> str:
        return self.fe.text(self.mod, n)

    def line(self, n: Any) -> int:
        return n.start_point[0] + 1

    def code(self, ln: int) -> str:
        return self.cg.code_at(self.mod.rel, ln)

    def norm(self, name: str) -> str:
        head, dot, rest = name.partition(".")
        if head in self.alias:
            return self.alias[head] + dot + rest
        return name

    def resolved(self, raw: str) -> str:
        """Expand an imported package alias: ``cp.exec`` -> ``child_process.exec``."""
        head, dot, rest = raw.partition(".")
        imp = self.mod.imports.get(head)
        if imp and not imp[0].startswith("./"):
            base = imp[0] if imp[1] in (None, "default") else f"{imp[0]}.{imp[1]}"
            return base + (dot + rest if rest else "")
        return raw

    def new_var(self, name: str, ln: int) -> str:
        k = self.counter.get(name, 0) + 1
        self.counter[name] = k
        return self.cg.node(f"v:{self.fid}:{name}#{k}", "var", name=name, fn=self.fid, file=self.mod.rel,
                            line=ln, code=self.code(ln))

    def source(self, label: str, n: Any, param: str = "") -> str:
        ln = self.line(n)
        return self.cg.node(f"src:{self.fid}:{ln}:{n.start_point[1]}:{label}", "source", label=label,
                            fn=self.fid, file=self.mod.rel, line=ln, code=self.code(ln), trust="remote",
                            coerced=False, param=param)

    # --- function entry ---------------------------------------------------------------
    def run(self) -> None:
        self.fe.built.add(self.fid)
        n = self.node
        params = self.cg.g.nodes[self.fid].get("params", [])
        if self.is_entry and params:
            self.alias[params[0]] = "req"
            if len(params) > 1:
                self.alias[params[1]] = "res"
        ps = n.child_by_field_name("parameters")
        pnodes = ps.named_children if ps is not None else (
            [n.child_by_field_name("parameter")] if n.child_by_field_name("parameter") is not None else [])
        for i, p in enumerate(pnodes):
            pname = params[i] if i < len(params) else f"_p{i}"
            pid = self.cg.node(f"p:{self.fid}:{pname}", "param", name=pname, index=i, fn=self.fid,
                               file=self.mod.rel, line=self.line(p), code=self.code(self.line(p)))
            if p.type == "identifier" or not pname.startswith("_p"):
                self.defs[pname] = {pid}
            else:
                pat = p.child_by_field_name("pattern") or p
                self.bind_pattern(pat, {pid}, self.line(p))
            pat = p
            if pat.type in ("required_parameter", "optional_parameter"):   # TS: ({ query }: Request)
                pat = pat.child_by_field_name("pattern") or pat
            if self.is_entry and i == 0 and pat.type == "object_pattern":
                # ({ query, body }, res) => ... destructured request
                for c in pat.named_children:
                    nm = self.t(c)
                    if f"req.{nm}" in self.fe.source_attrs:
                        self.defs[nm] = {self.source(f"req.{nm}", c)}
        body = n.child_by_field_name("body")
        if body is None:
            return
        if body.type == "statement_block":
            self.walk(body)
        else:  # concise arrow body is the return value
            for v in self.eval(body):
                self.cg.flow(v, self.ret)

    # --- statements ---------------------------------------------------------------------
    def walk(self, n: Any) -> None:
        for c in n.named_children:
            self.stmt(c)

    def _branch(self, bodies: List[Any], fallthrough: bool = True, loop: bool = False) -> None:
        before = {k: set(v) for k, v in self.defs.items()}
        merged = {k: set(v) for k, v in before.items()} if fallthrough else {}
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
        if t in ("lexical_declaration", "variable_declaration"):
            for d in n.named_children:
                if d.type != "variable_declarator":
                    continue
                val = d.child_by_field_name("value")
                name = d.child_by_field_name("name")
                vals = self.eval(val) if val is not None else set()
                if name is not None and self.fe._require_spec(self.mod, val) is None:
                    self.bind_pattern(name, vals, self.line(d))
        elif t == "expression_statement":
            for c in n.named_children:
                self.eval(c)
        elif t == "return_statement":
            for c in n.named_children:
                for v in self.eval(c):
                    self.cg.flow(v, self.ret)
        elif t == "if_statement":
            self.eval(n.child_by_field_name("condition"))
            alt = n.child_by_field_name("alternative")
            self._branch([n.child_by_field_name("consequence"), alt], fallthrough=alt is None)
        elif t in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
            if t == "for_in_statement":
                right = n.child_by_field_name("right")
                left = n.child_by_field_name("left")
                if left is not None:
                    self.bind_pattern(left, self.eval(right), self.line(n))
            for f in ("initializer", "condition", "increment"):
                c = n.child_by_field_name(f)
                if c is not None:
                    self.stmt(c) if c.type.endswith("declaration") else self.eval(c)
            self._branch([n.child_by_field_name("body")], loop=True)
        elif t == "try_statement":
            self.stmt(n.child_by_field_name("body"))
            h = n.child_by_field_name("handler")
            self._branch([h.child_by_field_name("body") if h is not None else None])
            fin = n.child_by_field_name("finalizer")
            if fin is not None:
                self.walk(fin)
        elif t == "switch_statement":
            self.eval(n.child_by_field_name("value"))
            body = n.child_by_field_name("body")
            self._branch(list(body.named_children) if body is not None else [])
        elif t in ("switch_case", "switch_default", "else_clause", "finally_clause"):
            for c in n.named_children:
                if c.type.endswith("statement") or c.type in ("statement_block", "lexical_declaration",
                                                              "variable_declaration"):
                    self.stmt(c)
                else:
                    self.eval(c)
        elif t in ("statement_block", "program", "class_body"):
            self.walk(n)
        elif t in ("class_declaration", "class"):
            body = n.child_by_field_name("body")
            if body is not None:
                self.walk(body)
        elif t in _FN_TYPES:
            self.nested(n)
        elif t in ("export_statement", "labeled_statement"):
            self.walk(n)
        elif t in ("field_definition", "public_field_definition"):
            v = n.child_by_field_name("value")
            if v is not None:
                self.eval(v)
        elif t in ("throw_statement",):
            for c in n.named_children:
                self.eval(c)
        elif t in ("import_statement", "comment", "empty_statement", "break_statement", "continue_statement",
                   "debugger_statement", "type_alias_declaration", "interface_declaration",
                   "enum_declaration", "ambient_declaration"):
            return
        else:
            self.eval(n)

    def nested(self, n: Any) -> None:
        fid = self.mod.fn_by_span.get((n.start_byte, n.end_byte))
        if fid and fid not in self.fe.built:
            _, _, cls = self.fe.fn_nodes.get(fid, (None, None, None))
            _JSBuilder(self.fe, self.mod, fid, n, cls or self.cls, self.defs).run()

    def bind_pattern(self, pat: Any, vals: Set[str], ln: int) -> None:
        if pat is None:
            return
        if pat.type in ("identifier", "shorthand_property_identifier_pattern"):
            nm = self.t(pat)
            nid = self.new_var(nm, ln)
            for v in vals:
                self.cg.flow(v, nid)
            self.defs[nm] = {nid}
        elif pat.type in ("object_pattern", "array_pattern"):
            for c in pat.named_children:
                if c.type == "pair_pattern":
                    self.bind_pattern(c.child_by_field_name("value"), vals, ln)
                elif c.type in ("object_assignment_pattern", "assignment_pattern"):
                    self.bind_pattern(c.child_by_field_name("left"), vals, ln)
                elif c.type == "rest_pattern":
                    self.bind_pattern(c.named_children[0] if c.named_children else None, vals, ln)
                else:
                    self.bind_pattern(c, vals, ln)
        elif pat.type in ("member_expression", "subscript_expression"):
            self.assign_member(pat, vals, ln)

    def assign_member(self, target: Any, vals: Set[str], ln: int) -> None:
        txt = self.norm(self.t(target))
        for spec in self.fe.sinks:
            if any(p.startswith("<prop>.") and txt.endswith(p[6:]) for p in spec.names):
                aid = self.cg.node(f"a:assign:{self.fid}:{ln}:{target.start_point[1]}", "arg", fn=self.fid,
                                   file=self.mod.rel, line=ln, code=self.code(ln))
                self._add_sink(aid, spec, txt)
                for v in vals:
                    self.cg.flow(v, aid)
        obj = target.child_by_field_name("object")
        if obj is not None and obj.type == "this" and self.cls:
            prop = target.child_by_field_name("property")
            fld = self.cg.node(f"fld:{self.mod.rel}:{self.cls}.{self.t(prop)}", "field",
                               name=f"{self.cls}.{self.t(prop)}", fn=self.fid, file=self.mod.rel, line=ln,
                               code=self.code(ln))
            for v in vals:
                self.cg.flow(v, fld)
            return
        root = obj
        while root is not None and root.type in ("member_expression", "subscript_expression"):
            root = root.child_by_field_name("object")
        if root is not None and root.type == "identifier" and vals:
            nm = self.t(root)
            old = self.defs.get(nm, set())
            nid = self.new_var(nm, ln)
            for v in old | vals:
                self.cg.flow(v, nid)
            self.defs[nm] = {nid}

    # --- expressions -------------------------------------------------------------------
    def eval(self, n: Any) -> Set[str]:
        if n is None:
            return set()
        t = n.type
        if t in _LITERALS or t.endswith("_type") or t == "type_annotation":
            return set()
        if t == "identifier":
            return set(self.defs.get(self.t(n), set()))
        if t in ("member_expression", "subscript_expression"):
            return self.member(n)
        if t in ("call_expression", "new_expression"):
            return self.call(n)
        if t in _FN_TYPES:
            self.nested(n)
            return set()
        if t == "binary_expression":
            op = n.child_by_field_name("operator")
            l, r = self.eval(n.child_by_field_name("left")), self.eval(n.child_by_field_name("right"))
            return set() if op is not None and self.t(op) in _CMP_OPS else l | r
        if t == "unary_expression":
            op = n.child_by_field_name("operator")
            inner = self.eval(n.child_by_field_name("argument"))
            return set() if op is not None and self.t(op) in ("typeof", "!", "void", "delete") else inner
        if t == "update_expression":
            return set()
        if t == "assignment_expression":
            vals = self.eval(n.child_by_field_name("right"))
            self.bind_pattern(n.child_by_field_name("left"), vals, self.line(n))
            return vals
        if t == "augmented_assignment_expression":
            left = n.child_by_field_name("left")
            vals = self.eval(n.child_by_field_name("right")) | self.eval(left)
            self.bind_pattern(left, vals, self.line(n))
            return vals
        if t == "pair":
            return self.eval(n.child_by_field_name("value"))
        if t == "shorthand_property_identifier":
            return set(self.defs.get(self.t(n), set()))
        if t == "jsx_attribute":
            kids = n.named_children
            if kids and self.t(kids[0]) == "dangerouslySetInnerHTML" and len(kids) > 1:
                ln = self.line(n)
                aid = self.cg.node(f"a:jsx:{self.fid}:{ln}:{n.start_point[1]}", "arg", fn=self.fid,
                                   file=self.mod.rel, line=ln, code=self.code(ln))
                d = self.cg.g.nodes[aid]
                d.setdefault("sinks", []).append({"class": "xss", "cwe": "CWE-79", "severity": "medium",
                                                  "owasp": "A03", "title": "DOM XSS (dangerouslySetInnerHTML)",
                                                  "sink": "dangerouslySetInnerHTML"})
                for v in self.eval(kids[1]):
                    self.cg.flow(v, aid)
            return set()
        out: Set[str] = set()
        for c in n.named_children:
            out |= self.eval(c)
        return out

    def member(self, n: Any) -> Set[str]:
        raw = self.norm(self.t(n))
        raw = re.sub(r"\s+", "", raw)
        if n.type == "member_expression":
            label = raw
            if specs.any_match(self.fe.source_attrs, raw):
                return {self.source(label, n, param="")}
            # req.query.host -> source labelled with the concrete field
            obj = n.child_by_field_name("object")
            objtxt = re.sub(r"\s+", "", self.norm(self.t(obj))) if obj is not None else ""
            if obj is not None and specs.any_match(self.fe.source_attrs, objtxt):
                prop = n.child_by_field_name("property")
                return {self.source(raw, n, param=self.t(prop) if prop is not None else "")}
            if obj is not None and obj.type == "this" and self.cls:
                prop = n.child_by_field_name("property")
                fid = f"fld:{self.mod.rel}:{self.cls}.{self.t(prop)}"
                return {fid} if fid in self.cg.g else set()
            return self.eval(obj)
        obj = n.child_by_field_name("object")
        idx = n.child_by_field_name("index")
        self.eval(idx)
        objtxt = re.sub(r"\s+", "", self.norm(self.t(obj))) if obj is not None else ""
        if obj is not None and specs.any_match(self.fe.source_attrs, objtxt):
            return {self.source(raw, n, param=self.t(idx).strip("'\"`") if idx is not None else "")}
        return self.eval(obj)

    def call(self, n: Any) -> Set[str]:
        self._n += 1
        is_new = n.type == "new_expression"
        fn = n.child_by_field_name("constructor" if is_new else "function")
        args_node = n.child_by_field_name("arguments")
        raw = re.sub(r"\s+", "", self.norm(self.t(fn))) if fn is not None else ""
        if fn is not None and fn.type not in ("identifier", "member_expression"):
            raw = ""
        full = self.resolved(raw)
        ln = self.line(n)
        cid = self.cg.node(f"c:{self.fid}:{ln}:{n.start_point[1]}:{self._n}", "call",
                           callee=full or "<dynamic>", raw=raw, fn=self.fid, file=self.mod.rel, line=ln,
                           code=self.code(ln))
        self.cg.flow(self.fid, cid, kind="contains")
        if raw == "require":
            return set()

        recv: Set[str] = set()
        if fn is not None and fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            recv = self.eval(obj)
        elif fn is not None and not raw:
            recv = self.eval(fn)

        args: List[Tuple[Any, str, Set[str], Any]] = []
        callbacks: List[Any] = []
        arg_nodes = args_node.named_children if args_node is not None and args_node.type == "arguments" else (
            [args_node] if args_node is not None else [])   # tagged template: fn`...`
        for i, a in enumerate(x for x in arg_nodes if x.type != "comment"):
            node = a.named_children[0] if a.type == "spread_element" and a.named_children else a
            if node.type in _FN_TYPES:
                callbacks.append(node)
                vals: Set[str] = set()
            else:
                vals = self.eval(node)
            aid = self.cg.node(f"a:{cid}:{i}", "arg", pos=i, fn=self.fid, file=self.mod.rel,
                               line=self.line(node), code=self.code(ln), call=cid)
            for v in vals:
                self.cg.flow(v, aid)
            args.append((i, aid, vals, node))

        names = (full, raw)
        recv_is_source = any(self.cg.g.nodes[r].get("kind") == "source" for r in recv)
        if not recv_is_source and specs.any_match(self.fe.source_calls, *names):
            p = ""
            if args and args[0][3].type == "string":
                p = self.t(args[0][3]).strip("'\"`")
            self.cg.flow(self.source(f"{raw}()", n, param=p), cid)
        elif recv_is_source and args and args[0][3].type == "string":
            for r in recv:   # req.query.get('x') style: record the field name
                if self.cg.g.nodes[r].get("kind") == "source" and not self.cg.g.nodes[r].get("param"):
                    self.cg.g.nodes[r]["param"] = self.t(args[0][3]).strip("'\"`")

        argtxt = self.t(args_node) if args_node is not None else ""
        for spec in specs.find_sinks(self.fe.sinks, *names):
            if spec.requires_kw and not all(re.search(rf"\b{k}\s*:\s*{str(v).lower()}\b", argtxt)
                                            for k, v in spec.requires_kw.items()):
                continue
            for key, aid, _, node in args:
                if spec.vclass == "mass_assignment" and node.type == "object":
                    continue   # explicit field picks are not mass assignment
                if spec.vclass == "nosqli" and node.type not in ("object", "identifier", "member_expression"):
                    continue   # hash.update(pw) / find(cb): no query document
                if spec.vclass == "nosqli" and raw.endswith((".update", ".remove")) and (
                        node.type != "object" or not re.search(r"(?i)(collection|coll|\bdb)\.\w+$", raw)):
                    continue   # Sequelize instance.update({...}) is not a Mongo query
                if spec.vclass == "nosqli" and node.type == "object" and re.search(
                        r"^\{\s*(where|include|attributes)\s*:", self.t(node)):
                    continue   # Sequelize/Prisma-style {where: ...}: parameterized by the ORM
                if spec.any_arg or key in spec.args:
                    self._add_sink(aid, spec, raw)
        if is_new and raw == "Function":
            for _, aid, _, _ in args:
                self._add_sink(aid, specs.JS_SINKS[2], "new Function")
        if specs.any_match(specs.JS_OBJECT_LOOKUPS, *names):
            for _, aid, _, _ in args:
                d = self.cg.g.nodes[aid]
                if not any(s["class"] == "bola" for s in d.get("sinks", [])):
                    d.setdefault("sinks", []).append({
                        "class": "bola", "cwe": "CWE-639", "severity": "high", "owasp": "API1",
                        "title": "Object lookup keyed by client-supplied id (BOLA candidate)",
                        "sink": raw, "lookup": True})

        targets, weak = self.fe.resolve(self.mod, self.cls, fn) if fn is not None else ([], False)
        if weak and specs.find_sinks(self.fe.sinks, *names):
            targets, weak = [], False
        san = specs.sanitizer_classes(self.fe.sanitizers, *names)
        if targets:
            for tgt in targets:
                self.bind(cid, tgt, args, weak)
        elif san is not None:
            if specs.ALL not in san:
                for _, aid, _, _ in args:
                    self.cg.flow(aid, cid, sanitizes=san)
                for r in recv:
                    self.cg.flow(r, cid, sanitizes=san)
        else:
            for _, aid, _, _ in args:
                self.cg.flow(aid, cid)
            for r in recv:
                self.cg.flow(r, cid)
            if fn is not None and fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                if prop is not None and self.t(prop) in ("push", "unshift", "set", "append", "assign", "concat"):
                    obj = fn.child_by_field_name("object")
                    if obj is not None and obj.type == "identifier":
                        nm = self.t(obj)
                        vals = {aid for _, aid, _, _ in args}
                        if vals:
                            nid = self.new_var(nm, ln)
                            for v in self.defs.get(nm, set()) | vals:
                                self.cg.flow(v, nid)
                            self.defs[nm] = {nid}
        # Callbacks: built as closures; unknown APIs feed their inputs to callback params.
        for cb in callbacks:
            fid = self.mod.fn_by_span.get((cb.start_byte, cb.end_byte))
            self.nested(cb)
            if fid and not targets and san is None and not self.cg.g.nodes[fid].get("entry"):
                feed = recv   # rows.map(r => ..) / p.then(v => ..); not exec(cmd, cb)
                for p in self.cg.g.nodes[fid].get("params", [])[:2]:
                    pid = f"p:{fid}:{p}"
                    if pid in self.cg.g:
                        for v in feed:
                            self.cg.flow(v, pid)
        return {cid}

    def _add_sink(self, aid: str, spec: specs.SinkSpec, name: str) -> None:
        d = self.cg.g.nodes[aid]
        lst = d.setdefault("sinks", [])
        if not any(x["class"] == spec.vclass for x in lst):
            info = {"class": spec.vclass, "cwe": spec.cwe, "severity": spec.severity, "owasp": spec.owasp,
                    "title": spec.title, "sink": name}
            if spec.vclass == "mass_assignment":
                info["whole_object"] = True
            lst.append(info)

    def bind(self, cid: str, target: str, args, weak: bool) -> None:
        self.cg.flow(self.fid, target, kind="calls", weak=weak)
        td = self.cg.g.nodes[target]
        params = td.get("params", [])
        for key, aid, _, _ in args:
            if isinstance(key, int) and key < len(params):
                pid = self.cg.node(f"p:{target}:{params[key]}", "param", name=params[key], fn=target,
                                   file=td.get("file"), line=td.get("line"), code=td.get("code"))
                self.cg.flow(aid, pid, kind="call", site=cid, weak=weak)
        self.cg.flow(f"ret:{target}", cid, kind="ret", site=cid, weak=weak)
