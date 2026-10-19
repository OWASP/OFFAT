"""Python frontend: stdlib ``ast`` -> CodeGraph.

Two passes:

1. **Index** every module: dotted module name, imports (alias -> full name),
   functions/methods (with decorators, params, route info), classes (bases,
   methods) and module-level names.
2. **Build** each function body into data-flow nodes. Local variables are
   versioned per assignment (a light reaching-definitions pass: branches are
   merged by union, loop bodies are walked twice), so ``x = int(x)`` kills the
   tainted definition instead of joining it. Calls to project functions are
   resolved through imports / ``self`` / class names and wired arg->param and
   return->call with a call-site label, which lets the taint search keep calls
   and returns matched (no ``f(a)`` taint leaking out of an unrelated ``f(b)``).
"""

from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from . import specs
from .graph import CodeGraph

_ROUTE_VERBS = {"route", "get", "post", "put", "delete", "patch", "head", "options",
                "api_route", "websocket", "api_view", "action"}
_FLASK_CONVERTER = re.compile(r"<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>")


def dotted(expr: ast.AST) -> str:
    """``a.b.c`` for Name/Attribute chains (calls/subscripts in the chain -> '')."""
    parts: List[str] = []
    cur = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    if isinstance(cur, ast.Call):
        inner = dotted(cur.func)
        if inner:
            parts.append(inner)
            return ".".join(reversed(parts))
    return ""


class _Module:
    def __init__(self, name: str, rel: str, tree: ast.Module, is_pkg: bool) -> None:
        self.name = name
        self.rel = rel
        self.tree = tree
        self.is_pkg = is_pkg
        self.imports: Dict[str, str] = {}
        self.functions: Dict[str, str] = {}     # qualname -> fn id
        self.classes: Dict[str, Dict[str, Any]] = {}
        self.globals: Set[str] = set()


class PythonFrontend:
    lang = "py"

    def __init__(self, root: str, cg: CodeGraph, local_sources: bool = False,
                 extra_sinks: Optional[List[specs.SinkSpec]] = None,
                 extra_sanitizers: Optional[List[specs.SanitizerSpec]] = None,
                 extra_sources: Optional[List[str]] = None) -> None:
        self.root = root
        self.cg = cg
        self.local_sources = local_sources
        self.sinks = [s for s in specs.PY_SINKS] + [s for s in (extra_sinks or []) if s.lang in ("*", "py")]
        self.sanitizers = specs.PY_SANITIZERS + [s for s in (extra_sanitizers or []) if s.lang in ("*", "py")]
        self.source_attrs = tuple(specs.PY_SOURCE_ATTRS) + tuple(extra_sources or ())
        self.source_calls = tuple(specs.PY_SOURCE_CALLS) + tuple(extra_sources or ())
        self.modules: Dict[str, _Module] = {}
        self.class_index: Dict[str, List[Tuple[_Module, str]]] = {}   # class name -> [(mod, name)]
        self.method_index: Dict[str, List[str]] = {}                   # method name -> fn ids
        self.fn_defs: Dict[str, Tuple[_Module, Optional[str], ast.AST]] = {}
        self.parse_errors: List[str] = []
        self.built: Set[str] = set()
        self._suffix: Dict[str, List[str]] = {}

    # --- pass 1: index ------------------------------------------------------
    def add_file(self, path: str) -> None:
        rel = os.path.relpath(path, self.root)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            tree = ast.parse(text, filename=rel)
        except (SyntaxError, ValueError, OSError) as exc:
            self.parse_errors.append(f"{rel}: {exc}")
            return
        self.cg.lines[rel] = text.splitlines(keepends=True)
        modname = rel[:-3].replace(os.sep, ".")
        is_pkg = modname.endswith("__init__")
        if is_pkg:
            modname = modname[: -len(".__init__")] if "." in modname else ""
        mod = _Module(modname, rel, tree, is_pkg)
        self.modules[modname] = mod
        # src/ layouts and monorepos: "src.offat.api" must answer to "offat.api" too.
        parts = modname.split(".")
        for i in range(1, len(parts)):
            self._suffix.setdefault(".".join(parts[i:]), []).append(modname)
        self._index_module(mod)

    def _index_module(self, mod: _Module) -> None:
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        mod.imports[a.asname] = a.name
                    else:
                        mod.imports[a.name.split(".")[0]] = a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                base = self._resolve_relative(mod, node.module or "", node.level)
                for a in node.names:
                    mod.imports[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
        for stmt in mod.tree.body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]):
                    for n in ast.walk(t):
                        if isinstance(n, ast.Name):
                            mod.globals.add(n.id)
        self._index_defs(mod, mod.tree.body, prefix="", cls=None)

    @staticmethod
    def _resolve_relative(mod: _Module, name: str, level: int) -> str:
        if not level:
            return name
        parts = mod.name.split(".") if mod.name else []
        if not mod.is_pkg:
            parts = parts[:-1]
        if level > 1:
            parts = parts[: len(parts) - (level - 1)]
        base = ".".join(parts)
        return f"{base}.{name}".strip(".") if name else base

    def _index_defs(self, mod: _Module, body: List[ast.stmt], prefix: str, cls: Optional[str]) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{stmt.name}"
                fid = f"fn:{mod.name}:{qual}"
                mod.functions[qual] = fid
                self.fn_defs[fid] = (mod, cls, stmt)
                params = [a.arg for a in stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs]
                route = self._route_of(mod, stmt)
                self.cg.node(fid, "function", name=stmt.name, qualname=qual, module=mod.name,
                             file=mod.rel, line=stmt.lineno, end_line=getattr(stmt, "end_lineno", stmt.lineno),
                             params=params, cls=cls, lang="py", fn=fid,
                             code=self.cg.code_at(mod.rel, stmt.lineno),
                             entry=bool(route), route=route,
                             decorators=[dotted(d.func if isinstance(d, ast.Call) else d)
                                         for d in stmt.decorator_list])
                self.cg.node(f"ret:{fid}", "return", fn=fid, file=mod.rel, line=stmt.lineno,
                             code=f"return of {qual}()")
                if cls:
                    self.method_index.setdefault(stmt.name, []).append(fid)
                self._index_defs(mod, stmt.body, prefix=f"{qual}.", cls=cls)
            elif isinstance(stmt, ast.ClassDef):
                qual = f"{prefix}{stmt.name}"
                mod.classes[qual] = {"bases": [dotted(b) for b in stmt.bases], "line": stmt.lineno}
                self.class_index.setdefault(stmt.name, []).append((mod, qual))
                self._index_defs(mod, stmt.body, prefix=f"{qual}.", cls=qual)
            elif isinstance(stmt, (ast.If, ast.Try)) and not prefix:
                # Conditional top-level definitions (try/except ImportError, if TYPE_CHECKING).
                inner = list(getattr(stmt, "body", [])) + list(getattr(stmt, "orelse", []))
                for h in getattr(stmt, "handlers", []):
                    inner += h.body
                self._index_defs(mod, inner, prefix, cls)

    def _route_of(self, mod: _Module, fn: ast.AST) -> Optional[Dict[str, Any]]:
        for d in getattr(fn, "decorator_list", []):
            if not isinstance(d, ast.Call):
                name = dotted(d)
                if name.split(".")[-1] in ("api_view",):
                    return {"method": "ANY", "path": "", "framework": "drf"}
                continue
            name = dotted(d.func)
            verb = name.split(".")[-1]
            if verb not in _ROUTE_VERBS or "." not in name and verb not in ("api_view",):
                continue
            path = ""
            if d.args and isinstance(d.args[0], ast.Constant) and isinstance(d.args[0].value, str):
                path = d.args[0].value
            elif verb not in ("api_view", "action"):
                continue
            methods = [verb.upper()] if verb not in ("route", "api_route", "api_view", "action") else []
            for kw in d.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    methods = [e.value.upper() for e in kw.value.elts
                               if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            fw = "fastapi" if verb in ("api_route", "websocket") else "flask"
            base = mod.imports.get(name.split(".")[0], "")
            if "fastapi" in base or any("fastapi" in v for v in mod.imports.values()):
                fw = "fastapi"
            return {"method": ",".join(methods) or "GET", "path": path, "framework": fw}
        # Django function views / lambda handlers: first parameter named request.
        args = getattr(fn, "args", None)
        if args and args.args:
            first = args.args[0].arg
            if first == "request" and (mod.rel.endswith("views.py") or "views" in mod.rel.split(os.sep)):
                return {"method": "ANY", "path": "", "framework": "django"}
            if getattr(fn, "name", "") == "lambda_handler" and first == "event":
                return {"method": "ANY", "path": "", "framework": "aws-lambda"}
        return None

    # --- pass 2: build ------------------------------------------------------
    def build(self) -> None:
        self._mark_registered_views()
        for mod in self.modules.values():
            mb = _FnBuilder(self, mod, None, None, f"fn:{mod.name}:<module>", {})
            self.cg.node(mb.fid, "function", name="<module>", qualname="<module>", module=mod.name,
                         file=mod.rel, line=1, end_line=1, params=[], lang="py", fn=mb.fid, entry=False)
            mb.walk_body([s for s in mod.tree.body], module_level=True)
        for fid, (mod, cls, node) in list(self.fn_defs.items()):
            if fid not in self.built:
                _FnBuilder(self, mod, cls, node, fid, {}).run()

    def _mark_registered_views(self) -> None:
        """``app.add_url_rule('/x', view_func=f)`` / ``path('x/', views.f)`` registrations."""
        for mod in self.modules.values():
            for node in ast.walk(mod.tree):
                if not isinstance(node, ast.Call):
                    continue
                name = dotted(node.func)
                tail = name.split(".")[-1]
                target, path = None, ""
                if tail in ("add_url_rule", "add_api_route", "add_route"):
                    for kw in node.keywords:
                        if kw.arg in ("view_func", "endpoint"):
                            target = kw.value
                    if target is None and len(node.args) >= 3:
                        target = node.args[2]
                    if target is None and tail != "add_url_rule" and len(node.args) >= 2:
                        target = node.args[1]
                elif tail in ("path", "re_path", "url") and len(node.args) >= 2:
                    target = node.args[1]
                if target is None:
                    continue
                if node.args and isinstance(node.args[0], ast.Constant):
                    path = str(node.args[0].value)
                for fid in self.resolve_name(mod, None, dotted(target)):
                    d = self.cg.g.nodes[fid]
                    if not d.get("entry"):
                        d["entry"] = True
                        d["route"] = {"method": "ANY", "path": path, "framework": "registered"}

    # --- name resolution ----------------------------------------------------
    def resolve_alias(self, mod: _Module, name: str) -> str:
        if not name:
            return ""
        head, _, rest = name.partition(".")
        full = mod.imports.get(head)
        if full:
            return f"{full}.{rest}" if rest else full
        return name

    def _lookup_qual(self, full: str, _seen: Optional[Set[str]] = None) -> List[str]:
        """Project function for a fully dotted name (module.func / module.Class.method)."""
        _seen = _seen if _seen is not None else set()
        if full in _seen or len(_seen) > 20:   # re-export cycles (pkg/__init__ <-> submodule)
            return []
        _seen.add(full)
        parts = full.split(".")
        for i in range(len(parts) - 1, -1, -1):
            modname = ".".join(parts[:i])
            mod = self.module(modname)
            if mod is None:
                continue
            qual = ".".join(parts[i:])
            if qual in mod.functions:
                return [mod.functions[qual]]
            if qual in mod.classes:
                return self._ctor(mod, qual)
            alias = mod.imports.get(parts[i]) if i < len(parts) else None
            if alias and alias != full:     # re-exported name (package __init__)
                rest = ".".join(parts[i + 1:])
                return self._lookup_qual(f"{alias}.{rest}" if rest else alias, _seen)
        return []

    def module(self, name: str) -> Optional[_Module]:
        mod = self.modules.get(name)
        if mod is None:
            cands = self._suffix.get(name, [])
            mod = self.modules[cands[0]] if len(cands) == 1 else None
        return mod

    def _ctor(self, mod: _Module, cls_qual: str) -> List[str]:
        fid = mod.functions.get(f"{cls_qual}.__init__")
        return [fid] if fid else []

    def _method_in_class(self, mod: _Module, cls_qual: str, meth: str, depth: int = 0) -> List[str]:
        fid = mod.functions.get(f"{cls_qual}.{meth}")
        if fid:
            return [fid]
        if depth > 5:
            return []
        out: List[str] = []
        for base in mod.classes.get(cls_qual, {}).get("bases", []):
            full = self.resolve_alias(mod, base)
            short = full.split(".")[-1]
            for bmod, bqual in self.class_index.get(short, []):
                out += self._method_in_class(bmod, bqual, meth, depth + 1)
        return out

    def resolve_name(self, mod: _Module, cls: Optional[str], raw: str, scope: str = "") -> List[str]:
        if not raw:
            return []
        if "." not in raw:
            # Nested functions shadow module-level ones: try outer.inner from the innermost scope out.
            parts = scope.split(".") if scope and scope != "<module>" else []
            for i in range(len(parts), 0, -1):
                q = ".".join(parts[:i]) + "." + raw
                if q in mod.functions:
                    return [mod.functions[q]]
            if raw in mod.functions:
                return [mod.functions[raw]]
            if raw in mod.classes:
                return self._ctor(mod, raw)
            full = mod.imports.get(raw)
            return self._lookup_qual(full) if full else []
        head, _, rest = raw.partition(".")
        if head in ("self", "cls") and cls and "." not in rest:
            return self._method_in_class(mod, cls, rest)
        if head in mod.classes and "." not in rest:
            return self._method_in_class(mod, head, rest)
        full = self.resolve_alias(mod, raw)
        hit = self._lookup_qual(full)
        if hit:
            return hit
        return self._lookup_qual(f"{mod.name}.{raw}") if mod.name else []

    def weak_methods(self, meth: str) -> List[str]:
        if meth in specs.GENERIC_METHODS or meth.startswith("__"):
            return []
        cands = self.method_index.get(meth, [])
        return cands if 0 < len(cands) <= 3 else []


class _FnBuilder:
    """Builds one function body into flow nodes."""

    def __init__(self, fe: PythonFrontend, mod: _Module, cls: Optional[str], node: Optional[ast.AST],
                 fid: str, outer: Dict[str, Set[str]]) -> None:
        self.fe = fe
        self.cg = fe.cg
        self.mod = mod
        self.cls = cls
        self.node = node
        self.fid = fid
        self.defs: Dict[str, Set[str]] = dict(outer)
        self.counter: Dict[str, int] = {}
        self.ret = f"ret:{fid}"
        fdata = self.cg.g.nodes.get(fid, {})
        self.route = fdata.get("route")
        self.is_entry = bool(fdata.get("entry"))
        self.qual = fdata.get("qualname", "")
        self._ncall = 0

    # --- helpers ------------------------------------------------------------
    def _code(self, line: int) -> str:
        return self.cg.code_at(self.mod.rel, line)

    def new_var(self, name: str, line: int) -> str:
        k = self.counter.get(name, 0) + 1
        self.counter[name] = k
        nid = f"v:{self.fid}:{name}#{k}"
        return self.cg.node(nid, "var", name=name, fn=self.fid, file=self.mod.rel, line=line,
                            code=self._code(line))

    def global_node(self, modname: str, name: str) -> str:
        mod = self.fe.modules.get(modname)
        return self.cg.node(f"g:{modname}:{name}", "global", name=name, fn=f"fn:{modname}:<module>",
                            file=mod.rel if mod else "", line=0, code=f"{modname}.{name}")

    def source(self, label: str, line: int, col: int, trust: str = "remote",
               coerced: bool = False, param: str = "") -> str:
        nid = f"src:{self.fid}:{line}:{col}:{label}"
        return self.cg.node(nid, "source", label=label, fn=self.fid, file=self.mod.rel, line=line,
                            code=self._code(line), trust=trust, coerced=coerced, param=param)

    # --- entry --------------------------------------------------------------
    def run(self) -> None:
        self.fe.built.add(self.fid)
        fn = self.node
        a = fn.args
        positional = a.posonlyargs + a.args
        params = positional + ([a.vararg] if a.vararg else []) + a.kwonlyargs + ([a.kwarg] if a.kwarg else [])
        defaults = dict(zip([p.arg for p in positional[len(positional) - len(a.defaults):]], a.defaults))
        defaults.update({p.arg: d for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None})
        coerced_path = self._coerced_route_params()
        for i, p in enumerate(params):
            pid = f"p:{self.fid}:{p.arg}"
            self.cg.node(pid, "param", name=p.arg, index=i, fn=self.fid, file=self.mod.rel,
                         line=p.lineno, code=self._code(p.lineno))
            self.defs[p.arg] = {pid}
            if self.is_entry:
                self._handler_param_source(p, pid, defaults.get(p.arg), coerced_path)
        self.walk_body(fn.body)

    def _coerced_route_params(self) -> Set[str]:
        out = set()
        for conv, name in _FLASK_CONVERTER.findall((self.route or {}).get("path", "")):
            if conv in ("int", "float", "uuid"):
                out.add(name)
        return out

    def _handler_param_source(self, p: ast.arg, pid: str, default: Optional[ast.AST],
                              coerced_path: Set[str]) -> None:
        ann = dotted(p.annotation) if p.annotation is not None else ""
        if isinstance(p.annotation, ast.Subscript):
            ann = dotted(p.annotation.value)
        if p.arg in specs.HANDLER_PARAM_SKIP and p.arg != "event":
            return
        if ann.split(".")[-1] in specs.HANDLER_TYPE_SKIP:
            return
        if isinstance(default, ast.Call) and dotted(default.func).split(".")[-1] in ("Depends", "Security"):
            return
        coerced = p.arg in coerced_path or ann.split(".")[-1] in specs.COERCED_TYPES
        src = self.source(f"handler param `{p.arg}`" + (f": {ann}" if ann else ""), p.lineno,
                          p.col_offset, coerced=coerced, param=p.arg)
        if coerced:
            self.cg.flow(src, pid, sanitizes=specs.INJECTION_CLASSES)
        else:
            self.cg.flow(src, pid)

    # --- statements -----------------------------------------------------------
    def walk_body(self, body: Iterable[ast.stmt], module_level: bool = False) -> None:
        for s in body:
            self.stmt(s, module_level)

    def _branch(self, bodies: List[List[ast.stmt]], include_fallthrough: bool = True,
                loop: bool = False) -> None:
        before = {k: set(v) for k, v in self.defs.items()}
        merged: Dict[str, Set[str]] = {k: set(v) for k, v in before.items()} if include_fallthrough else {}
        for body in bodies:
            self.defs = {k: set(v) for k, v in before.items()}
            for _ in range(2 if loop else 1):
                self.walk_body(body)
            for k, v in self.defs.items():
                merged.setdefault(k, set()).update(v)
        self.defs = merged

    def stmt(self, s: ast.stmt, module_level: bool = False) -> None:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if isinstance(s, ast.ClassDef):
                for st in s.body:          # class-level assignments (fields with defaults)
                    if isinstance(st, (ast.Assign, ast.AnnAssign)):
                        self.eval(st.value) if st.value is not None else None
            elif not module_level:
                # Nested function: give it the enclosing scope as closure defs.
                qual = self.fe.cg.g.nodes[self.fid].get("qualname", "")
                fid = f"fn:{self.mod.name}:{qual}.{s.name}"
                if fid in self.fe.fn_defs and fid not in self.fe.built:
                    _FnBuilder(self.fe, self.mod, self.cls, s, fid, self.defs).run()
            return
        if isinstance(s, ast.Assign):
            vals = self.eval(s.value)
            for t in s.targets:
                self.assign(t, vals, s.lineno, module_level)
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None:
                self.assign(s.target, self.eval(s.value), s.lineno, module_level)
        elif isinstance(s, ast.AugAssign):
            vals = self.eval(s.value) | self.eval(s.target)
            self.assign(s.target, vals, s.lineno, module_level)
        elif isinstance(s, ast.Expr):
            self.eval(s.value)
        elif isinstance(s, ast.Return):
            if s.value is not None:
                vals = self.eval(s.value)
                for v in vals:
                    self.cg.flow(v, self.ret)
                self._handler_return_sink(s, vals)
        elif isinstance(s, ast.If):
            self.eval(s.test)
            self._branch([s.body, s.orelse], include_fallthrough=not s.orelse)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            it = self.eval(s.iter)
            self.assign(s.target, it, s.lineno, module_level)
            self._branch([s.body], loop=True)
            if s.orelse:
                self._branch([s.orelse])
        elif isinstance(s, ast.While):
            self.eval(s.test)
            self._branch([s.body], loop=True)
            if s.orelse:
                self._branch([s.orelse])
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                vals = self.eval(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, vals, s.lineno, module_level)
            self.walk_body(s.body)
        elif isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
            self.walk_body(s.body)
            bodies = [h.body for h in s.handlers] + [s.orelse]
            self._branch(bodies)
            self.walk_body(s.finalbody)
        elif isinstance(s, ast.Match):
            self.eval(s.subject)
            self._branch([c.body for c in s.cases])
        elif isinstance(s, ast.Raise):
            if s.exc is not None:
                self.eval(s.exc)
        elif isinstance(s, ast.Assert):
            self.eval(s.test)
        elif isinstance(s, (ast.Delete, ast.Global, ast.Nonlocal, ast.Pass, ast.Break, ast.Continue,
                            ast.Import, ast.ImportFrom)):
            return
        else:
            for child in ast.iter_child_nodes(s):
                if isinstance(child, ast.expr):
                    self.eval(child)

    def _handler_return_sink(self, s: ast.Return, vals: Set[str]) -> None:
        """Flask/Django handlers that return a string built from input -> reflected XSS."""
        if not self.is_entry or (self.route or {}).get("framework") not in ("flask", "registered"):
            return
        v = s.value
        is_str_build = isinstance(v, ast.JoinedStr) or (
            isinstance(v, ast.BinOp) and isinstance(v.op, (ast.Add, ast.Mod))
            and any(isinstance(x, (ast.Constant, ast.JoinedStr)) and isinstance(getattr(x, "value", ""), str)
                    for x in (v.left, v.right))) or (
            isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute) and v.func.attr == "format")
        if not is_str_build or not vals:
            return
        nid = f"a:ret:{self.fid}:{s.lineno}"
        self.cg.node(nid, "arg", fn=self.fid, file=self.mod.rel, line=s.lineno, code=self._code(s.lineno),
                     sinks=[{"class": "xss", "cwe": "CWE-79", "severity": "medium", "owasp": "A03",
                             "title": "Reflected XSS (handler returns HTML built from input)",
                             "sink": "return (text/html response)"}])
        for x in vals:
            self.cg.flow(x, nid)

    # --- assignment -----------------------------------------------------------
    def assign(self, target: ast.AST, vals: Set[str], line: int, module_level: bool = False) -> None:
        if isinstance(target, ast.Name):
            if module_level:
                nid = self.global_node(self.mod.name, target.id)
                for v in vals:
                    self.cg.flow(v, nid)
                self.defs[target.id] = {nid}
                return
            nid = self.new_var(target.id, line)
            for v in vals:
                self.cg.flow(v, nid)
            self.defs[target.id] = {nid}
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt.value if isinstance(elt, ast.Starred) else elt, vals, line, module_level)
        elif isinstance(target, ast.Attribute):
            base = target.value
            if isinstance(base, ast.Name) and base.id == "self" and self.cls:
                fld = self.cg.node(f"fld:{self.mod.name}:{self.cls}.{target.attr}", "field",
                                   name=f"{self.cls}.{target.attr}", fn=self.fid, file=self.mod.rel,
                                   line=line, code=self._code(line))
                for v in vals:
                    self.cg.flow(v, fld)
            else:
                # obj.attr = tainted  ->  obj is now tainted (field-insensitive on locals)
                root = self._root_name(base)
                if root:
                    self._taint_receiver(root, vals, line)
        elif isinstance(target, ast.Subscript):
            self.eval(target.slice)
            root = self._root_name(target.value)
            if root:
                self._taint_receiver(root, vals, line)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, vals, line, module_level)

    @staticmethod
    def _root_name(expr: ast.AST) -> str:
        while isinstance(expr, (ast.Attribute, ast.Subscript)):
            expr = expr.value
        return expr.id if isinstance(expr, ast.Name) else ""

    def _taint_receiver(self, name: str, vals: Set[str], line: int) -> None:
        if not vals or name in ("self", "cls"):
            return
        old = self.defs.get(name, set())
        nid = self.new_var(name, line)
        for v in old | vals:
            self.cg.flow(v, nid)
        self.defs[name] = {nid}

    # --- expressions ----------------------------------------------------------
    def eval(self, e: Optional[ast.AST]) -> Set[str]:
        if e is None:
            return set()
        if isinstance(e, ast.Constant):
            return set()
        if isinstance(e, ast.Name):
            return self._read_name(e.id, e)
        if isinstance(e, ast.Attribute):
            return self._attribute(e)
        if isinstance(e, ast.Subscript):
            self.eval(e.slice)
            vals = self.eval(e.value)
            if isinstance(e.slice, ast.Constant) and isinstance(e.slice.value, str):
                for r in vals:   # request.json["host"] -> the source is field "host"
                    rd = self.cg.g.nodes[r]
                    if rd.get("kind") == "source" and not rd.get("param"):
                        rd["param"] = e.slice.value
            return vals
        if isinstance(e, ast.Call):
            return self.call(e)
        if isinstance(e, ast.Compare):
            for x in [e.left] + e.comparators:
                self.eval(x)
            return set()   # a boolean carries no payload
        if isinstance(e, ast.NamedExpr):
            vals = self.eval(e.value)
            self.assign(e.target, vals, e.lineno)
            return vals
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for gen in e.generators:
                self.assign(gen.target, self.eval(gen.iter), e.lineno)
                for cond in gen.ifs:
                    self.eval(cond)
            if isinstance(e, ast.DictComp):
                return self.eval(e.key) | self.eval(e.value)
            return self.eval(e.elt)
        if isinstance(e, ast.Lambda):
            saved = dict(self.defs)
            for a in e.args.args + e.args.kwonlyargs:
                self.defs[a.arg] = set()
            self.eval(e.body)          # sinks inside the lambda body still count
            self.defs = saved
            return set()
        out: Set[str] = set()
        for child in ast.iter_child_nodes(e):
            if isinstance(child, ast.expr):
                out |= self.eval(child)
            elif isinstance(child, ast.keyword):
                out |= self.eval(child.value)
        return out

    def _read_name(self, name: str, e: ast.AST) -> Set[str]:
        if name in self.defs:
            return set(self.defs[name])
        if name in self.mod.globals:
            return {self.global_node(self.mod.name, name)}
        full = self.mod.imports.get(name, "")
        if self.fe.local_sources and full in specs.PY_LOCAL_SOURCES:
            return {self.source(full, e.lineno, e.col_offset, trust="local")}
        if "." in full:  # from config import SETTING
            modname, _, attr = full.rpartition(".")
            target = self.fe.module(modname)
            if target and attr in target.globals:
                return {self.global_node(target.name, attr)}
        return set()

    def _attribute(self, e: ast.Attribute) -> Set[str]:
        raw = dotted(e)
        full = self.fe.resolve_alias(self.mod, raw)
        if raw and specs.any_match(self.fe.source_attrs, raw, full):
            return {self.source(raw, e.lineno, e.col_offset)}
        if self.fe.local_sources and specs.any_match(specs.PY_LOCAL_SOURCES, full):
            return {self.source(full, e.lineno, e.col_offset, trust="local")}
        base = e.value
        if isinstance(base, ast.Name) and base.id == "self" and self.cls:
            fid = f"fld:{self.mod.name}:{self.cls}.{e.attr}"
            if fid in self.cg.g:
                return {fid}
            return set()
        if isinstance(base, ast.Name) and base.id in self.mod.imports and base.id not in self.defs:
            target = self.fe.module(self.mod.imports[base.id])
            if target and e.attr in target.globals:
                return {self.global_node(target.name, e.attr)}
            return set()
        return self.eval(base)

    def call(self, e: ast.Call) -> Set[str]:
        self._ncall += 1
        raw = dotted(e.func)
        full = self.fe.resolve_alias(self.mod, raw)
        cid = f"c:{self.fid}:{e.lineno}:{e.col_offset}:{self._ncall}"
        self.cg.node(cid, "call", callee=full or raw or "<dynamic>", raw=raw, fn=self.fid,
                     file=self.mod.rel, line=e.lineno, code=self._code(e.lineno))
        self.cg.flow(self.fid, cid, kind="contains")

        # Receiver value (``x`` in ``x.strip()``).
        recv: Set[str] = set()
        if isinstance(e.func, ast.Attribute):
            recv = self.eval(e.func.value)
        elif not raw:
            recv = self.eval(e.func)

        # Argument nodes.
        args: List[Tuple[Any, str, Set[str]]] = []   # (position|kw, node id, value nodes)
        for i, a in enumerate(e.args):
            node = a.value if isinstance(a, ast.Starred) else a
            vals = self.eval(node)
            aid = self.cg.node(f"a:{cid}:{i}", "arg", pos=i, fn=self.fid, file=self.mod.rel,
                               line=getattr(node, "lineno", e.lineno), code=self._code(e.lineno), call=cid)
            for v in vals:
                self.cg.flow(v, aid)
            args.append((i if not isinstance(a, ast.Starred) else "*", aid, vals))
        for kw in e.keywords:
            vals = self.eval(kw.value)
            key = kw.arg if kw.arg is not None else "**"
            aid = self.cg.node(f"a:{cid}:{key}", "arg", pos=key, fn=self.fid, file=self.mod.rel,
                               line=e.lineno, code=self._code(e.lineno), call=cid)
            for v in vals:
                self.cg.flow(v, aid)
            args.append((key, aid, vals))

        names = (full, raw)

        # Sources produced by a call (request.get_json(), input()).
        recv_is_source = any(self.cg.g.nodes[r].get("kind") == "source" for r in recv)
        if not recv_is_source and specs.any_match(self.fe.source_calls, *names):
            src = self.source(f"{raw}()", e.lineno, e.col_offset)
            self.cg.flow(src, cid)
        elif recv_is_source and e.args and isinstance(e.args[0], ast.Constant) \
                and isinstance(e.args[0].value, str):
            for r in recv:   # request.args.get("q") -> the source is field "q"
                rd = self.cg.g.nodes[r]
                if rd.get("kind") == "source" and not rd.get("param"):
                    rd["param"] = e.args[0].value
        elif self.fe.local_sources and specs.any_match(("input", "os.getenv", "os.environ.get"), *names):
            self.cg.flow(self.source(f"{full}()", e.lineno, e.col_offset, trust="local"), cid)

        # Sinks: annotate the argument nodes that reach them.
        self._annotate_sinks(e, names, args)

        # Project call targets.
        targets = self.fe.resolve_name(self.mod, self.cls, raw, self.qual)
        weak = False
        if not targets and isinstance(e.func, ast.Attribute) and not specs.any_match(
                [p for s in self.fe.sinks for p in s.names], *names):
            targets = self.fe.weak_methods(e.func.attr)
            weak = bool(targets)

        san = specs.sanitizer_classes(self.fe.sanitizers, *names)
        if targets:
            for t in targets:
                self._bind(cid, t, e, args, recv, weak)
                if self.cg.g.nodes[t].get("name") == "__init__":
                    # The constructed object carries its constructor arguments.
                    for _, aid, _ in args:
                        self.cg.flow(aid, cid)
        elif san is not None:
            if specs.ALL not in san:
                for _, aid, _ in args:
                    self.cg.flow(aid, cid, sanitizes=san)
                for r in recv:
                    self.cg.flow(r, cid, sanitizes=san)
        else:
            # Unknown library call: result depends on arguments and receiver.
            for _, aid, _ in args:
                self.cg.flow(aid, cid)
            for r in recv:
                self.cg.flow(r, cid)
            if isinstance(e.func, ast.Attribute) and e.func.attr in specs.MUTATORS:
                root = self._root_name(e.func.value)
                if root:
                    self._taint_receiver(root, {aid for _, aid, _ in args}, e.lineno)

        # Mass assignment: Model(**request.json) / obj.__dict__.update(data).
        is_ctor = any(self.cg.g.nodes[t].get("name") == "__init__" for t in targets) or (
            (raw.split(".")[-1][:1].isupper()) and not raw.isupper())
        if is_ctor or (raw.endswith("__dict__.update")):
            for key, aid, vals in args:
                if key == "**" or (raw.endswith("__dict__.update") and key == 0):
                    self._add_sink(aid, {"class": "mass_assignment", "cwe": "CWE-915", "severity": "high",
                                         "owasp": "API3", "title": "Mass assignment / BOPLA "
                                         "(request data expanded into object attributes)", "sink": raw,
                                         "whole_object": True})
        self._deferred(e, cid, raw, args)

        # BOLA candidates: ORM lookup keyed by attacker data.
        if specs.any_match(specs.PY_OBJECT_LOOKUPS, *names):
            for _, aid, _ in args:
                self._add_sink(aid, {"class": "bola", "cwe": "CWE-639", "severity": "high", "owasp": "API1",
                                     "title": "Object lookup keyed by client-supplied id (BOLA candidate)",
                                     "sink": raw, "lookup": True})
        return {cid}

    def _deferred(self, e: ast.Call, cid: str, raw: str, args) -> None:
        """``queue.enqueue(fn, a, b)`` / ``Thread(target=fn, args=(a,))`` / ``fn.delay(a)``:
        bind the arguments to ``fn``'s parameters as if it were called here."""
        tail = raw.split(".")[-1]
        fn_expr: Optional[ast.AST] = None
        arg_exprs: List[Tuple[Any, ast.AST]] = []
        if tail in ("delay", "apply_async", "s", "si") and isinstance(e.func, ast.Attribute):
            fn_expr = e.func.value                       # celery: task.delay(a, b)
            if tail == "apply_async":
                for kw in e.keywords:
                    if kw.arg == "args" and isinstance(kw.value, (ast.Tuple, ast.List)):
                        arg_exprs = list(enumerate(kw.value.elts))
            else:
                arg_exprs = list(enumerate(e.args))
        elif tail in specs.DEFERRED_CALLS:
            where, src = specs.DEFERRED_CALLS[tail]
            kw = {k.arg: k.value for k in e.keywords if k.arg}
            if isinstance(where, int):
                if len(e.args) <= where:
                    return
                fn_expr = e.args[where]
                if src == "rest":
                    arg_exprs = list(enumerate(e.args[where + 1:]))
            else:
                fn_expr = kw.get(where)
            if src == "args":
                tup = kw.get("args") or (e.args[where + 1] if isinstance(where, int)
                                         and len(e.args) > where + 1 else None)
                if isinstance(tup, (ast.Tuple, ast.List)):
                    arg_exprs = list(enumerate(tup.elts))
            if isinstance(kw.get("kwargs"), ast.Dict):
                for k, v in zip(kw["kwargs"].keys, kw["kwargs"].values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        arg_exprs.append((k.value, v))
            if src == "rest":
                arg_exprs += [(k.arg, k.value) for k in e.keywords
                              if k.arg and k.arg not in ("job_timeout", "result_ttl", "ttl", "job_id",
                                                          "depends_on", "at_front", "retry", "timeout")]
        if fn_expr is None:
            return
        targets = self.fe.resolve_name(self.mod, self.cls, dotted(fn_expr), self.qual)
        if not targets:
            return
        bound = []
        for key, ex in arg_exprs:
            vals = self.eval(ex)
            aid = self.cg.node(f"a:{cid}:d{key}", "arg", pos=key, fn=self.fid, file=self.mod.rel,
                               line=getattr(ex, "lineno", e.lineno), code=self._code(e.lineno), call=cid)
            for v in vals:
                self.cg.flow(v, aid)
            bound.append((key, aid, vals))
        for t in targets:
            self._bind(cid, t, e, bound, set(), weak=False, returns=False)

    def _annotate_sinks(self, e: ast.Call, names: Tuple[str, str], args) -> None:
        kw_map = {kw.arg: kw.value for kw in e.keywords if kw.arg}
        for spec in specs.find_sinks(self.fe.sinks, *names):
            if spec.requires_kw:
                ok = all(isinstance(kw_map.get(k), ast.Constant) and kw_map[k].value == v
                         for k, v in spec.requires_kw.items())
                if not ok:
                    continue
            if any(k in kw_map for k in spec.unless_kw):
                continue
            for key, aid, _ in args:
                if spec.any_arg or key in spec.args or key in spec.kwargs or key == "*":
                    self._add_sink(aid, {"class": spec.vclass, "cwe": spec.cwe, "severity": spec.severity,
                                         "owasp": spec.owasp, "title": spec.title, "sink": names[0] or names[1]})

    def _add_sink(self, aid: str, info: Dict[str, Any]) -> None:
        d = self.cg.g.nodes[aid]
        lst = d.setdefault("sinks", [])
        if not any(x["class"] == info["class"] for x in lst):
            lst.append(info)

    def _bind(self, cid: str, target: str, e: ast.Call, args, recv: Set[str], weak: bool,
              returns: bool = True) -> None:
        self.cg.flow(self.fid, target, kind="calls", weak=weak)
        tdata = self.cg.g.nodes[target]
        params: List[str] = tdata.get("params", [])
        offset = 1 if params and params[0] in ("self", "cls") else 0
        for key, aid, _ in args:
            pname = None
            if isinstance(key, int):
                idx = key + offset
                if idx < len(params):
                    pname = params[idx]
            elif key in ("*", "**"):
                for p in params[offset:]:
                    self.cg.flow(aid, f"p:{target}:{p}", kind="call", site=cid, weak=weak)
                continue
            else:
                pname = key if key in params else None
            if pname:
                pid = f"p:{target}:{pname}"
                self.cg.node(pid, "param", name=pname, fn=target, file=tdata.get("file"),
                             line=tdata.get("line"), code=tdata.get("code"))
                self.cg.flow(aid, pid, kind="call", site=cid, weak=weak)
        if offset and recv:
            pid = f"p:{target}:{params[0]}"
            self.cg.node(pid, "param", name=params[0], fn=target, file=tdata.get("file"),
                         line=tdata.get("line"), code=tdata.get("code"))
            for r in recv:
                self.cg.flow(r, pid, kind="call", site=cid, weak=weak)
        if returns:
            self.cg.flow(f"ret:{target}", cid, kind="ret", site=cid, weak=weak)
