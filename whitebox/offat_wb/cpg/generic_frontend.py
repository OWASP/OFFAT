"""Profile-driven multi-language frontend.

One tree-sitter taint builder driven by a per-language :class:`GrammarProfile`,
so a new language is a data table, not a new frontend. Ships concrete profiles
for **Ruby** and **PHP**, plus a **generic** profile that applies conservative
structural heuristics (function defs, calls, string concatenation) to any other
tree-sitter grammar with a shared cross-language sink/source catalog.

It models what the per-language frontends do, at lower resolution: function
bodies, versioned locals, string-concatenation taint, call arguments, a shallow
interprocedural call/return binding (resolved by function name), request/
superglobal sources, and spec sinks/sanitizers. Findings carry a proven path;
generic-profile findings are marked lower confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import tree_sitter_language_pack as tslp

from . import specs
from .graph import CodeGraph


@dataclass
class GrammarProfile:
    name: str
    exts: Tuple[str, ...]
    ts_lang: str
    sinks: List[specs.SinkSpec]
    sanitizers: List[specs.SanitizerSpec]
    func_types: Tuple[str, ...] = ()
    call_types: Tuple[str, ...] = ()
    assign_types: Tuple[str, ...] = ()
    binary_types: Tuple[str, ...] = ()
    concat_ops: Tuple[str, ...] = ("+", ".", "<<", "%")
    member_types: Tuple[str, ...] = ()
    name_field: str = "name"
    body_field: str = "body"
    args_field: str = "arguments"
    source_globals: Tuple[str, ...] = ()
    source_patterns: Tuple[str, ...] = ()
    strip_prefix: str = ""
    echo_types: Tuple[str, ...] = ()   # statements whose args are a direct XSS sink (PHP echo)
    generic: bool = False      # heuristic node-type matching for unknown grammars

    def is_func(self, t: str) -> bool:
        if self.generic:
            return (("function" in t or "method" in t) and
                    ("declaration" in t or "definition" in t or "item" in t))
        return t in self.func_types

    def is_call(self, t: str) -> bool:
        if self.generic:
            return "call" in t or "invocation" in t
        return t in self.call_types

    def is_assign(self, t: str) -> bool:
        if self.generic:
            return "assignment" in t
        return t in self.assign_types

    def is_binary(self, t: str) -> bool:
        if self.generic:
            return t in ("binary_expression", "binary")
        return t in self.binary_types


class GenericFrontend:
    lang = "generic"

    def __init__(self, profile: GrammarProfile, root: str, cg: CodeGraph) -> None:
        self.p = profile
        self.lang = profile.name
        self.root = root
        self.cg = cg
        self.modules: Dict[str, Any] = {}
        self.src_by_mod: Dict[str, bytes] = {}
        self.functions: Dict[str, str] = {}         # name -> fid (last wins)
        self.fn_nodes: Dict[str, Tuple[str, Any]] = {}
        self.built: Set[str] = set()
        self.parse_errors: List[str] = []

    # --- parse / index ------------------------------------------------------
    def add_file(self, path: str) -> None:
        import os
        rel = os.path.relpath(path, self.root)
        try:
            with open(path, "rb") as fh:
                src = fh.read()
            tree = tslp.get_parser(self.p.ts_lang).parse(src)
        except Exception as exc:  # noqa: BLE001
            self.parse_errors.append(f"{rel}: {exc}")
            return
        self.cg.lines[rel] = src.decode("utf-8", "ignore").splitlines(keepends=True)
        self.modules[rel] = tree
        self.src_by_mod[rel] = src
        self._index(rel, tree.root_node)

    def text(self, rel: str, n: Any) -> str:
        if n is None:
            return ""
        return self.src_by_mod[rel][n.start_byte:n.end_byte].decode("utf-8", "ignore")

    def _index(self, rel: str, root: Any) -> None:
        def walk(n: Any) -> None:
            if self.p.is_func(n.type):
                name_node = n.child_by_field_name(self.p.name_field)
                name = self.text(rel, name_node).strip(self.p.strip_prefix) or f"<anon>@{n.start_point[0] + 1}"
                fid = f"fn:{rel}:{name}@{n.start_point[0] + 1}"
                line = n.start_point[0] + 1
                self.cg.node(fid, "function", name=name, qualname=name, module=rel, file=rel,
                             line=line, end_line=n.end_point[0] + 1, params=self._params(rel, n),
                             lang=self.p.name, fn=fid, code=self.cg.code_at(rel, line),
                             entry=True, route=None, decorators=[])
                self.cg.node(f"ret:{fid}", "return", fn=fid, file=rel, line=line)
                self.functions.setdefault(name, fid)
                self.fn_nodes[fid] = (rel, n)
            for c in n.named_children:
                walk(c)
        walk(root)

    def _params(self, rel: str, fn: Any) -> List[str]:
        ps = fn.child_by_field_name("parameters")
        if ps is None:
            return []
        out = []
        for p in ps.named_children:
            txt = self.text(rel, p).strip(self.p.strip_prefix).split("=")[0].split(":")[0].strip()
            # take the first identifier-ish token
            tok = "".join(ch for ch in txt if ch.isalnum() or ch == "_")
            out.append(tok or f"_p{len(out)}")
        return out

    def build(self) -> None:
        for fid, (rel, n) in list(self.fn_nodes.items()):
            if fid not in self.built:
                _Builder(self, rel, fid, n).run()

    def resolve(self, callee: str) -> List[str]:
        name = callee.split(".")[-1]
        fid = self.functions.get(name)
        return [fid] if fid else []


class _Builder:
    def __init__(self, fe: GenericFrontend, rel: str, fid: str, node: Any) -> None:
        self.fe = fe
        self.p = fe.p
        self.cg = fe.cg
        self.rel = rel
        self.fid = fid
        self.node = node
        self.defs: Dict[str, Set[str]] = {}
        self.counter: Dict[str, int] = {}
        self.ret = f"ret:{fid}"
        self._n = 0

    def t(self, n: Any) -> str:
        return self.fe.text(self.rel, n)

    def line(self, n: Any) -> int:
        return n.start_point[0] + 1

    def code(self, ln: int) -> str:
        return self.cg.code_at(self.rel, ln)

    def new_var(self, name: str, ln: int) -> str:
        k = self.counter.get(name, 0) + 1
        self.counter[name] = k
        return self.cg.node(f"v:{self.fid}:{name}#{k}", "var", name=name, fn=self.fid, file=self.rel,
                            line=ln, code=self.code(ln))

    def source(self, label: str, n: Any) -> str:
        ln = self.line(n)
        return self.cg.node(f"src:{self.fid}:{ln}:{n.start_point[1]}:{label}", "source", label=label,
                            fn=self.fid, file=self.rel, line=ln, code=self.code(ln), trust="remote")

    # --- callee flattening --------------------------------------------------
    def dotted(self, n: Any) -> str:
        if n is None:
            return ""
        t = n.type
        if t in ("identifier", "name", "variable_name", "field_identifier", "constant",
                 "property_identifier", "type_identifier", "simple_identifier"):
            return self.t(n).strip(self.p.strip_prefix)
        if self.p.is_call(t):
            callee = (n.child_by_field_name("function") or n.child_by_field_name("method")
                      or n.child_by_field_name("name"))
            recv = (n.child_by_field_name("receiver") or n.child_by_field_name("object"))
            base = self.dotted(recv) if recv is not None else ""
            return (base + "." if base else "") + self.dotted(callee)
        # member / field access across grammars
        obj = (n.child_by_field_name("object") or n.child_by_field_name("receiver")
               or n.child_by_field_name("operand") or n.child_by_field_name("scope"))
        fld = (n.child_by_field_name("name") or n.child_by_field_name("field")
               or n.child_by_field_name("property"))
        if obj is not None or fld is not None:
            base = self.dotted(obj) if obj is not None else ""
            return (base + "." if base else "") + (self.dotted(fld) if fld is not None else "")
        if n.named_child_count == 1:
            return self.dotted(n.named_children[0])
        return ""

    # --- statements / expressions ------------------------------------------
    def run(self) -> None:
        self.fe.built.add(self.fid)
        for prm in self.cg.g.nodes[self.fid].get("params", []):
            self.defs[prm] = {self.cg.node(f"p:{self.fid}:{prm}", "param", name=prm, fn=self.fid,
                                           file=self.rel, line=self.cg.g.nodes[self.fid].get("line"), code="")}
        body = self.node.child_by_field_name(self.p.body_field)
        self.walk(body if body is not None else self.node)

    def walk(self, n: Any) -> None:
        if n is None:
            return
        for c in n.named_children:
            self.stmt(c)

    def stmt(self, n: Any) -> None:
        t = n.type
        if t in self.p.echo_types:
            for c in n.named_children:
                vals = self.eval(c)
                if not vals:
                    continue
                aid = self.cg.node(f"a:echo:{self.fid}:{self.line(n)}:{c.start_point[1]}", "arg",
                                   fn=self.fid, file=self.rel, line=self.line(n), code=self.code(self.line(n)))
                aid_d = self.cg.g.nodes[aid]
                aid_d.setdefault("sinks", []).append({"class": "xss", "cwe": "CWE-79", "severity": "medium",
                                                      "owasp": "A03", "title": "Reflected XSS (echo of input)",
                                                      "sink": "echo"})
                for v in vals:
                    self.cg.flow(v, aid)
            return
        if self.p.is_assign(t):
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            vals = self.eval(right)
            self._bind(left, vals)
            return
        # variable declarations (Java local_variable_declaration, Rust let_declaration, ...)
        if "declaration" in t or t == "let_declaration":
            self._declare(n)
            return
        if self.p.is_func(t):
            fid = f"fn:{self.rel}:{self.t(n.child_by_field_name(self.p.name_field)).strip(self.p.strip_prefix)}@{n.start_point[0] + 1}"
            if fid in self.fe.fn_nodes and fid not in self.fe.built:
                _Builder(self.fe, self.rel, fid, n).run()
            return
        if "return" in t:
            for c in n.named_children:
                for v in self.eval(c):
                    self.cg.flow(v, self.ret)
            return
        # control-flow and blocks: recurse, evaluating expressions
        if n.named_child_count and (t.endswith(("statement", "block", "body_statement", "compound_statement",
                                                "do_block", "then", "else", "elsif", "case", "when"))
                                    or "if" in t or "for" in t or "while" in t or "each" in t):
            self.walk(n)
            return
        self.eval(n)

    def eval(self, n: Any) -> Set[str]:
        if n is None:
            return set()
        t = n.type
        if t in ("identifier", "variable_name", "simple_identifier", "constant"):
            name = self.t(n).strip(self.p.strip_prefix)
            if n.type == "variable_name" and self.t(n) in self.p.source_globals:
                return {self.source(self.t(n), n)}
            if name in self.p.source_globals:
                return {self.source(name, n)}
            return set(self.defs.get(name, set()))
        if "string" in t and "interpolation" not in t and t != "string_content":
            # string literal, but descend into interpolations if present
            out: Set[str] = set()
            for c in n.named_children:
                if "interpolation" in c.type or "embedded" in c.type:
                    for g in c.named_children:
                        out |= self.eval(g)
            return out
        if t in ("integer", "float", "true", "false", "nil", "null", "boolean"):
            return set()
        if self.p.is_binary(t):
            op = n.child_by_field_name("operator")
            l = self.eval(n.child_by_field_name("left"))
            r = self.eval(n.child_by_field_name("right"))
            if op is not None and self.t(op) not in self.p.concat_ops:
                return set()
            return l | r
        if t in ("subscript_expression", "element_reference", "index_expression", "array_access",
                 "subscript"):
            obj = (n.child_by_field_name("object") or n.child_by_field_name("operand")
                   or (n.named_children[0] if n.named_children else None))
            return self.eval(obj)
        if self.p.is_call(t):
            return self.call(n)
        # member access that is itself a source (dotted matches a source pattern)
        dotted = self.dotted(n)
        if dotted and specs.any_match(self.p.source_patterns, dotted):
            return {self.source(dotted, n)}
        out = set()
        for c in n.named_children:
            out |= self.eval(c)
        return out

    def _bind(self, target: Any, vals: Set[str]) -> None:
        if target is None:
            return
        if target.type in ("identifier", "variable_name", "simple_identifier", "constant"):
            name = self.t(target).strip(self.p.strip_prefix)
            nid = self.new_var(name, self.line(target))
            for v in vals:
                self.cg.flow(v, nid)
            self.defs[name] = {nid}
        else:
            for c in target.named_children:
                self._bind(c, vals)

    def _declare(self, n: Any) -> None:
        """Bind a variable declaration: ``T x = expr`` / ``let x = expr`` / ``var x = expr``.

        Handles both direct name+value fields and nested declarators (Java/JS style).
        """
        name_node = n.child_by_field_name("name") or n.child_by_field_name("pattern")
        value = n.child_by_field_name("value")
        if value is not None and name_node is not None:
            self._bind(name_node, self.eval(value))
            return
        for c in n.named_children:
            if c.type in ("variable_declarator", "init_declarator", "declarator"):
                nm = c.child_by_field_name("name") or c.child_by_field_name("declarator")
                val = c.child_by_field_name("value")
                if val is not None and nm is not None:
                    self._bind(nm, self.eval(val))
            elif "declaration" in c.type or c.type == "let_declaration":
                self._declare(c)

    def call(self, n: Any) -> Set[str]:
        self._n += 1
        raw = self.dotted(n)
        ln = self.line(n)
        cid = self.cg.node(f"c:{self.fid}:{ln}:{n.start_point[1]}:{self._n}", "call", callee=raw or "<dyn>",
                           raw=raw, fn=self.fid, file=self.rel, line=ln, code=self.code(ln))
        self.cg.flow(self.fid, cid, kind="contains")

        args_node = n.child_by_field_name(self.p.args_field)
        args: List[Tuple[int, str, Set[str]]] = []
        if args_node is not None:
            idx = 0
            for a in args_node.named_children:
                if a.type in ("block", "block_argument", "do_block"):
                    self.eval(a)
                    continue
                vals = self.eval(a)
                aid = self.cg.node(f"a:{cid}:{idx}", "arg", pos=idx, fn=self.fid, file=self.rel,
                                   line=self.line(a), code=self.code(ln), call=cid)
                for v in vals:
                    self.cg.flow(v, aid)
                args.append((idx, aid, vals))
                idx += 1

        # source call (e.g. request.params, params.require)
        if specs.any_match(self.p.source_patterns, raw):
            self.cg.flow(self.source(raw, n), cid)

        for spec in specs.find_sinks(self.p.sinks, raw):
            for key, aid, _ in args:
                if spec.any_arg or key in spec.args:
                    d = self.cg.g.nodes[aid]
                    if not any(x["class"] == spec.vclass for x in d.get("sinks", [])):
                        d.setdefault("sinks", []).append(
                            {"class": spec.vclass, "cwe": spec.cwe, "severity": spec.severity,
                             "owasp": spec.owasp, "title": spec.title, "sink": raw,
                             "generic": self.p.generic})

        targets = self.fe.resolve(raw)
        san = specs.sanitizer_classes(self.p.sanitizers, raw)
        if targets:
            for tgt in targets:
                self._bind_call(cid, tgt, args)
        elif san is not None:
            if specs.ALL not in san:
                for _, aid, _ in args:
                    self.cg.flow(aid, cid, sanitizes=san)
        else:
            for _, aid, _ in args:
                self.cg.flow(aid, cid)
            # receiver taint passes through
            recv = n.child_by_field_name("receiver") or n.child_by_field_name("object")
            if recv is not None:
                for v in self.eval(recv):
                    self.cg.flow(v, cid)
        return {cid}

    def _bind_call(self, cid: str, target: str, args) -> None:
        self.cg.flow(self.fid, target, kind="calls")
        td = self.cg.g.nodes[target]
        params = td.get("params", [])
        for key, aid, _ in args:
            if isinstance(key, int) and key < len(params):
                pid = self.cg.node(f"p:{target}:{params[key]}", "param", name=params[key], fn=target,
                                   file=td.get("file"), line=td.get("line"), code=td.get("code"))
                self.cg.flow(aid, pid, kind="call", site=cid)
        self.cg.flow(f"ret:{target}", cid, kind="ret", site=cid)


# --- profiles ---------------------------------------------------------------

RUBY = GrammarProfile(
    name="ruby", exts=(".rb",), ts_lang="ruby",
    sinks=specs.RUBY_SINKS, sanitizers=specs.RUBY_SANITIZERS,
    func_types=("method", "singleton_method"), call_types=("call", "command", "command_call"),
    assign_types=("assignment", "operator_assignment"), binary_types=("binary",),
    concat_ops=("+", "<<", "%", "concat"), member_types=("call", "scope_resolution"),
    args_field="arguments", source_globals=("params", "request", "cookies", "session"),
    source_patterns=specs.RUBY_SOURCE_ROOTS + ("params.require", "params.permit", "params.fetch",
                                               "*.require", "*.permit", "request.params"),
)

PHP = GrammarProfile(
    name="php", exts=(".php",), ts_lang="php",
    sinks=specs.PHP_SINKS, sanitizers=specs.PHP_SANITIZERS,
    func_types=("function_definition", "method_declaration"),
    call_types=("function_call_expression", "member_call_expression", "scoped_call_expression",
                "nullsafe_member_call_expression"),
    assign_types=("assignment_expression", "augmented_assignment_expression"),
    binary_types=("binary_expression",), concat_ops=(".", "+"),
    member_types=("member_access_expression", "scoped_property_access_expression"),
    args_field="arguments", strip_prefix="$", source_globals=specs.PHP_SOURCE_GLOBALS,
    source_patterns=("*.getQuery", "*.get_query", "*.input", "*.query", "request.get"),
    echo_types=("echo_statement", "print_intrinsic"),
)


def generic_profile(ts_lang: str, name: str, exts: Tuple[str, ...]) -> GrammarProfile:
    return GrammarProfile(
        name=name, exts=exts, ts_lang=ts_lang, generic=True,
        sinks=specs.GENERIC_SINKS, sanitizers=specs.GENERIC_SANITIZERS,
        source_patterns=("*.getParameter", "*.getQueryString", "*.Query", "*.FormValue",
                         "request.getParameter", "*.query", "*.params", "*.body"),
    )


# Languages routed through the generic heuristic profile (no dedicated frontend).
GENERIC_LANGS = {
    ".java": ("java", "java"), ".kt": ("kotlin", "kotlin"),
    ".cs": ("csharp", "c_sharp"), ".rs": ("rust", "rust"),
    ".scala": ("scala", "scala"),
}

PROFILES: Dict[str, GrammarProfile] = {".rb": RUBY, ".php": PHP}
