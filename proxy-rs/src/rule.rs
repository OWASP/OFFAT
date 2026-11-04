//! Rule engine + expression interpreter ("bambdas").
//!
//! A safe, sandboxed little language lets you match flows and act on them live -
//! block/allow, drop, tag/highlight, and match-and-replace on headers or bodies -
//! and the same expressions filter captured history. It is an interpreter over a
//! fixed set of flow fields, **not** an eval of arbitrary code: there is no I/O,
//! no host access, and nothing executes. All target-derived values are data.
//!
//! Example rules (one per line; `#` comments):
//! ```text
//! # block a path unless the caller has the admin role
//! block respond 403 "forbidden" when path contains "/admin" && header["x-role"] != "admin"
//! drop when host endswith ".ads.test"
//! allow when host == "api.example.test"
//! tag "login" when path endswith "/login"
//! set-req-header "X-OFFAT: 1" when in_scope
//! replace-resp "secret" -> "<redacted>" when status == 200
//! ```
//!
//! Filter expressions (for history) are just the `when` part, e.g.
//! `status >= 500 || (method == "POST" && path contains "/api")`.

use crate::flow::{Flow, Header};
use crate::util::wildcard_match;

// ----------------------------------------------------------------------------
// Expression AST + evaluation
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Expr {
    Bool(bool),
    /// A bare field reference, true when "truthy".
    Truthy(Field),
    Cmp(Field, Op, Lit),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone)]
enum Field {
    Simple(String),
    /// Indexed field such as `header["name"]`.
    Indexed(String, String),
}

#[derive(Debug, Clone, PartialEq)]
enum Op {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug, Clone)]
enum Lit {
    Str(String),
    Num(f64),
    Bool(bool),
}

/// Evaluation context: a view over a flow's fields.
pub struct Ctx<'a> {
    flow: &'a Flow,
}

impl<'a> Ctx<'a> {
    pub fn new(flow: &'a Flow) -> Self {
        Self { flow }
    }

    fn simple(&self, name: &str) -> FieldVal {
        let r = &self.flow.request;
        match name {
            "method" => FieldVal::S(r.method.clone()),
            "host" => FieldVal::S(r.host.clone()),
            "path" => FieldVal::S(path_only(&r.path)),
            "query" => FieldVal::S(query_only(&r.path)),
            "url" => FieldVal::S(self.flow.url()),
            "scheme" => FieldVal::S(r.scheme.clone()),
            "body" => FieldVal::S(r.body.clone()),
            "in_scope" => FieldVal::B(self.flow.in_scope),
            "intercepted" => FieldVal::B(self.flow.intercepted),
            "tags" => FieldVal::S(self.flow.tags.join(" ")),
            "status" => self
                .flow
                .response
                .as_ref()
                .map(|r| FieldVal::N(r.status as f64))
                .unwrap_or(FieldVal::Missing),
            "resp_body" => self
                .flow
                .response
                .as_ref()
                .map(|r| FieldVal::S(r.body.clone()))
                .unwrap_or(FieldVal::Missing),
            "content_type" => self
                .flow
                .response
                .as_ref()
                .map(|r| FieldVal::S(r.content_type.clone()))
                .unwrap_or(FieldVal::Missing),
            _ => FieldVal::Missing,
        }
    }

    fn indexed(&self, name: &str, key: &str) -> FieldVal {
        match name {
            "header" => header_val(&self.flow.request.headers, key),
            "resp_header" => self
                .flow
                .response
                .as_ref()
                .map(|r| header_val(&r.headers, key))
                .unwrap_or(FieldVal::Missing),
            "query" => query_param(&self.flow.request.path, key),
            _ => FieldVal::Missing,
        }
    }

    fn resolve(&self, f: &Field) -> FieldVal {
        match f {
            Field::Simple(n) => self.simple(n),
            Field::Indexed(n, k) => self.indexed(n, k),
        }
    }
}

enum FieldVal {
    S(String),
    N(f64),
    B(bool),
    Missing,
}

impl FieldVal {
    fn as_string(&self) -> String {
        match self {
            FieldVal::S(s) => s.clone(),
            FieldVal::N(n) => trim_num(*n),
            FieldVal::B(b) => b.to_string(),
            FieldVal::Missing => String::new(),
        }
    }
    fn as_num(&self) -> Option<f64> {
        match self {
            FieldVal::N(n) => Some(*n),
            FieldVal::S(s) => s.trim().parse().ok(),
            FieldVal::B(_) | FieldVal::Missing => None,
        }
    }
    fn truthy(&self) -> bool {
        match self {
            FieldVal::S(s) => !s.is_empty(),
            FieldVal::N(n) => *n != 0.0,
            FieldVal::B(b) => *b,
            FieldVal::Missing => false,
        }
    }
}

impl Expr {
    fn eval(&self, ctx: &Ctx) -> bool {
        match self {
            Expr::Bool(b) => *b,
            Expr::Truthy(f) => ctx.resolve(f).truthy(),
            Expr::Not(e) => !e.eval(ctx),
            Expr::And(a, b) => a.eval(ctx) && b.eval(ctx),
            Expr::Or(a, b) => a.eval(ctx) || b.eval(ctx),
            Expr::Cmp(f, op, lit) => {
                let v = ctx.resolve(f);
                match op {
                    Op::Lt | Op::Gt | Op::Le | Op::Ge => {
                        let (lhs, rhs) = match (v.as_num(), lit_num(lit)) {
                            (Some(a), Some(b)) => (a, b),
                            _ => return false,
                        };
                        match op {
                            Op::Lt => lhs < rhs,
                            Op::Gt => lhs > rhs,
                            Op::Le => lhs <= rhs,
                            Op::Ge => lhs >= rhs,
                            _ => unreachable!(),
                        }
                    }
                    _ => {
                        let lhs = v.as_string();
                        let rhs = lit_str(lit);
                        match op {
                            Op::Eq => lhs == rhs,
                            Op::Ne => lhs != rhs,
                            Op::Contains => lhs.contains(&rhs),
                            Op::StartsWith => lhs.starts_with(&rhs),
                            Op::EndsWith => lhs.ends_with(&rhs),
                            Op::Matches => wildcard_match(&rhs, &lhs),
                            _ => unreachable!(),
                        }
                    }
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Tokenizer + recursive-descent parser for expressions
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Num(f64),
    Bool(bool),
    LBracket,
    RBracket,
    LParen,
    RParen,
    And,
    Or,
    Not,
    Op(Op),
}

fn lex(input: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut toks = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' | '\n' => i += 1,
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                toks.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                toks.push(Tok::RBracket);
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let mut s = String::new();
                while i < chars.len() && chars[i] != quote {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                        s.push(chars[i]);
                    } else {
                        s.push(chars[i]);
                    }
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("unterminated string literal".into());
                }
                i += 1; // closing quote
                toks.push(Tok::Str(s));
            }
            '&' if peek(&chars, i + 1) == Some('&') => {
                toks.push(Tok::And);
                i += 2;
            }
            '|' if peek(&chars, i + 1) == Some('|') => {
                toks.push(Tok::Or);
                i += 2;
            }
            '!' if peek(&chars, i + 1) == Some('=') => {
                toks.push(Tok::Op(Op::Ne));
                i += 2;
            }
            '!' => {
                toks.push(Tok::Not);
                i += 1;
            }
            '=' if peek(&chars, i + 1) == Some('=') => {
                toks.push(Tok::Op(Op::Eq));
                i += 2;
            }
            '<' if peek(&chars, i + 1) == Some('=') => {
                toks.push(Tok::Op(Op::Le));
                i += 2;
            }
            '>' if peek(&chars, i + 1) == Some('=') => {
                toks.push(Tok::Op(Op::Ge));
                i += 2;
            }
            '<' => {
                toks.push(Tok::Op(Op::Lt));
                i += 1;
            }
            '>' => {
                toks.push(Tok::Op(Op::Gt));
                i += 1;
            }
            c if c.is_ascii_digit()
                || (c == '-' && peek(&chars, i + 1).is_some_and(|d| d.is_ascii_digit())) =>
            {
                let mut s = String::new();
                if c == '-' {
                    s.push('-');
                    i += 1;
                }
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    s.push(chars[i]);
                    i += 1;
                }
                toks.push(Tok::Num(s.parse().map_err(|_| format!("bad number: {s}"))?));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut s = String::new();
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    s.push(chars[i]);
                    i += 1;
                }
                match s.as_str() {
                    "and" => toks.push(Tok::And),
                    "or" => toks.push(Tok::Or),
                    "not" => toks.push(Tok::Not),
                    "true" => toks.push(Tok::Bool(true)),
                    "false" => toks.push(Tok::Bool(false)),
                    "contains" => toks.push(Tok::Op(Op::Contains)),
                    "startswith" => toks.push(Tok::Op(Op::StartsWith)),
                    "endswith" => toks.push(Tok::Op(Op::EndsWith)),
                    "matches" => toks.push(Tok::Op(Op::Matches)),
                    _ => toks.push(Tok::Ident(s)),
                }
            }
            other => return Err(format!("unexpected character: {other}")),
        }
    }
    Ok(toks)
}

fn peek(chars: &[char], i: usize) -> Option<char> {
    chars.get(i).copied()
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn new(toks: Vec<Tok>) -> Self {
        Self { toks, pos: 0 }
    }
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn parse(&mut self) -> Result<Expr, String> {
        let e = self.parse_or()?;
        if self.pos != self.toks.len() {
            return Err(format!("trailing tokens after expression at {}", self.pos));
        }
        Ok(e)
    }
    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_cmp()
    }
    fn parse_cmp(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.next();
            let e = self.parse_or()?;
            match self.next() {
                Some(Tok::RParen) => return Ok(e),
                _ => return Err("expected )".into()),
            }
        }
        if let Some(Tok::Bool(b)) = self.peek().cloned() {
            self.next();
            return Ok(Expr::Bool(b));
        }
        let field = self.parse_field()?;
        if let Some(Tok::Op(op)) = self.peek().cloned() {
            self.next();
            let lit = self.parse_lit()?;
            Ok(Expr::Cmp(field, op, lit))
        } else {
            Ok(Expr::Truthy(field))
        }
    }
    fn parse_field(&mut self) -> Result<Field, String> {
        let name = match self.next() {
            Some(Tok::Ident(n)) => n,
            other => return Err(format!("expected field name, got {other:?}")),
        };
        if matches!(self.peek(), Some(Tok::LBracket)) {
            self.next();
            let key = match self.next() {
                Some(Tok::Str(s)) => s,
                other => return Err(format!("expected string index, got {other:?}")),
            };
            match self.next() {
                Some(Tok::RBracket) => {}
                _ => return Err("expected ]".into()),
            }
            Ok(Field::Indexed(name, key))
        } else {
            Ok(Field::Simple(name))
        }
    }
    fn parse_lit(&mut self) -> Result<Lit, String> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(Lit::Str(s)),
            Some(Tok::Num(n)) => Ok(Lit::Num(n)),
            Some(Tok::Bool(b)) => Ok(Lit::Bool(b)),
            other => Err(format!("expected literal, got {other:?}")),
        }
    }
}

/// Parse a boolean filter expression. Used for history filters and rule `when`.
pub fn parse_expr(src: &str) -> Result<ParsedExpr, String> {
    let toks = lex(src)?;
    let mut p = Parser::new(toks);
    Ok(ParsedExpr(p.parse()?))
}

/// A compiled expression; evaluate with [`ParsedExpr::matches`].
#[derive(Debug, Clone)]
pub struct ParsedExpr(Expr);

impl ParsedExpr {
    pub fn matches(&self, flow: &Flow) -> bool {
        self.0.eval(&Ctx::new(flow))
    }
}

// ----------------------------------------------------------------------------
// Rules: action + when
// ----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Action {
    Block { status: u16, body: String },
    Drop,
    Allow,
    Tag(String),
    SetReqHeader(String, String),
    SetRespHeader(String, String),
    ReplaceReq(String, String),
    ReplaceResp(String, String),
}

#[derive(Debug, Clone)]
pub struct Rule {
    action: Action,
    when: Expr,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// The original text the rules were parsed from (for `get_rules`).
    pub source: String,
}

/// Terminal decision for the request phase.
#[derive(Debug, PartialEq)]
pub enum ReqDecision {
    Forward,
    Allow,
    Block { status: u16, body: String },
    Drop,
}

#[derive(Debug, Default)]
pub struct Mods {
    pub set_headers: Vec<(String, String)>,
    pub replace_body: Vec<(String, String)>,
    pub tags: Vec<String>,
}

impl RuleSet {
    /// Parse a ruleset from text (one rule per line; `#` comments; blank lines ok).
    pub fn parse(src: &str) -> Result<RuleSet, String> {
        let mut rules = Vec::new();
        for (n, raw) in src.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let rule = parse_rule(line).map_err(|e| format!("line {}: {e}", n + 1))?;
            rules.push(rule);
        }
        Ok(RuleSet {
            rules,
            source: src.to_string(),
        })
    }

    /// Evaluate request-phase rules against a flow (response not yet set).
    pub fn apply_request(&self, flow: &Flow) -> (ReqDecision, Mods) {
        let ctx = Ctx::new(flow);
        let mut mods = Mods::default();
        for rule in &self.rules {
            if !rule.when.eval(&ctx) {
                continue;
            }
            match &rule.action {
                Action::Block { status, body } => {
                    return (
                        ReqDecision::Block {
                            status: *status,
                            body: body.clone(),
                        },
                        mods,
                    )
                }
                Action::Drop => return (ReqDecision::Drop, mods),
                Action::Allow => return (ReqDecision::Allow, mods),
                Action::Tag(t) => mods.tags.push(t.clone()),
                Action::SetReqHeader(k, v) => mods.set_headers.push((k.clone(), v.clone())),
                Action::ReplaceReq(a, b) => mods.replace_body.push((a.clone(), b.clone())),
                // Response-phase actions are ignored here.
                Action::SetRespHeader(..) | Action::ReplaceResp(..) => {}
            }
        }
        (ReqDecision::Forward, mods)
    }

    /// Evaluate response-phase rules against a flow (response set).
    pub fn apply_response(&self, flow: &Flow) -> Mods {
        let ctx = Ctx::new(flow);
        let mut mods = Mods::default();
        for rule in &self.rules {
            if !rule.when.eval(&ctx) {
                continue;
            }
            match &rule.action {
                Action::Tag(t) => mods.tags.push(t.clone()),
                Action::SetRespHeader(k, v) => mods.set_headers.push((k.clone(), v.clone())),
                Action::ReplaceResp(a, b) => mods.replace_body.push((a.clone(), b.clone())),
                _ => {}
            }
        }
        mods
    }
}

/// Apply header sets (replace-or-add, case-insensitive) in place.
pub fn apply_header_mods(headers: &mut Vec<Header>, sets: &[(String, String)]) {
    for (name, value) in sets {
        headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
        headers.push(Header {
            name: name.clone(),
            value: value.clone(),
        });
    }
}

/// Apply literal find/replace pairs to a body string.
pub fn apply_body_mods(body: &str, pairs: &[(String, String)]) -> String {
    let mut out = body.to_string();
    for (find, repl) in pairs {
        if !find.is_empty() {
            out = out.replace(find, repl);
        }
    }
    out
}

fn parse_rule(line: &str) -> Result<Rule, String> {
    // Split off the ` when <expr>` suffix (keyword surrounded by spaces).
    let (action_part, when_src) = match split_when(line) {
        Some((a, w)) => (a, Some(w)),
        None => (line, None),
    };
    let when = match when_src {
        Some(w) => parse_expr(w)?.0,
        None => Expr::Bool(true),
    };
    let action = parse_action(action_part.trim())?;
    Ok(Rule { action, when })
}

/// Split on a top-level ` when ` (not inside quotes).
fn split_when(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut quote = 0u8;
    let mut i = 0;
    while i + 6 <= bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == quote {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'"' || c == b'\'' {
            in_str = true;
            quote = c;
            i += 1;
            continue;
        }
        if line[i..].starts_with(" when ") {
            return Some((&line[..i], &line[i + 6..]));
        }
        i += 1;
    }
    None
}

/// Scan an action clause into (keyword, quoted-strings, numbers). Unlike the
/// expression lexer this tolerates hyphenated keywords (`set-req-header`) and
/// filler tokens (`respond`, the `->` arrow), which it simply skips.
fn scan_action(src: &str) -> Result<(String, Vec<String>, Vec<f64>), String> {
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let skip_ws = |i: &mut usize| {
        while *i < chars.len() && chars[*i].is_whitespace() {
            *i += 1
        }
    };
    skip_ws(&mut i);
    let kw_start = i;
    while i < chars.len() && !chars[i].is_whitespace() {
        i += 1;
    }
    if i == kw_start {
        return Err(format!("expected an action keyword in `{src}`"));
    }
    let kw: String = chars[kw_start..i].iter().collect();
    let mut strs = Vec::new();
    let mut nums = Vec::new();
    while i < chars.len() {
        skip_ws(&mut i);
        if i >= chars.len() {
            break;
        }
        let c = chars[i];
        if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            let mut s = String::new();
            while i < chars.len() && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                s.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                return Err("unterminated string in action".into());
            }
            i += 1; // closing quote
            strs.push(s);
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let n: String = chars[start..i].iter().collect();
            nums.push(n.parse().map_err(|_| format!("bad number: {n}"))?);
        } else {
            // filler word (respond, ->, etc.): skip to next whitespace
            while i < chars.len() && !chars[i].is_whitespace() {
                i += 1;
            }
        }
    }
    Ok((kw, strs, nums))
}

fn parse_action(src: &str) -> Result<Action, String> {
    let (kw, strs, nums) = scan_action(src)?;
    match kw.as_str() {
        "block" => {
            let status = nums.first().map(|n| *n as u16).unwrap_or(403);
            let body = strs
                .first()
                .cloned()
                .unwrap_or_else(|| "blocked by offat-proxy".into());
            Ok(Action::Block { status, body })
        }
        "drop" => Ok(Action::Drop),
        "allow" => Ok(Action::Allow),
        "tag" => Ok(Action::Tag(
            strs.first().cloned().ok_or("tag needs a \"name\"")?,
        )),
        "set-req-header" => {
            let (k, v) = split_header(strs.first().ok_or("set-req-header needs \"Name: value\"")?)?;
            Ok(Action::SetReqHeader(k, v))
        }
        "set-resp-header" => {
            let (k, v) = split_header(
                strs.first()
                    .ok_or("set-resp-header needs \"Name: value\"")?,
            )?;
            Ok(Action::SetRespHeader(k, v))
        }
        "replace-req" => {
            let (a, b) = (strs.first(), strs.get(1));
            match (a, b) {
                (Some(a), Some(b)) => Ok(Action::ReplaceReq(a.clone(), b.clone())),
                _ => Err("replace-req needs \"find\" -> \"replace\"".into()),
            }
        }
        "replace-resp" => {
            let (a, b) = (strs.first(), strs.get(1));
            match (a, b) {
                (Some(a), Some(b)) => Ok(Action::ReplaceResp(a.clone(), b.clone())),
                _ => Err("replace-resp needs \"find\" -> \"replace\"".into()),
            }
        }
        other => Err(format!("unknown action: {other}")),
    }
}

fn split_header(s: &str) -> Result<(String, String), String> {
    match s.split_once(':') {
        Some((k, v)) => Ok((k.trim().to_string(), v.trim().to_string())),
        None => Err(format!("header must be \"Name: value\", got \"{s}\"")),
    }
}

// ----------------------------------------------------------------------------
// small helpers
// ----------------------------------------------------------------------------

fn path_only(p: &str) -> String {
    p.split_once('?')
        .map(|(a, _)| a.to_string())
        .unwrap_or_else(|| p.to_string())
}
fn query_only(p: &str) -> String {
    p.split_once('?')
        .map(|(_, b)| b.to_string())
        .unwrap_or_default()
}
fn header_val(headers: &[Header], key: &str) -> FieldVal {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(key))
        .map(|h| FieldVal::S(h.value.clone()))
        .unwrap_or(FieldVal::Missing)
}
fn query_param(path: &str, key: &str) -> FieldVal {
    let q = query_only(path);
    for kv in q.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return FieldVal::S(v.to_string());
            }
        } else if kv == key {
            return FieldVal::S(String::new());
        }
    }
    FieldVal::Missing
}
fn lit_str(l: &Lit) -> String {
    match l {
        Lit::Str(s) => s.clone(),
        Lit::Num(n) => trim_num(*n),
        Lit::Bool(b) => b.to_string(),
    }
}
fn lit_num(l: &Lit) -> Option<f64> {
    match l {
        Lit::Num(n) => Some(*n),
        Lit::Str(s) => s.trim().parse().ok(),
        Lit::Bool(_) => None,
    }
}
fn trim_num(n: f64) -> String {
    if n.fract() == 0.0 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Header, Request, Response};

    fn flow() -> Flow {
        let req = Request {
            method: "POST".into(),
            scheme: "https".into(),
            host: "api.example.test".into(),
            path: "/admin/users?page=2".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![
                Header {
                    name: "X-Role".into(),
                    value: "user".into(),
                },
                Header {
                    name: "Accept".into(),
                    value: "application/json".into(),
                },
            ],
            body: "{\"k\":\"v\"}".into(),
            body_truncated: false,
        };
        let mut f = Flow::new("c".into(), req, true, true);
        f.response = Some(Response {
            status: 500,
            http_version: "HTTP/1.1".into(),
            content_type: "application/json".into(),
            headers: vec![Header {
                name: "Server".into(),
                value: "nginx".into(),
            }],
            body: "oops secret here".into(),
            body_truncated: false,
        });
        f
    }

    fn eval(src: &str) -> bool {
        parse_expr(src).unwrap().matches(&flow())
    }

    #[test]
    fn comparisons_and_fields() {
        assert!(eval("method == \"POST\""));
        assert!(eval("host endswith \".example.test\""));
        assert!(eval("path contains \"/admin\""));
        assert!(eval("header[\"x-role\"] == \"user\"")); // case-insensitive name
        assert!(eval("query[\"page\"] == \"2\""));
        assert!(eval("status >= 500"));
        assert!(eval("status == 500"));
        assert!(eval("in_scope"));
        assert!(eval("scheme matches \"http*\""));
        assert!(!eval("status < 500"));
        assert!(!eval("method == \"GET\""));
    }

    #[test]
    fn boolean_logic_and_precedence() {
        assert!(eval("method == \"POST\" && path contains \"/admin\""));
        assert!(eval("method == \"GET\" || status == 500"));
        assert!(eval("!(method == \"GET\")"));
        assert!(eval("not method == \"GET\""));
        // precedence: AND binds tighter than OR
        assert!(eval("method == \"GET\" && status == 200 || status == 500"));
    }

    #[test]
    fn response_fields() {
        assert!(eval("resp_body contains \"secret\""));
        assert!(eval("content_type == \"application/json\""));
        assert!(eval("resp_header[\"server\"] == \"nginx\""));
    }

    #[test]
    fn parse_errors_are_reported() {
        assert!(parse_expr("method == ").is_err());
        assert!(parse_expr("(method == \"x\"").is_err());
        assert!(parse_expr("method foo \"x\"").is_err());
    }

    #[test]
    fn ruleset_request_phase() {
        let rs = RuleSet::parse(
            "# comment\n\
             block respond 403 \"no\" when path contains \"/admin\" && header[\"x-role\"] != \"admin\"\n\
             tag \"mutating\" when method == \"POST\"\n",
        )
        .unwrap();
        let (decision, _mods) = rs.apply_request(&flow());
        assert_eq!(
            decision,
            ReqDecision::Block {
                status: 403,
                body: "no".into()
            }
        );
    }

    #[test]
    fn ruleset_allow_short_circuits() {
        let rs = RuleSet::parse(
            "allow when host == \"api.example.test\"\n\
             block when path contains \"/admin\"\n",
        )
        .unwrap();
        let (decision, _) = rs.apply_request(&flow());
        assert_eq!(decision, ReqDecision::Allow);
    }

    #[test]
    fn ruleset_tags_and_mods() {
        let rs = RuleSet::parse(
            "tag \"post\" when method == \"POST\"\n\
             set-req-header \"X-OFFAT: 1\" when in_scope\n",
        )
        .unwrap();
        let (decision, mods) = rs.apply_request(&flow());
        assert_eq!(decision, ReqDecision::Forward);
        assert_eq!(mods.tags, vec!["post".to_string()]);
        assert_eq!(
            mods.set_headers,
            vec![("X-OFFAT".to_string(), "1".to_string())]
        );
    }

    #[test]
    fn response_phase_replace_and_tag() {
        let rs = RuleSet::parse("replace-resp \"secret\" -> \"<x>\" when status == 500\n").unwrap();
        let mods = rs.apply_response(&flow());
        let out = apply_body_mods("oops secret here", &mods.replace_body);
        assert_eq!(out, "oops <x> here");
    }

    #[test]
    fn header_mods_replace_case_insensitive() {
        let mut h = vec![Header {
            name: "x-role".into(),
            value: "user".into(),
        }];
        apply_header_mods(&mut h, &[("X-Role".into(), "admin".into())]);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].value, "admin");
    }

    #[test]
    fn drop_action() {
        let rs = RuleSet::parse("drop when host endswith \".ads.test\"").unwrap();
        let mut f = flow();
        f.request.host = "x.ads.test".into();
        assert_eq!(rs.apply_request(&f).0, ReqDecision::Drop);
    }
}
