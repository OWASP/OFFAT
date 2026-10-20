"""Build the OFFAT documentation site.

    pip install -r docs/requirements.txt
    python docs/build.py                 # -> docs/_site/
    python -m http.server -d docs/_site  # preview

Every ``docs/*.md`` with front matter becomes ``<name>.html``. Front matter keys:
``title``, ``section``, ``nav_order``, ``description``, optional ``nav_title``
and ``layout: home``. Links to other pages may be written as ``page.md``;
links to anything else in the repository are rewritten to GitHub.
"""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import sys
from datetime import date
from typing import Dict, List

import markdown
from markdown.extensions.toc import slugify

HERE = os.path.dirname(os.path.abspath(__file__))
THEME = os.path.join(HERE, "_theme")
OUT = os.path.join(HERE, "_site")
REPO = "https://github.com/OWASP/OFFAT"
BRANCH = "dev"
SITE_URL = os.environ.get("DOCS_SITE_URL", "https://owasp.github.io/OFFAT/")
BASE_PATH = os.environ.get("DOCS_BASE_PATH", "/OFFAT/")
SECTIONS = ["Start", "Concepts", "Integrate", "Deep dives"]


def front_matter(text: str):
    if not text.startswith("---\n"):
        return {}, text
    end = text.index("\n---", 4)
    meta = {}
    for line in text[4:end].splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip().strip('"')
    return meta, text[end + 4:].lstrip("\n")


def render(body: str):
    md = markdown.Markdown(extensions=[
        "fenced_code", "tables", "sane_lists", "attr_list", "md_in_html",
        "toc", "codehilite",
    ], extension_configs={
        "toc": {"permalink": "#", "permalink_class": "anchor", "toc_depth": "2-3",
                "slugify": slugify},
        "codehilite": {"css_class": "hl", "guess_lang": False, "pygments_lang_class": True},
    })
    out = md.convert(body)
    # Tag each highlighted block with its fence language (opening fences only).
    fences = re.findall(r"^\s*(```+)([\w+-]*)", body, flags=re.M)
    langs = [lang for i, (_, lang) in enumerate(fences) if i % 2 == 0]
    blocks = out.count('<div class="hl">')
    if blocks == len(langs):
        it = iter(langs)
        out = re.sub(r'<div class="hl">', lambda m: f'<div class="hl" data-lang="{next(it) or "text"}">', out)
    return out, md.toc_tokens


def rewrite_links(content: str, pages: Dict[str, Dict]) -> str:
    def fix(m: "re.Match[str]") -> str:
        href = html.unescape(m.group(2))
        if re.match(r"^(https?:|mailto:|#|//)", href):
            return m.group(0)
        path, _, anchor = href.partition("#")
        frag = f"#{anchor}" if anchor else ""
        if path.endswith(".md") and "/" not in path and path in pages:
            return f'{m.group(1)}"{pages[path]["url"]}{frag}"'
        target = os.path.normpath(os.path.join("docs", path)).replace(os.sep, "/")
        kind = "tree" if path.endswith("/") or "." not in os.path.basename(target) else "blob"
        return f'{m.group(1)}"{REPO}/{kind}/{BRANCH}/{target}{frag}"'
    return re.sub(r'(href=)"([^"]+)"', fix, content)


def decorate(content: str) -> str:
    # Callouts: every blockquote is a note; "Authorized use only" / "Warning" are warnings.
    def callout(m: "re.Match[str]") -> str:
        inner = m.group(1)
        kind = "warn" if re.search(r"Authorized use only|Warning|Caution", inner) else "note"
        return f'<blockquote class="callout {kind}">{inner}</blockquote>'
    content = re.sub(r"<blockquote>(.*?)</blockquote>", callout, content, flags=re.S)
    # Tables scroll horizontally on narrow screens.
    content = re.sub(r"<table>", '<div class="table-wrap"><table>', content)
    content = content.replace("</table>", "</table></div>")
    # External links open in a new tab.
    content = re.sub(r'<a href="(https?://[^"]+)"', r'<a href="\1" target="_blank" rel="noopener"', content)
    return content


def plain(content: str) -> str:
    text = re.sub(r"<pre.*?</pre>", " ", content, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def headings(tokens: List[Dict]) -> List[Dict]:
    """Flatten the h2/h3 tokens (toc_depth 2-3 makes h2 the top level)."""
    out = []
    for t in tokens:
        out.append(t)
        out.extend(t.get("children", []))
    return out


def toc_html(tokens: List[Dict]) -> str:
    items = [f'<li class="l{h["level"]}"><a href="#{h["id"]}">{h["name"]}</a></li>'
             for h in headings(tokens)]
    if not items:
        return ""
    return '<p class="toc-title">On this page</p><ul>' + "".join(items) + "</ul>"


def nav_html(ordered: List[Dict], current: str) -> str:
    out = []
    for sec in SECTIONS:
        group = [p for p in ordered if p["section"] == sec]
        if not group:
            continue
        out.append(f'<div class="nav-group"><p class="nav-label">{html.escape(sec)}</p><ul>')
        for p in group:
            active = ' class="active" aria-current="page"' if p["name"] == current else ""
            out.append(f'<li><a href="{p["url"]}"{active}>{html.escape(p["nav_title"])}</a></li>')
        out.append("</ul></div>")
    return "".join(out)


def fill(tpl: str, values: Dict[str, str]) -> str:
    return re.sub(r"\{\{\s*(\w+)\s*\}\}", lambda m: values.get(m.group(1), ""), tpl)


def build() -> int:
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    os.makedirs(os.path.join(OUT, "assets"))
    layout = open(os.path.join(THEME, "layout.html"), encoding="utf-8").read()
    hero = open(os.path.join(THEME, "hero.html"), encoding="utf-8").read()

    pages: Dict[str, Dict] = {}
    for name in sorted(os.listdir(HERE)):
        if not name.endswith(".md"):
            continue
        meta, body = front_matter(open(os.path.join(HERE, name), encoding="utf-8").read())
        if "title" not in meta:
            continue
        stem = name[:-3]
        pages[name] = {
            "name": name, "body": body, "meta": meta,
            "url": "./" if stem == "index" else f"{stem}.html",
            "file": "index.html" if stem == "index" else f"{stem}.html",
            "title": meta["title"], "nav_title": meta.get("nav_title", meta["title"]),
            "section": meta.get("section", "Start"),
            "order": int(meta.get("nav_order", 99)),
        }
    ordered = sorted(pages.values(), key=lambda p: (SECTIONS.index(p["section"])
                                                     if p["section"] in SECTIONS else 99, p["order"]))

    search = []
    for i, p in enumerate(ordered):
        content, tokens = render(p["body"])
        content = decorate(rewrite_links(content, pages))
        prev_p = ordered[i - 1] if i > 0 else None
        next_p = ordered[i + 1] if i + 1 < len(ordered) else None
        pn = ""
        if prev_p:
            pn += (f'<a class="pn prev" href="{prev_p["url"]}"><span>Previous</span>'
                   f'{html.escape(prev_p["nav_title"])}</a>')
        if next_p:
            pn += (f'<a class="pn next" href="{next_p["url"]}"><span>Next</span>'
                   f'{html.escape(next_p["nav_title"])}</a>')
        is_home = p["meta"].get("layout") == "home"
        values = {
            "page_title": "OWASP OFFAT" if is_home else f'{p["title"]} · OWASP OFFAT',
            "description": html.escape(p["meta"].get("description", "")),
            "nav": nav_html(ordered, p["name"]),
            "toc": "" if is_home else toc_html(tokens),
            "content": content,
            "prev_next": pn,
            "edit_url": f"{REPO}/edit/{BRANCH}/docs/{p['name']}",
            "body_class": "home" if is_home else "doc",
            "hero": hero if is_home else "",
            "canonical": SITE_URL + ("" if p["file"] == "index.html" else p["file"]),
            "year": str(date.today().year),
            "base": "",
        }
        with open(os.path.join(OUT, p["file"]), "w", encoding="utf-8") as fh:
            fh.write(fill(layout, values))
        search.append({
            "t": p["title"], "u": p["url"], "d": p["meta"].get("description", ""), "s": p["section"],
            "h": [{"i": h["id"], "n": html.unescape(re.sub(r"<[^>]+>", "", h["name"]))}
                  for h in headings(tokens)],
            "x": plain(content)[:6000],
        })

    # 404 page: served at arbitrary paths, so anchor every relative link to the site base.
    nf = fill(layout, {
        "page_title": "Not found · OWASP OFFAT", "description": "Page not found",
        "nav": nav_html(ordered, ""), "toc": "", "body_class": "doc",
        "content": ('<div class="notfound"><p class="nf-code">404</p><h1>No route to this page</h1>'
                    '<p>The trace went cold. Try the search, or start from the overview.</p>'
                    '<p><a class="btn primary" href="./">Back to the overview</a></p></div>'),
        "prev_next": "", "edit_url": REPO, "hero": "", "canonical": SITE_URL,
        "year": str(date.today().year), "base": f'<base href="{BASE_PATH}">',
    })
    with open(os.path.join(OUT, "404.html"), "w", encoding="utf-8") as fh:
        fh.write(nf)

    with open(os.path.join(OUT, "search-index.json"), "w", encoding="utf-8") as fh:
        json.dump(search, fh, separators=(",", ":"))
    with open(os.path.join(OUT, "sitemap.xml"), "w", encoding="utf-8") as fh:
        fh.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n')
        for p in ordered:
            fh.write(f"  <url><loc>{SITE_URL}{'' if p['file'] == 'index.html' else p['file']}</loc></url>\n")
        fh.write("</urlset>\n")
    open(os.path.join(OUT, ".nojekyll"), "w").close()

    for f in ("style.css", "app.js", "favicon.svg"):
        shutil.copy(os.path.join(THEME, f), os.path.join(OUT, "assets", f))
    for f in os.listdir(os.path.join(HERE, "assets")):
        shutil.copy(os.path.join(HERE, "assets", f), os.path.join(OUT, "assets", f))
    print(f"built {len(ordered)} pages -> {os.path.relpath(OUT)}")
    return 0


if __name__ == "__main__":
    sys.exit(build())
