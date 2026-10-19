"""offat-report - render an OFFAT Bundle into reports.

Bundle in, reports out. Formats: sarif, md, html, compliance, pdf. PDF needs an
external engine (wkhtmltopdf or headless Chrome); it is skipped with a note when
none is present.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import render

_ALL = ["sarif", "md", "html", "compliance", "pdf"]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="offat-report",
        description="Render an OFFAT Bundle into SARIF/Markdown/HTML/compliance/PDF reports",
    )
    ap.add_argument("bundle", help="path to a .offat.json Bundle")
    ap.add_argument("-o", "--out", default="offat-report/reports", help="output directory")
    ap.add_argument("--formats", default="sarif,md,html,compliance",
                    help=f"comma-separated: {','.join(_ALL)} (or 'all')")
    args = ap.parse_args(argv)

    try:
        with open(args.bundle, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read bundle: {e}", file=sys.stderr)
        return 2

    formats = _ALL if args.formats.strip() == "all" else \
        [f.strip() for f in args.formats.split(",") if f.strip()]
    os.makedirs(args.out, exist_ok=True)
    written = []

    if "sarif" in formats:
        p = os.path.join(args.out, "results.sarif")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(render.sarif(bundle), fh, indent=2)
        written.append(p)
    if "md" in formats:
        p = os.path.join(args.out, "report.md")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(render.markdown(bundle))
        written.append(p)
    if "compliance" in formats:
        p = os.path.join(args.out, "compliance.md")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(render.compliance(bundle))
        written.append(p)
    html_path = os.path.join(args.out, "report.html")
    if "html" in formats or "pdf" in formats:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render.html_report(bundle))
        if "html" in formats:
            written.append(html_path)
    if "pdf" in formats:
        pdf_path = os.path.join(args.out, "report.pdf")
        engine = render.pdf_from_html(html_path, pdf_path)
        if engine:
            written.append(pdf_path + f" (via {engine})")
        else:
            print("note: no PDF engine (wkhtmltopdf/chrome) found; skipped report.pdf",
                  file=sys.stderr)

    for w in written:
        print("wrote", w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
