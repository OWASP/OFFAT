"""OFFAT-AI reporter - render an OFFAT Bundle into deliverables.

Bundle in, reports out: SARIF 2.1.0, Markdown, a self-contained HTML report (with
the threat-model data-flow diagram), an OWASP API Top 10 / ASVS compliance report,
and best-effort PDF. See ``docs/platform.md``.
"""

from . import render

__all__ = ["render"]
__version__ = "1.0.0"
