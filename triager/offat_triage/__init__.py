"""OFFAT-AI shared triager.

Validates candidate security findings (from the DAST engine or the white-box
pipeline) and enriches each with a verdict, CVSS score and remediation. Ships a
deterministic heuristic triager and an AI triager backed by the Anthropic
Messages API, with automatic fallback. Pure standard library — no third-party
dependencies.
"""

from .triager import (
    AnthropicTriager,
    heuristic_triage,
    triage_findings,
    make_triager,
    cvss_for,
    remediation_for,
    DEFAULT_MODEL,
)
from .cli_providers import ClaudeCodeTriager, CodexTriager, cli_available
from .cache import VerdictCache, finding_key
from .batch import tiered_triage, default_block

__all__ = [
    "AnthropicTriager",
    "ClaudeCodeTriager",
    "CodexTriager",
    "cli_available",
    "heuristic_triage",
    "triage_findings",
    "tiered_triage",
    "default_block",
    "make_triager",
    "cvss_for",
    "remediation_for",
    "VerdictCache",
    "finding_key",
    "DEFAULT_MODEL",
]

__version__ = "1.0.0"
