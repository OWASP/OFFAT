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

__all__ = [
    "AnthropicTriager",
    "ClaudeCodeTriager",
    "CodexTriager",
    "cli_available",
    "heuristic_triage",
    "triage_findings",
    "make_triager",
    "cvss_for",
    "remediation_for",
    "DEFAULT_MODEL",
]

__version__ = "1.0.0"
