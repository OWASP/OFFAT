"""OFFAT-AI platform orchestrator.

Runs the staged pipeline over a single Bundle (see ``docs/platform.md``). Phase 1
provides mapping (attack surface + sink/source inventory) and the parameter
relation graph; later phases add threat modeling, test generation, execution,
triage and reporting.
"""

from . import mapping, prg, testgen, threat_model

__all__ = ["mapping", "prg", "testgen", "threat_model"]
__version__ = "1.0.0"
