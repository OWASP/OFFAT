"""OFFAT Bundle - the canonical interchange document for the OFFAT-AI platform.

A Bundle is one JSON file that every pipeline stage reads and writes: attack
surface model (ASM), sink/source inventory, parameter relation graph (PRG),
threat model, test plan, execution results and canonical findings. See
``docs/platform.md`` and the JSON Schema under ``schema/``.

This package provides builders (``model``), validation (``validate``) and
load/save/merge (``io``). Pure standard library; ``jsonschema`` is used for
validation only when present.
"""

from . import io, model, validate
from .model import (
    SCHEMA_VERSION,
    new_bundle,
    new_run_id,
    make_id,
    record_stage,
    endpoint,
    param,
    sink,
    source,
    prg_node,
    prg_edge,
    threat,
    test_case,
    execution,
    add_endpoint,
    add_sink,
    add_source,
    add_prg_node,
    add_prg_edge,
    add_threat,
    add_test_case,
    add_execution,
    add_finding,
)
from .validate import validate as validate_bundle, is_valid, cross_refs
from .io import load, save, merge

__all__ = [
    "io", "model", "validate",
    "SCHEMA_VERSION", "new_bundle", "new_run_id", "make_id", "record_stage",
    "endpoint", "param", "sink", "source", "prg_node", "prg_edge", "threat",
    "test_case", "execution",
    "add_endpoint", "add_sink", "add_source", "add_prg_node", "add_prg_edge",
    "add_threat", "add_test_case", "add_execution", "add_finding",
    "validate_bundle", "is_valid", "cross_refs", "load", "save", "merge",
]

__version__ = "1.0.0"
