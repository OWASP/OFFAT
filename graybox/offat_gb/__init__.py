"""OFFAT-AI gray-box pipeline.

Fuses the white-box view (source code, data-flow sinks) with a black-box view
(the HTTP endpoint attack surface, mapped from source with graft) and analyzes
them together with AI. It sends no live traffic: reachability is established from
the structural call graph, and AI tokens are spent only on findings reachable
from a mapped endpoint (batched, cached, and model-tiered for token discipline).

Stages: recon -> map endpoints -> hunt (SAST) -> reachability -> analyze -> report.
"""

__version__ = "1.0.0"
