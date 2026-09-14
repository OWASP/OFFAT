"""OFFAT-AI white-box (SAST) pipeline.

A multi-stage source-code security review modeled on the security-harness
workflow: recon -> hunt -> chain -> verify (triage) -> report. It integrates
external tools when available (semgrep for hunting, syft/grype/trivy/osv for
SBOM & CVEs, graft for code mapping) and always ships a dependency-free
built-in hunter so it produces findings even with no tools installed.
"""

__version__ = "1.0.0"
