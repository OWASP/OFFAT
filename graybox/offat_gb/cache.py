"""Verdict cache - re-exported from the shared triager package.

The implementation lives in ``offat_triage.cache`` so the white-box and gray-box
pipelines share one cache. This module is kept for backward-compatible imports
(``offat_gb.cache``).
"""

from __future__ import annotations

from offat_triage.cache import DEFAULT_CACHE_NAME, VerdictCache, finding_key

__all__ = ["VerdictCache", "finding_key", "DEFAULT_CACHE_NAME"]
