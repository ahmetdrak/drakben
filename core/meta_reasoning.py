"""Simple meta-reasoning / post-run analysis helpers.

This module provides conservative, testable suggestions based on the
agent `state` and recent `observations`. It's intentionally small and
meant to be extended; current recommendations are safety-focused.
"""
from typing import Any, Dict, List


def analyze_run(state: Any, observations: List[Dict]) -> Dict:
    """Analyze state + observations and return short recommendations.

    The function is defensive: it accepts either an object with attributes
    or a mapping (dict-like). Returned dict schema:
      {"recommendations": [str], "reasons": [str]}
    """
    recs: List[str] = []
    reasons: List[str] = []

    def _g(k, default=None):
        # try attribute then key access
        if hasattr(state, k):
            return getattr(state, k)
        try:
            return state.get(k, default)  # type: ignore[attr-defined]
        except Exception:
            return default

    has_foothold = bool(_g("has_foothold", False))
    iter_count = int(_g("iteration_count", 0) or 0)
    max_iters = int(_g("max_iterations", 15) or 15)

    if not has_foothold:
        recs.append("acquire_foothold")
        reasons.append("No foothold detected; payloads are forbidden until foothold is acquired.")

    if iter_count >= max_iters - 1:
        recs.append("stop_or_rotate_target")
        reasons.append("Approaching max iterations to avoid infinite loops/resource exhaustion.")

    # Look for any observation indicating SQLi or open web service
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        svc = obs.get("service") or obs.get("type")
        if svc and "sql" in str(svc).lower():
            recs.append("prioritize_sql_investigation")
            reasons.append("SQL-related service observed in recent observations.")
            break

    if not recs:
        recs.append("continue")
        reasons.append("No high-priority issues found; continue normal operation.")

    return {"recommendations": recs, "reasons": reasons}
