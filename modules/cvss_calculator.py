# modules/cvss_calculator.py
# DRAKBEN — CVSS v3.1 Base Score Calculator
# Implements the CVSS v3.1 specification from FIRST.org

"""CVSS v3.1 Base Score Calculator.

Computes base scores from CVSS vector strings and maps scores to
qualitative severity ratings compatible with
``modules.report_generator.FindingSeverity``.

Usage::

    from modules.cvss_calculator import CVSSCalculator

    calc = CVSSCalculator()
    result = calc.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    print(result.score)      # 9.8
    print(result.severity)   # "CRITICAL"

    score = calc.from_metrics(
        attack_vector="N", attack_complexity="L",
        privileges_required="N", user_interaction="N",
        scope="U", confidentiality="H", integrity="H", availability="H",
    )
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CVSSResult:
    """CVSS calculation result."""

    score: float
    severity: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    vector: str
    breakdown: dict[str, Any]


# ──────────────────────────────────────────────────────────────
# Metric value weights (CVSS v3.1 specification table)
# ──────────────────────────────────────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                          # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}            # Privileges Required (Scope Unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}            # Privileges Required (Scope Changed)
_UI = {"N": 0.85, "R": 0.62}                          # User Interaction
_C = {"N": 0.00, "L": 0.22, "H": 0.56}               # Confidentiality Impact
_I = {"N": 0.00, "L": 0.22, "H": 0.56}               # Integrity Impact
_A = {"N": 0.00, "L": 0.22, "H": 0.56}               # Availability Impact

_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])"
    r"/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])$",
)


class CVSSCalculator:
    """CVSS v3.1 Base Score calculator."""

    @staticmethod
    def from_vector(vector: str) -> CVSSResult:
        """Parse a CVSS v3.1 vector string and compute the base score.

        Args:
            vector: Full vector string, e.g.
                ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``

        Returns:
            CVSSResult with score, severity, and breakdown.

        Raises:
            ValueError: If the vector string is malformed.
        """
        m = _VECTOR_RE.match(vector.strip())
        if not m:
            msg = f"Invalid CVSS v3.1 vector: {vector}"
            raise ValueError(msg)

        av, ac, pr, ui, s, c, i, a = m.groups()
        return CVSSCalculator.from_metrics(
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a,
        )

    @staticmethod
    def from_metrics(
        *,
        attack_vector: str,
        attack_complexity: str,
        privileges_required: str,
        user_interaction: str,
        scope: str,
        confidentiality: str,
        integrity: str,
        availability: str,
    ) -> CVSSResult:
        """Compute CVSS v3.1 base score from individual metrics.

        All parameters are single-character CVSS abbreviations
        (e.g. ``"N"``, ``"L"``, ``"H"``).
        """
        av_val = _AV[attack_vector]
        ac_val = _AC[attack_complexity]
        pr_val = (_PR_C if scope == "C" else _PR_U)[privileges_required]
        ui_val = _UI[user_interaction]
        c_val = _C[confidentiality]
        i_val = _I[integrity]
        a_val = _A[availability]

        # Impact Sub-Score (ISS)
        iss = 1 - (1 - c_val) * (1 - i_val) * (1 - a_val)

        # Impact
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        # Exploitability
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # Base Score
        if impact <= 0:
            score = 0.0
        elif scope == "U":
            score = min(impact + exploitability, 10.0)
            score = _roundup(score)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)
            score = _roundup(score)

        vector_str = (
            f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}"
            f"/PR:{privileges_required}/UI:{user_interaction}"
            f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        )

        return CVSSResult(
            score=score,
            severity=_score_to_severity(score),
            vector=vector_str,
            breakdown={
                "impact_sub_score": round(iss, 4),
                "impact": round(impact, 2),
                "exploitability": round(exploitability, 2),
            },
        )

    @staticmethod
    def severity_from_score(score: float) -> str:
        """Map a CVSS score to a qualitative severity string."""
        return _score_to_severity(score)


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _roundup(value: float) -> float:
    """CVSS v3.1 'roundup' function: round up to 1 decimal place."""
    return math.ceil(value * 10) / 10


def _score_to_severity(score: float) -> str:
    """Map numeric score → qualitative rating (FIRST specification)."""
    if score == 0.0:
        return "NONE"
    if score <= 3.9:
        return "LOW"
    if score <= 6.9:
        return "MEDIUM"
    if score <= 8.9:
        return "HIGH"
    return "CRITICAL"
