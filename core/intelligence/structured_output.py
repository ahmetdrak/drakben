# core/intelligence/structured_output.py
# DRAKBEN — Structured Output Models
# Replaces fragile regex JSON parsing with validated data models
# that work with ANY LLM (not model-specific).
#
# Usage:
#   parser = StructuredOutputParser()
#   action = parser.parse(llm_response, PentestAction)
#   # Returns validated PentestAction or None

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────── Output Models ───────────────────────

class ActionIntent(Enum):
    """What the agent intends to do."""

    SCAN = "scan"
    EXPLOIT = "exploit"
    RECON = "recon"
    ENUMERATE = "enumerate"
    BRUTE_FORCE = "brute_force"
    POST_EXPLOIT = "post_exploit"
    CHAT = "chat"
    FINISH = "finish"
    UNKNOWN = "unknown"


@dataclass
class PentestAction:
    """Structured output for a pentest action decision.

    This replaces the ad-hoc dict parsing in brain_reasoning.py.
    Every field has a safe default so partial JSON still produces a usable object.
    """

    intent: str = "unknown"
    confidence: float = 0.5
    tool: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    risks: list[str] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    needs_approval: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PentestAction:
        """Create from a dict with safe defaults for missing fields."""
        return cls(
            intent=str(data.get("intent", data.get("action", "unknown"))),
            confidence=_safe_float(data.get("confidence"), 0.5),
            tool=data.get("tool"),
            arguments=data.get("arguments", data.get("args", data.get("tool_args", {}))),
            reasoning=str(data.get("reasoning", data.get("thought", ""))),
            risks=data.get("risks", []),
            steps=data.get("steps", []),
            needs_approval=bool(data.get("needs_approval", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for backward compatibility."""
        return {
            "intent": self.intent,
            "confidence": self.confidence,
            "tool": self.tool,
            "arguments": self.arguments,
            "reasoning": self.reasoning,
            "risks": self.risks,
            "steps": self.steps,
            "needs_approval": self.needs_approval,
            "success": True,
            "response": self.reasoning,
            "llm_response": self.reasoning,
            "action": self.intent,
        }


@dataclass
class ToolAnalysis:
    """Structured output for tool output analysis.

    Replaces the fragile JSON parsing in _analyze_with_llm_transparency().
    """

    summary: str = ""
    findings: list[str] = field(default_factory=list)
    severity: str = "info"  # info, low, medium, high, critical
    next_steps: list[dict[str, str]] = field(default_factory=list)
    ports_found: list[dict[str, Any]] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolAnalysis:
        """Create from a dict with safe defaults."""
        return cls(
            summary=str(data.get("summary", "")),
            findings=data.get("findings", []),
            severity=str(data.get("severity", "info")),
            next_steps=data.get("next_steps", []),
            ports_found=data.get("ports_found", data.get("ports", [])),
            services=data.get("services", []),
            vulnerabilities=data.get("vulnerabilities", data.get("vulns", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for backward compatibility."""
        return {
            "summary": self.summary,
            "findings": self.findings,
            "severity": self.severity,
            "next_steps": self.next_steps,
            "ports_found": self.ports_found,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
        }


@dataclass
class RecoveryPlan:
    """Structured output for failure recovery suggestions."""

    steps: list[dict[str, str]] = field(default_factory=list)
    reasoning: str = ""
    requires_human: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecoveryPlan:
        """Create from an LLM response dict."""
        if isinstance(data, list):
            return cls(steps=data[:3])
        return cls(
            steps=data.get("steps", data.get("recovery_steps", [])),
            reasoning=str(data.get("reasoning", "")),
            requires_human=bool(data.get("requires_human", False)),
        )


@dataclass
class ReflectionResult:
    """Structured output for self-reflection."""

    verdict: str = "continue"  # continue, pivot, escalate
    reasoning: str = ""
    progress_assessment: str = ""
    blind_spots: list[str] = field(default_factory=list)
    suggested_changes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReflectionResult:
        """Create from an LLM response dict."""
        return cls(
            verdict=str(data.get("verdict", data.get("action", "continue"))).lower(),
            reasoning=str(data.get("reasoning", "")),
            progress_assessment=str(data.get("progress_assessment", data.get("progress", ""))),
            blind_spots=data.get("blind_spots", []),
            suggested_changes=data.get("suggested_changes", data.get("suggestions", [])),
        )


# ─────────────────────── Parser ───────────────────────

# Pre-compiled regex patterns for JSON extraction
_RE_JSON_FENCED = re.compile(r"```(?:json)?\s*(\{[^}]*\})\s*```", re.DOTALL)
_RE_JSON_ARRAY_FENCED = re.compile(r"```(?:json)?\s*(\[[^\]]*\])\s*```", re.DOTALL)
_RE_JSON_OBJECT = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)
_RE_JSON_ARRAY = re.compile(r"\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\]", re.DOTALL)


class StructuredOutputParser:
    """Parse LLM output into structured dataclass models.

    Handles:
    - Clean JSON responses
    - JSON wrapped in markdown code fences
    - JSON mixed with natural language text
    - Partial/malformed JSON with safe defaults
    - Retry logic with LLM to repair broken output

    Works with ANY LLM — no model-specific features required.
    """

    def __init__(self, llm_client: Any = None, max_retries: int = 1) -> None:
        self._llm = llm_client
        self._max_retries = max_retries
        self._stats = {"parses": 0, "successes": 0, "retries": 0, "failures": 0}

    def parse(
        self,
        raw_response: str,
        model_class: type | None = None,
        *,
        expect_array: bool = False,
    ) -> Any | None:
        """Parse raw LLM response into a structured object.

        Args:
            raw_response: Raw string from LLM
            model_class: Dataclass with from_dict() method (e.g. PentestAction)
            expect_array: If True, parse as JSON array instead of object

        Returns:
            Instance of model_class, raw dict/list, or None on failure

        """
        self._stats["parses"] += 1

        if not raw_response or not raw_response.strip():
            self._stats["failures"] += 1
            return None

        # Try parsing
        data = self._extract_json(raw_response, expect_array=expect_array)

        if data is not None:
            self._stats["successes"] += 1
            if model_class and hasattr(model_class, "from_dict"):
                return model_class.from_dict(data)
            return data

        # Retry with LLM repair if available
        if self._llm and self._max_retries > 0:
            self._stats["retries"] += 1
            repaired = self._repair_with_llm(raw_response, expect_array)
            if repaired is not None:
                self._stats["successes"] += 1
                if model_class and hasattr(model_class, "from_dict"):
                    return model_class.from_dict(repaired)
                return repaired

        self._stats["failures"] += 1
        return None

    def parse_or_default(
        self,
        raw_response: str,
        model_class: type,
    ) -> Any:
        """Parse or return a default instance (never None).

        Useful when you need a guaranteed result.
        """
        result = self.parse(raw_response, model_class)
        if result is not None:
            return result
        # Return default instance
        return model_class()

    def _extract_json(
        self,
        text: str,
        *,
        expect_array: bool = False,
    ) -> dict | list | None:
        """Extract JSON from text using multiple strategies."""
        fenced_re = _RE_JSON_ARRAY_FENCED if expect_array else _RE_JSON_FENCED
        raw_re = _RE_JSON_ARRAY if expect_array else _RE_JSON_OBJECT

        # Strategy 1: Fenced code block
        result = self._try_parse_regex(fenced_re, text, group=1)
        if result is not None:
            return result

        # Strategy 2: Raw JSON parse
        result = self._try_raw_json(text)
        if result is not None:
            return result

        # Strategy 3: Find JSON in mixed text
        result = self._try_parse_regex(raw_re, text, group=0)
        if result is not None:
            return result

        return None

    @staticmethod
    def _try_parse_regex(
        pattern: re.Pattern[str], text: str, *, group: int,
    ) -> dict | list | None:
        """Try parsing JSON from a regex match."""
        match = pattern.search(text)
        if not match:
            return None
        try:
            return json.loads(match.group(group))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _try_raw_json(text: str) -> dict | list | None:
        """Try parsing text directly as JSON dict or list."""
        try:
            result = json.loads(text.strip())
            if isinstance(result, (dict, list)):
                return result
        except json.JSONDecodeError:
            pass
        return None

    def _repair_with_llm(
        self,
        broken_response: str,
        expect_array: bool = False,
    ) -> dict | list | None:
        """Ask LLM to fix broken JSON output."""
        type_str = "JSON array" if expect_array else "JSON object"
        repair_prompt = (
            f"The following text should be a valid {type_str} but has errors. "
            f"Fix it and return ONLY the corrected {type_str}, nothing else:\n\n"
            f"{broken_response[:2000]}"
        )

        try:
            repaired = self._llm.query(repair_prompt, timeout=10)
            return self._extract_json(repaired, expect_array=expect_array)
        except Exception as e:
            logger.debug("JSON repair failed: %s", e)
            return None

    def get_stats(self) -> dict[str, int]:
        """Get parsing statistics."""
        return dict(self._stats)


# ─────────────────────── Prompt Templates ───────────────────────

class PromptTemplates:
    """Standardized prompt templates that guide LLMs toward structured output.

    These work with ANY LLM — no function calling or special features needed.
    The key insight: clear instructions + examples = reliable JSON output.
    """

    @staticmethod
    def pentest_action(
        user_input: str,
        target: str | None = None,
        phase: str = "unknown",
        available_tools: list[str] | None = None,
        language: str = "tr",
    ) -> str:
        """Generate prompt for pentest action decision."""
        tools_str = ", ".join(available_tools[:15]) if available_tools else "nmap, nikto, sqlmap, gobuster, hydra"
        target_str = target or "not set"

        return (
            f"Target: {target_str} | Phase: {phase}\n"
            f"Available tools: {tools_str}\n\n"
            f"User request: {user_input}\n\n"
            f"Respond ONLY with a JSON object:\n"
            f'{{"intent": "scan|exploit|recon|enumerate|chat|finish", '
            f'"confidence": 0.0-1.0, '
            f'"tool": "tool_name_or_null", '
            f'"arguments": {{"target": "..."}}, '
            f'"reasoning": "why this action (in {"Turkish" if language == "tr" else "English"})", '
            f'"risks": ["risk1"], '
            f'"needs_approval": false}}'
        )

    @staticmethod
    def tool_analysis(
        tool_name: str,
        output: str,
        target: str = "",
        phase: str = "",
        max_output: int = 4000,
    ) -> str:
        """Generate prompt for analyzing tool output."""
        truncated = output[:max_output]
        return (
            f"Analyze this {tool_name} output for target {target} (phase: {phase}).\n\n"
            f"OUTPUT:\n{truncated}\n\n"
            f"Respond ONLY with a JSON object:\n"
            f'{{"summary": "2-3 sentence analysis", '
            f'"findings": ["finding1", "finding2"], '
            f'"severity": "info|low|medium|high|critical", '
            f'"next_steps": [{{"action": "x", "tool": "y", "reason": "z"}}]}}'
        )

    @staticmethod
    def recovery_suggestion(
        tool_name: str,
        error: str,
        target: str = "",
        available_tools: list[str] | None = None,
    ) -> str:
        """Generate prompt for failure recovery."""
        tools_str = ", ".join(available_tools[:15]) if available_tools else "nmap, nikto, sqlmap"
        return (
            f"Tool '{tool_name}' failed on target {target}.\n"
            f"ERROR: {error[:500]}\n"
            f"Available tools: {tools_str}\n\n"
            f"Suggest 1-3 recovery steps. Respond ONLY with a JSON array:\n"
            f'[{{"action": "action_name", "tool": "tool_name", "reason": "why"}}]'
        )

    @staticmethod
    def reflection(
        last_actions: list[dict[str, Any]],
        goal: str = "",
        step_count: int = 0,
    ) -> str:
        """Generate prompt for self-reflection."""
        actions_str = json.dumps(last_actions[-5:], indent=2, default=str)
        return (
            f"Goal: {goal}\n"
            f"Steps completed: {step_count}\n\n"
            f"Recent actions and results:\n{actions_str}\n\n"
            f"Reflect on progress. Respond ONLY with a JSON object:\n"
            f'{{"verdict": "continue|pivot|escalate", '
            f'"reasoning": "analysis", '
            f'"progress_assessment": "how close to goal", '
            f'"blind_spots": ["what might be missed"], '
            f'"suggested_changes": ["what to do differently"]}}'
        )


# ─────────────────────── Utilities ───────────────────────

def _safe_float(value: Any, default: float = 0.5) -> float:
    """Safely convert value to float with bounds."""
    try:
        result = float(value)
        return min(max(result, 0.0), 1.0)
    except (TypeError, ValueError):
        return default
