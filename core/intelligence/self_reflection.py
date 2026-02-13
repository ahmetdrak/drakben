# core/intelligence/self_reflection.py
# DRAKBEN — Proactive Self-Reflection Engine
# Instead of only reacting to errors, the agent periodically
# evaluates its own performance and decides whether to continue,
# change strategy, or escalate.
#
# Runs every N steps during autonomous scanning.

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReflectionEntry:
    """Single reflection checkpoint."""

    step: int
    timestamp: float
    verdict: str           # continue, pivot, escalate
    reasoning: str
    progress_pct: float    # Estimated progress (0.0-1.0)
    blind_spots: list[str] = field(default_factory=list)
    suggested_changes: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


class SelfReflectionEngine:
    """Proactive self-reflection that runs periodically during scans.

    Instead of only reacting to errors, this engine asks:
    1. Am I making progress toward the goal?
    2. Am I repeating failed approaches?
    3. What information am I missing?
    4. Should I change strategy?

    Usage::

        reflector = SelfReflectionEngine(llm_client=client)
        should_continue = reflector.reflect(
            step=10,
            goal="Pentest 10.0.0.1",
            recent_actions=[...],
            agent_state=state,
        )
        if should_continue.verdict == "pivot":
            # Change strategy

    """

    REFLECT_EVERY_N_STEPS = 5     # How often to reflect
    MAX_REFLECTIONS = 50          # History limit
    STAGNATION_THRESHOLD = 3      # Same action repeated N times = stagnation

    def __init__(
        self,
        llm_client: Any = None,
        *,
        reflect_interval: int = 5,
    ) -> None:
        self._llm = llm_client
        self.reflect_interval = max(reflect_interval, 3)
        self.history: list[ReflectionEntry] = []
        self._stats = {
            "total_reflections": 0,
            "pivots_suggested": 0,
            "escalations_suggested": 0,
        }

    def should_reflect(self, step: int) -> bool:
        """Check if it's time for a reflection checkpoint."""
        return step > 0 and step % self.reflect_interval == 0

    def reflect(
        self,
        step: int,
        goal: str,
        recent_actions: list[dict[str, Any]],
        agent_state: Any = None,
        observations: list[dict[str, Any]] | None = None,
    ) -> ReflectionEntry:
        """Perform a reflection checkpoint.

        Args:
            step: Current step number
            goal: High-level objective
            recent_actions: Last N actions with results
            agent_state: Current agent state
            observations: Recent tool observations

        Returns:
            ReflectionEntry with verdict and suggestions

        """
        self._stats["total_reflections"] += 1

        # Gather metrics
        metrics = self._compute_metrics(recent_actions, agent_state)

        # Try LLM-based reflection
        if self._llm:
            entry = self._llm_reflect(step, goal, recent_actions, metrics, agent_state)
            if entry:
                self._record(entry)
                return entry

        # Rule-based reflection
        entry = self._rule_reflect(step, goal, recent_actions, metrics, agent_state)
        self._record(entry)
        return entry

    def _compute_metrics(
        self,
        recent_actions: list[dict[str, Any]],
        agent_state: Any = None,
    ) -> dict[str, Any]:
        """Compute quantitative metrics for reflection."""
        metrics: dict[str, Any] = {}

        if recent_actions:
            # Success rate
            successes = sum(1 for a in recent_actions if a.get("success"))
            metrics["success_rate"] = successes / len(recent_actions)

            # Action diversity (unique tools used)
            tools = {a.get("tool", "") for a in recent_actions}
            metrics["tools_used"] = len(tools)
            metrics["tool_names"] = list(tools)

            # Repetition detection
            tool_sequence = [a.get("tool", "") for a in recent_actions[-6:]]
            repetitions = self._count_repetitions(tool_sequence)
            metrics["repetition_count"] = repetitions

            # Time analysis
            durations = [a.get("duration", 0) for a in recent_actions if a.get("duration")]
            if durations:
                metrics["avg_duration"] = sum(durations) / len(durations)
                metrics["total_time"] = sum(durations)

        if agent_state:
            metrics["phase"] = getattr(agent_state, "phase", None)
            if hasattr(agent_state, "phase"):
                metrics["phase"] = agent_state.phase.value
            metrics["services_found"] = len(getattr(agent_state, "open_services", {}))
            metrics["vulns_found"] = len(getattr(agent_state, "vulnerabilities", []))
            metrics["has_foothold"] = getattr(agent_state, "has_foothold", False)
            metrics["iteration"] = getattr(agent_state, "iteration_count", 0)

        return metrics

    @staticmethod
    def _count_repetitions(sequence: list[str]) -> int:
        """Count consecutive repetitions in a sequence."""
        if len(sequence) < 2:
            return 0
        count = 0
        for i in range(1, len(sequence)):
            if sequence[i] == sequence[i - 1] and sequence[i]:
                count += 1
        return count

    def _llm_reflect(
        self,
        step: int,
        goal: str,
        recent_actions: list[dict[str, Any]],
        metrics: dict[str, Any],
        agent_state: Any = None,
    ) -> ReflectionEntry | None:
        """Use LLM for deep self-reflection."""
        try:
            # Build compact action summary
            actions_summary = []
            for a in recent_actions[-8:]:
                tool = a.get("tool", "?")
                success = "✓" if a.get("success") else "✗"
                output_preview = str(a.get("output", ""))[:100]
                actions_summary.append(f"  [{success}] {tool}: {output_preview}")

            state_info = ""
            if agent_state:
                state_info = (
                    f"Phase: {metrics.get('phase', '?')} | "
                    f"Services: {metrics.get('services_found', 0)} | "
                    f"Vulns: {metrics.get('vulns_found', 0)} | "
                    f"Foothold: {metrics.get('has_foothold', False)}"
                )

            prompt = (
                f"SELF-REFLECTION CHECKPOINT (Step {step})\n"
                f"Goal: {goal}\n"
                f"State: {state_info}\n\n"
                f"Recent Actions:\n" + "\n".join(actions_summary) + "\n\n"
                f"Metrics:\n"
                f"  Success rate: {metrics.get('success_rate', 0):.0%}\n"
                f"  Tools used: {metrics.get('tools_used', 0)}\n"
                f"  Repetitions: {metrics.get('repetition_count', 0)}\n\n"
                f"Questions to answer:\n"
                f"1. Am I making progress toward the goal?\n"
                f"2. Am I repeating failed approaches?\n"
                f"3. What information am I missing?\n"
                f"4. Should I change strategy?\n\n"
                f"Respond ONLY as JSON:\n"
                f'{{"verdict": "continue|pivot|escalate", '
                f'"reasoning": "analysis", '
                f'"progress_pct": 0.0-1.0, '
                f'"blind_spots": ["what might be missed"], '
                f'"suggested_changes": ["what to do differently"]}}'
            )

            t0 = time.time()
            response = self._llm.query(prompt, timeout=20)
            duration = time.time() - t0

            logger.debug("Self-reflection completed in %.1fs", duration)

            # Parse response
            data = self._parse_json(response)
            if data:
                verdict = str(data.get("verdict", "continue")).lower()
                if verdict == "pivot":
                    self._stats["pivots_suggested"] += 1
                elif verdict == "escalate":
                    self._stats["escalations_suggested"] += 1

                return ReflectionEntry(
                    step=step,
                    timestamp=time.time(),
                    verdict=verdict,
                    reasoning=str(data.get("reasoning", "")),
                    progress_pct=min(max(float(data.get("progress_pct", 0.0)), 0.0), 1.0),
                    blind_spots=data.get("blind_spots", []),
                    suggested_changes=data.get("suggested_changes", []),
                    metrics=metrics,
                )

        except Exception as e:
            logger.debug("LLM reflection failed: %s", e)

        return None

    def _rule_reflect(
        self,
        step: int,
        _goal: str,
        _recent_actions: list[dict[str, Any]],
        metrics: dict[str, Any],
        _agent_state: Any = None,
    ) -> ReflectionEntry:
        """Rule-based reflection when LLM is unavailable."""
        verdict = "continue"
        reasoning_parts: list[str] = []
        blind_spots: list[str] = []
        suggestions: list[str] = []

        success_rate = metrics.get("success_rate", 0.5)
        repetitions = metrics.get("repetition_count", 0)
        services_found = metrics.get("services_found", 0)
        vulns_found = metrics.get("vulns_found", 0)
        has_foothold = metrics.get("has_foothold", False)

        # Progress estimation
        progress = 0.0
        if services_found > 0:
            progress += 0.2
        if vulns_found > 0:
            progress += 0.3
        if has_foothold:
            progress += 0.5

        # Check for problems
        if success_rate < 0.3:
            verdict = "pivot"
            reasoning_parts.append(f"Low success rate ({success_rate:.0%}) — tools failing too often")
            suggestions.append("Try different tools or check target reachability")

        if repetitions >= self.STAGNATION_THRESHOLD:
            verdict = "pivot"
            reasoning_parts.append(f"Stagnation detected ({repetitions} repeated actions)")
            suggestions.append("Switch to a different attack vector")

        if step > 15 and services_found == 0:
            verdict = "pivot"
            reasoning_parts.append("No services found after 15 steps")
            suggestions.append("Verify target is reachable, try broader port ranges")
            blind_spots.append("Target may be behind a firewall")

        if step > 20 and vulns_found == 0 and services_found > 0:
            reasoning_parts.append("Services found but no vulnerabilities detected yet")
            suggestions.append("Try more aggressive vulnerability scanning")
            blind_spots.append("May need authenticated scanning")

        if not reasoning_parts:
            if progress > 0:
                reasoning_parts.append(f"Making progress ({progress:.0%} estimated)")
            else:
                reasoning_parts.append("Early stage — gathering information")

        return ReflectionEntry(
            step=step,
            timestamp=time.time(),
            verdict=verdict,
            reasoning="; ".join(reasoning_parts),
            progress_pct=progress,
            blind_spots=blind_spots,
            suggested_changes=suggestions,
            metrics=metrics,
        )

    def _record(self, entry: ReflectionEntry) -> None:
        """Record reflection in history."""
        self.history.append(entry)
        if len(self.history) > self.MAX_REFLECTIONS:
            self.history = self.history[-self.MAX_REFLECTIONS:]

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any] | None:
        """Parse JSON from LLM response."""
        import re

        # Try fenced code block
        match = re.search(r"```(?:json)?\s*(\{[^}]*\})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try raw JSON
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass

        # Try finding JSON object in text
        match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None

    def get_latest_verdict(self) -> str:
        """Get the most recent reflection verdict."""
        if self.history:
            return self.history[-1].verdict
        return "continue"

    def get_progress_trend(self) -> list[float]:
        """Get progress percentage trend over time."""
        return [e.progress_pct for e in self.history]

    def get_stats(self) -> dict[str, Any]:
        """Get reflection statistics."""
        stats = dict(self._stats)
        stats["history_length"] = len(self.history)
        if self.history:
            stats["latest_verdict"] = self.history[-1].verdict
            stats["latest_progress"] = self.history[-1].progress_pct
        return stats
