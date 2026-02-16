# core/agent/brain_orchestrator.py
# DRAKBEN - Master Orchestrator Module (extracted from brain.py)

from __future__ import annotations

import logging
from typing import Any

logger: logging.Logger = logging.getLogger(__name__)

# Error message constants (SonarCloud: avoid duplicate literals)
_ERR_ORCHESTRATOR_NOT_INIT = "Orchestrator modules are not initialized"
_ERR_CONTEXT_NOT_INIT = "Context manager is not initialized"


class MasterOrchestrator:
    """Ana orkestratör - Tüm modülleri koordine eder."""

    def __init__(self) -> None:
        """Initialize the orchestrator with sub-modules and clear context."""
        from core.agent.brain import ExecutionContext

        self.context = ExecutionContext()
        self.reasoning_engine = None
        self.context_manager = None
        self.self_correction = None
        self.decision_engine = None

    def initialize(
        self,
        reasoning: Any,
        context_mgr: Any,
        self_corr: Any,
        decision: Any,
    ) -> None:
        """Connect the orchestrator to its functional modules.

        Args:
            reasoning: The reasoning engine instance.
            context_mgr: The context manager instance.
            self_corr: The self-correction module instance.
            decision: The decision engine instance.

        """
        self.reasoning_engine = reasoning
        self.context_manager = context_mgr
        self.self_correction = self_corr
        self.decision_engine = decision

    def _make_error_response(self, error_msg: str) -> dict:
        """Create standardized error response."""
        return {
            "action": "error",
            "error": error_msg,
            "response": error_msg,
            "llm_response": error_msg,
            "needs_approval": False,
            "steps": [],
            "risks": [],
        }

    def _validate_modules(self) -> dict | None:
        """Validate all core modules are initialized. Returns error dict if invalid."""
        if self.reasoning_engine is None or self.decision_engine is None or self.self_correction is None:
            return self._make_error_response(_ERR_ORCHESTRATOR_NOT_INIT)
        if self.context_manager is None:
            return self._make_error_response(_ERR_CONTEXT_NOT_INIT)
        return None

    def _update_context(self, system_context: dict) -> None:
        """Update context manager and execution context."""
        self.context_manager.update(system_context)
        self.context.system_info.update(self.context_manager.current_context)
        if "language" in system_context:
            self.context.language = system_context["language"]
        if "target" in system_context:
            self.context.target = system_context["target"]

    def _check_infinite_loop(self, decision: dict) -> dict | None:
        """Check for infinite loop patterns. Returns error dict if detected."""
        if len(self.context.history) < 3:
            return None

        last_3 = self.context.history[-3:]
        current_action = self._normalize_action(decision.get("action") or decision.get("next_action", {}).get("type"))
        repeated_count = sum(1 for hist in last_3 if self._get_hist_action(hist) == current_action)

        if repeated_count >= 3:
            logging.getLogger(__name__).critical("Infinite Loop Detected: Same action proposed 3+ times.")
            return {
                "action": "error",
                "error": "Infinite Loop Detected. The agent is repeating the same action.",
                "needs_approval": True,
                "risks": ["Infinite Loop"],
            }
        return None

    @staticmethod
    def _normalize_action(action) -> str | None:
        """Normalize an action to a comparable string."""
        if action is None:
            return None
        if isinstance(action, dict):
            return action.get("tool") or action.get("type") or str(sorted(action.items()))
        return str(action)

    def _get_hist_action(self, hist: dict) -> str | None:
        """Extract action from history entry."""
        hist_action_obj = hist.get("action", {})
        return self._normalize_action(hist_action_obj)

    def process_request(self, user_input: str, system_context: dict) -> dict:
        """Ana işlem döngüsü.

        Returns:
            {
                "plan": [...],
                "needs_approval": bool,
                "reasoning": str,
                "next_action": {...}
            }

        """
        # Validate modules
        if validation_error := self._validate_modules():
            return validation_error

        # Update context
        self._update_context(system_context)

        # Continuous reasoning
        analysis = self.reasoning_engine.analyze(user_input, self.context)

        # Check for errors from LLM
        if not analysis.get("success", True):
            return self._make_error_response(analysis.get("error", "Unknown error"))

        # Decision making
        decision = self.decision_engine.decide(analysis, self.context)

        # Preserve response from analysis
        if analysis.get("response"):
            decision["response"] = analysis["response"]
        if analysis.get("llm_response"):
            decision["llm_response"] = analysis["llm_response"]

        # Check for infinite loops
        if loop_error := self._check_infinite_loop(decision):
            return loop_error

        # Self-correction check
        if decision.get("has_risks") and self.self_correction:
            decision = self.self_correction.review(decision)

        # Record decision in history for infinite loop detection
        self.context.history.append(
            {
                "action": decision.get("action") or decision.get("next_action", {}),
                "command": decision.get("command"),
                "success": not decision.get("error"),
            }
        )

        # Prevent unbounded memory growth in long autonomous sessions
        _MAX_HISTORY = 500
        if len(self.context.history) > _MAX_HISTORY:
            self.context.history = self.context.history[-_MAX_HISTORY:]

        return decision
