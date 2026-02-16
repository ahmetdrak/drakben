# core/agent/multi_agent.py
# DRAKBEN — Multi-Agent Pilot Framework
# Inspired by PentAGI's 13-role architecture.
# Provides agent role specialization with per-role model selection.

"""Multi-agent orchestration for DRAKBEN.

Defines specialized agent roles that can use different LLM models
for cost optimization (cheap models for simple tasks, expensive
models for reasoning).

Integration points:
- FallbackChain for automatic provider failover
- PromptRegistry for centralized, versioned system prompts
- EventBus for delegation telemetry

Usage::

    from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

    orchestrator = MultiAgentOrchestrator(llm_client, model_overrides)
    result = orchestrator.delegate(AgentRole.RESEARCHER, "Analyze nmap output...")
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


class AgentRole(enum.Enum):
    """Specialized agent roles for task delegation.

    Each role can use a different LLM model for cost optimization.
    """

    # Core roles
    REASONING = "reasoning"      # Main reasoning / planning (~expensive model)
    PARSING = "parsing"          # Output parsing / summarization (~cheap model)
    CODING = "coding"            # Code generation / review (~mid-tier model)
    SCANNING = "scanning"        # Scan result analysis (~cheap model)
    REPORTING = "reporting"      # Report generation (~mid-tier model)

    # Advanced roles
    RESEARCHER = "researcher"    # Exploit research / CVE analysis
    ADVISER = "adviser"          # Strategic recommendations
    REFLECTOR = "reflector"      # Self-reflection / improvement
    ENRICHER = "enricher"        # Data enrichment / OSINT
    INSTALLER = "installer"     # Tool installation / setup

    # Default
    DEFAULT = "default"          # Fallback for unspecified roles


# Default model tiers (users override via config.model_overrides)
DEFAULT_MODEL_TIERS: dict[AgentRole, str] = {
    AgentRole.REASONING: "expensive",    # GPT-4o, Claude-3.5-Sonnet
    AgentRole.PARSING: "cheap",          # Llama-3.1-8B, GPT-4o-mini
    AgentRole.CODING: "mid",             # DeepSeek-Coder, GPT-4o-mini
    AgentRole.SCANNING: "cheap",         # Llama-3.1-8B
    AgentRole.REPORTING: "mid",          # GPT-4o-mini
    AgentRole.RESEARCHER: "expensive",   # GPT-4o
    AgentRole.ADVISER: "mid",            # GPT-4o-mini
    AgentRole.REFLECTOR: "mid",          # GPT-4o-mini
    AgentRole.ENRICHER: "cheap",         # Llama-3.1-8B
    AgentRole.INSTALLER: "cheap",        # Llama-3.1-8B
    AgentRole.DEFAULT: "mid",            # Default tier
}

# System prompts per role
ROLE_SYSTEM_PROMPTS: dict[AgentRole, str] = {
    AgentRole.REASONING: (
        "You are a senior penetration testing strategist. "
        "Analyze situations deeply, plan attack vectors, and make strategic decisions. "
        "Think step-by-step about the most effective approach."
    ),
    AgentRole.PARSING: (
        "You are a security tool output parser. "
        "Extract structured data from raw tool outputs (nmap, nikto, sqlmap, etc.). "
        "Return JSON with findings, services, vulnerabilities."
    ),
    AgentRole.CODING: (
        "You are a security-focused Python developer. "
        "Write exploit code, automation scripts, and security tools. "
        "Follow secure coding practices. Never use shell=True."
    ),
    AgentRole.SCANNING: (
        "You are a vulnerability scanner analyst. "
        "Analyze scan results, identify false positives, prioritize findings."
    ),
    AgentRole.REPORTING: (
        "You are a professional penetration testing report writer. "
        "Create clear, actionable reports for both technical teams and executives."
    ),
    AgentRole.RESEARCHER: (
        "You are a security researcher specializing in CVE analysis and exploit development. "
        "Research vulnerabilities, find public exploits, assess exploitability."
    ),
    AgentRole.ADVISER: (
        "You are a cybersecurity adviser. "
        "Provide strategic guidance on attack paths, tool selection, and risk assessment."
    ),
    AgentRole.REFLECTOR: (
        "You are a self-improvement analyst for an AI penetration testing agent. "
        "Analyze past actions, identify mistakes, suggest improvements."
    ),
    AgentRole.ENRICHER: (
        "You are an OSINT specialist. "
        "Enrich target data with publicly available information from various sources."
    ),
    AgentRole.INSTALLER: (
        "You are a system administrator. "
        "Help install and configure security tools on Linux/Kali systems."
    ),
    AgentRole.DEFAULT: (
        "You are a helpful penetration testing assistant."
    ),
}


@dataclass(frozen=True, slots=True)
class DelegationRecord:
    """Immutable record of a role delegation."""

    role: str
    model: str
    success: bool
    latency_ms: float
    timestamp: float = 0.0


class MultiAgentOrchestrator:
    """Orchestrates task delegation to specialized agent roles.

    Each role can use a different LLM model for cost optimization.
    Falls back to default model if no override is configured.

    New in Phase 5:
    - FallbackChain integration for automatic provider failover
    - PromptRegistry integration for versioned prompts
    - Delegation history with latency tracking
    - EventBus telemetry
    """

    def __init__(
        self,
        llm_client: Any = None,
        model_overrides: dict[str, str] | None = None,
        *,
        fallback_chain: Any | None = None,
    ) -> None:
        self._llm_client = llm_client
        self._model_overrides = model_overrides or {}
        self._fallback_chain = fallback_chain
        self._call_counts: dict[AgentRole, int] = dict.fromkeys(AgentRole, 0)
        self._delegation_history: list[DelegationRecord] = []
        self._max_history = 200

    def get_model_for_role(self, role: AgentRole) -> str | None:
        """Get the model override for a specific role.

        Returns None if no override — caller should use default model.
        """
        return self._model_overrides.get(role.value)

    def get_system_prompt(self, role: AgentRole) -> str:
        """Get the system prompt for a specific role.

        Tries PromptRegistry first (versioned, bilingual), falls back to
        hardcoded ROLE_SYSTEM_PROMPTS.
        """
        try:
            from core.llm.prompt_registry import get_prompt
            registry_key = f"role.{role.value}"
            prompt = get_prompt(registry_key)
            if prompt:
                return prompt
        except (ImportError, KeyError, AttributeError):
            pass
        return ROLE_SYSTEM_PROMPTS.get(role, ROLE_SYSTEM_PROMPTS[AgentRole.DEFAULT])

    def delegate(
        self,
        role: AgentRole,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Delegate a task to a specialized agent role.

        Tries FallbackChain first (if available), then direct llm_client.

        Args:
            role: The agent role to handle this task.
            prompt: The user/system prompt for the task.
            context: Additional context for the role.

        Returns:
            Dict with 'success', 'response', 'role', 'model', 'latency_ms' keys.
        """
        t0 = time.time()
        model = self.get_model_for_role(role)
        system_prompt = self.get_system_prompt(role)

        # Build full prompt with context
        full_prompt = prompt
        if context:
            context_str = "\n".join(f"- {k}: {v}" for k, v in context.items())
            full_prompt = f"Context:\n{context_str}\n\nTask:\n{prompt}"

        # Try FallbackChain first (multi-provider failover)
        if self._fallback_chain is not None:
            result = self._delegate_via_fallback(role, full_prompt, system_prompt, model, t0)
            if result is not None:
                return result

        # Direct LLM client
        if not self._llm_client:
            return self._make_result(False, "No LLM client available", role, model, t0)

        try:
            kwargs: dict[str, Any] = {}
            if model:
                kwargs["model"] = model

            response = self._llm_client.query(
                prompt=full_prompt,
                system_prompt=system_prompt,
                **kwargs,
            )

            self._call_counts[role] += 1
            return self._make_result(True, response, role, model or "default", t0)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Multi-agent delegate failed for role %s", role.value)
            return self._make_result(False, str(e), role, model, t0)

    def _delegate_via_fallback(
        self,
        role: AgentRole,
        full_prompt: str,
        system_prompt: str,
        _model: str | None,
        t0: float,
    ) -> dict[str, Any] | None:
        """Attempt delegation through FallbackChain."""
        try:
            qr = self._fallback_chain.query(
                prompt=full_prompt,
                system_prompt=system_prompt,
            )
            if qr.success:
                self._call_counts[role] += 1
                return self._make_result(
                    True, qr.response, role, qr.provider_used, t0,
                )
        except (OSError, ValueError, RuntimeError):
            logger.debug("FallbackChain unavailable, falling back to direct client")
        return None

    def _make_result(
        self,
        success: bool,
        response: Any,
        role: AgentRole,
        model: Any,
        t0: float,
    ) -> dict[str, Any]:
        """Build a result dict and record in history."""
        latency_ms = (time.time() - t0) * 1000
        record = DelegationRecord(
            role=role.value,
            model=str(model or ""),
            success=success,
            latency_ms=latency_ms,
            timestamp=t0,
        )
        self._delegation_history.append(record)
        if len(self._delegation_history) > self._max_history:
            self._delegation_history = self._delegation_history[-self._max_history:]

        # Emit event (best-effort)
        try:
            from core.events import EventType, get_event_bus
            get_event_bus().publish(EventType.TOOL_COMPLETE, {
                "tool": f"multi_agent.{role.value}",
                "success": success,
                "latency_ms": latency_ms,
            })
        except (ImportError, AttributeError, RuntimeError):
            pass

        return {
            "success": success,
            "response": response,
            "role": role.value,
            "model": model,
            "latency_ms": round(latency_ms, 1),
        }

    def get_stats(self) -> dict[str, Any]:
        """Get usage statistics per role."""
        total = len(self._delegation_history)
        successes = sum(1 for r in self._delegation_history if r.success)
        avg_latency = (
            sum(r.latency_ms for r in self._delegation_history) / total
            if total > 0 else 0.0
        )
        return {
            "call_counts": {r.value: c for r, c in self._call_counts.items() if c > 0},
            "model_overrides": self._model_overrides,
            "available_roles": [r.value for r in AgentRole],
            "total_delegations": total,
            "success_rate": round(successes / total, 3) if total > 0 else 0.0,
            "avg_latency_ms": round(avg_latency, 1),
        }

    def get_tier(self, role: AgentRole) -> str:
        """Get the cost tier for a role."""
        return DEFAULT_MODEL_TIERS.get(role, "mid")
