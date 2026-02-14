# core/agent/multi_agent.py
# DRAKBEN — Multi-Agent Pilot Framework
# Inspired by PentAGI's 13-role architecture.
# Provides agent role specialization with per-role model selection.

"""Multi-agent orchestration for DRAKBEN.

Defines specialized agent roles that can use different LLM models
for cost optimization (cheap models for simple tasks, expensive
models for reasoning).

Usage::

    from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

    orchestrator = MultiAgentOrchestrator(llm_client, model_overrides)
    result = orchestrator.delegate(AgentRole.RESEARCHER, "Analyze nmap output...")
"""

from __future__ import annotations

import enum
import logging
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


class MultiAgentOrchestrator:
    """Orchestrates task delegation to specialized agent roles.

    Each role can use a different LLM model for cost optimization.
    Falls back to default model if no override is configured.
    """

    def __init__(
        self,
        llm_client: Any = None,
        model_overrides: dict[str, str] | None = None,
    ) -> None:
        self._llm_client = llm_client
        self._model_overrides = model_overrides or {}
        self._call_counts: dict[AgentRole, int] = dict.fromkeys(AgentRole, 0)

    def get_model_for_role(self, role: AgentRole) -> str | None:
        """Get the model override for a specific role.

        Returns None if no override — caller should use default model.
        """
        return self._model_overrides.get(role.value)

    def get_system_prompt(self, role: AgentRole) -> str:
        """Get the system prompt for a specific role."""
        return ROLE_SYSTEM_PROMPTS.get(role, ROLE_SYSTEM_PROMPTS[AgentRole.DEFAULT])

    def delegate(
        self,
        role: AgentRole,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Delegate a task to a specialized agent role.

        Args:
            role: The agent role to handle this task.
            prompt: The user/system prompt for the task.
            context: Additional context for the role.

        Returns:
            Dict with 'success', 'response', 'role', 'model' keys.
        """
        if not self._llm_client:
            return {
                "success": False,
                "response": "No LLM client available",
                "role": role.value,
                "model": None,
            }

        model = self.get_model_for_role(role)
        system_prompt = self.get_system_prompt(role)

        # Add context to prompt if provided
        full_prompt = prompt
        if context:
            context_str = "\n".join(f"- {k}: {v}" for k, v in context.items())
            full_prompt = f"Context:\n{context_str}\n\nTask:\n{prompt}"

        try:
            # Use model override or default
            kwargs: dict[str, Any] = {}
            if model:
                kwargs["model"] = model

            response = self._llm_client.query(
                prompt=full_prompt,
                system_prompt=system_prompt,
                **kwargs,
            )

            self._call_counts[role] += 1

            return {
                "success": True,
                "response": response,
                "role": role.value,
                "model": model or "default",
            }
        except Exception as e:
            logger.exception("Multi-agent delegate failed for role %s", role.value)
            return {
                "success": False,
                "response": str(e),
                "role": role.value,
                "model": model,
            }

    def get_stats(self) -> dict[str, Any]:
        """Get usage statistics per role."""
        return {
            "call_counts": {r.value: c for r, c in self._call_counts.items() if c > 0},
            "model_overrides": self._model_overrides,
            "available_roles": [r.value for r in AgentRole],
        }

    def get_tier(self, role: AgentRole) -> str:
        """Get the cost tier for a role."""
        return DEFAULT_MODEL_TIERS.get(role, "mid")
