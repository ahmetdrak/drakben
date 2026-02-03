"""DRAKBEN Agent Package
Author: @drak_ben.

This package contains the core agent components:
- refactored_agent: Main autonomous agent
- brain: LLM-powered decision making
- planner: Attack planning and orchestration
- state: Agent state management
- error_diagnostics: Error pattern matching
- recovery/healer: Self-healing capabilities
"""

from core.agent.brain import DrakbenBrain
from core.agent.error_diagnostics import ErrorDiagnosticsMixin
from core.agent.planner import Planner
from core.agent.refactored_agent import RefactoredDrakbenAgent
from core.agent.state import (
    AgentState,
    AttackPhase,
    ServiceInfo,
    VulnerabilityInfo,
    reset_state,
)

__all__ = [
    "AgentState",
    "AttackPhase",
    "DrakbenBrain",
    "ErrorDiagnosticsMixin",
    "Planner",
    "RefactoredDrakbenAgent",
    "ServiceInfo",
    "VulnerabilityInfo",
    "reset_state",
]
