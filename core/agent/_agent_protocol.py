"""Type-checking protocol for RefactoredDrakbenAgent mixin architecture.

This module defines the shared interface that all RA* mixins expect
from their host class. Used exclusively during static analysis
(TYPE_CHECKING) — zero runtime overhead.

Pattern: Each mixin inherits from ``AgentProtocol`` only when
``TYPE_CHECKING`` is ``True``, giving mypy full visibility of
cross-mixin and cross-class attribute access without changing the
runtime MRO.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from rich.console import Console

    from core.agent.state import AgentState


class AgentProtocol(Protocol):
    """Shared attribute contract for all agent mixins.

    Every attribute listed here is set in
    ``RefactoredDrakbenAgent.__init__`` and may be accessed by any
    mixin through ``self``.
    """

    # ── Core Components ──────────────────────────────────────────
    console: Console
    state: AgentState | None
    brain: Any  # DrakbenBrain — lazy import
    tool_selector: Any  # ToolSelector
    executor: Any  # ExecutionEngine
    healer: Any  # SelfHealer
    planner: Any  # Planner
    evolution: Any  # EvolutionMemory
    refining_engine: Any  # SelfRefiningEngine
    coder: Any  # AICoder
    transparency: Any  # TransparencyDashboard
    logger: Any  # DrakbenLogger

    # ── Intelligence v2 (optional) ───────────────────────────────
    reflector: Any  # SelfReflectionEngine | None
    react_loop: Any  # ReActLoop | None

    # ── Runtime State ────────────────────────────────────────────
    running: bool
    stagnation_counter: int
    tools_created_this_session: int
    current_strategy: Any  # Strategy | None
    current_profile: Any  # StrategyProfile | None
    target_signature: str
    _scan_mode: str
    _fallback_mode: bool
    _self_heal_attempts: dict[str, int]

    # ── Class-level Constants ────────────────────────────────────
    MSG_STATE_NOT_NONE: str
    MAX_SELF_HEAL_PER_TOOL: int
    STYLE_GREEN: str
    STYLE_RED: str
    STYLE_CYAN: str
    STYLE_YELLOW: str
    STYLE_MAGENTA: str
    STYLE_MAGENTA_BLINK: str
    STYLE_BLUE: str

    # ── Cross-mixin Methods ──────────────────────────────────────
    def _diagnose_error(
        self,
        output: str,
        exit_code: int,
    ) -> dict[str, Any]: ...

    def _format_tool_result(
        self,
        result: Any,
        args: dict[str, Any],
        tool_name: str = ...,
    ) -> dict[str, Any]: ...

    def _handle_tool_failure(
        self,
        tool_name: str,
        command: str,
        result: Any,
        args: dict[str, Any],
    ) -> dict[str, Any]: ...
