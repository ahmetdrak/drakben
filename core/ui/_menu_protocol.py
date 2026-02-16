"""Type-checking protocol for DrakbenMenu mixin architecture.

This module defines the shared interface that all Menu* mixins expect
from their host class.  Used exclusively during static analysis
(``TYPE_CHECKING``) — zero runtime overhead.

Pattern (identical to ``core.agent._agent_protocol``):
    Each mixin inherits from ``MenuProtocol`` only when
    ``TYPE_CHECKING`` is ``True``, giving mypy full visibility of
    cross-mixin attribute access without changing the runtime MRO.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.console import Console

    from core.config import ConfigManager, DrakbenConfig


class MenuProtocol(Protocol):
    """Shared attribute contract for all DrakbenMenu mixins.

    Every attribute listed here is set in ``DrakbenMenu.__init__``
    (or as a class-level constant) and may be accessed by any mixin
    through ``self``.
    """

    # ── Instance Attributes (set in __init__) ────────────────────
    config_manager: ConfigManager
    config: DrakbenConfig
    console: Console
    agent: Any  # RefactoredDrakbenAgent | None
    brain: Any  # DrakbenBrain | None
    orchestrator: Any  # PentestOrchestrator | None
    running: bool
    system_info: dict[str, Any]
    _commands: dict[str, Callable[[str], Any]]

    # ── Style Constants ──────────────────────────────────────────
    COLORS: dict[str, str]
    STYLE_BOLD_WHITE: str
    STYLE_BOLD_GREEN: str
    STYLE_BOLD_CYAN: str
    STYLE_BOLD_YELLOW: str
    STYLE_BOLD_RED: str
    STYLE_DIM_CYAN: str
    STYLE_DIM_RED: str

    # ── Command Constants ────────────────────────────────────────
    CMD_SCAN: str
    CMD_SHELL: str
    CMD_STATUS: str
    CMD_CLEAR: str
    CMD_EXIT: str
    CMD_REPORT: str
    CMD_CONFIG: str
    CMD_UNTARGET: str
    CMD_TOOLS: str
    CMD_MEMORY: str

    # ── UI Constants ─────────────────────────────────────────────
    MSG_AGENT_NOT_NONE: str
    BANNER: str
    VERSION: str

    # ── Cross-mixin Methods ──────────────────────────────────────
    def show_banner(self) -> None: ...
    def show_status_line(self) -> None: ...
    def _handle_command(self, user_input: str) -> None: ...
    def _clear_screen(self) -> None: ...
    def _ensure_agent_initialized(self) -> None: ...
