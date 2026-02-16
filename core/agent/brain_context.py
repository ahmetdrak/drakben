# core/agent/brain_context.py
# DRAKBEN - Typed Context Manager Module (extracted from brain.py)
# Improvement: typed context keys + enum-based access for safety.

from __future__ import annotations

import enum
from typing import Any


class ContextKey(enum.Enum):
    """Typed context keys — prevents string-based key errors."""

    # Target info
    TARGET = "target"
    TARGET_TYPE = "target_type"
    TARGET_OS = "target_os"

    # Phase & progress
    PHASE = "phase"
    ITERATION = "iteration"
    MAX_ITERATIONS = "max_iterations"

    # Discoveries
    OPEN_PORTS = "open_ports"
    SERVICES = "services"
    VULNERABILITIES = "vulnerabilities"
    CREDENTIALS = "credentials"

    # Execution state
    LAST_TOOL = "last_tool"
    LAST_OUTPUT = "last_output"
    LAST_ERROR = "last_error"
    TOOLS_RUN = "tools_run"

    # Strategy
    STRATEGY = "strategy"
    PROFILE = "profile"
    SCAN_MODE = "scan_mode"

    # LLM
    LLM_MODEL = "llm_model"
    LLM_PROVIDER = "llm_provider"

    # Findings
    FOOTHOLD = "foothold"
    FOOTHOLD_METHOD = "foothold_method"

    # System
    AVAILABLE_TOOLS = "available_tools"
    KALI_DETECTED = "kali_detected"

    # Custom (for extensibility)
    CUSTOM = "custom"


class ContextManager:
    """Typed context manager — tracks system state with type-safe keys.

    Supports both typed (ContextKey enum) and string-based access
    for backward compatibility.
    """

    MAX_HISTORY_SIZE = 500  # Prevent unbounded growth

    def __init__(self) -> None:
        self.current_context: dict[str, Any] = {}
        self.context_history: list[dict[str, Any]] = []

    def update(self, new_context: dict[str, Any]) -> None:
        """Update context with new system information.

        Accepts both ``ContextKey`` enum keys and plain strings.
        """
        self.context_history.append(self.current_context.copy())
        # Evict oldest entries to prevent memory leak
        if len(self.context_history) > self.MAX_HISTORY_SIZE:
            self.context_history = self.context_history[-self.MAX_HISTORY_SIZE :]
        # Normalize ContextKey enums to their string values
        normalized = {(k.value if isinstance(k, ContextKey) else k): v for k, v in new_context.items()}
        self.current_context.update(normalized)

    def set(self, key: ContextKey | str, value: Any) -> None:
        """Set a single typed context value."""
        str_key = key.value if isinstance(key, ContextKey) else key
        self.update({str_key: value})

    def get(self, key: ContextKey | str, default: Any = None) -> Any:
        """Get context value by typed key or string key."""
        str_key = key.value if isinstance(key, ContextKey) else key
        return self.current_context.get(str_key, default)

    def get_typed(self, key: ContextKey, expected_type: type, default: Any = None) -> Any:
        """Get context value with runtime type checking.

        Returns ``default`` if the value is not of the expected type.
        """
        value = self.current_context.get(key.value, default)
        if value is not None and not isinstance(value, expected_type):
            return default
        return value

    def get_full_context(self) -> dict[str, Any]:
        """Get complete context for AI."""
        return {
            "current": self.current_context,
            "previous": self.context_history[-1] if self.context_history else {},
            "changes": self._detect_changes(),
        }

    def _detect_changes(self) -> list[str]:
        """Detect what changed in context."""
        changes: list[str] = []

        if not self.context_history:
            return ["Initial context"]

        prev = self.context_history[-1]
        curr = self.current_context

        for key in curr:
            if key not in prev:
                changes.append(f"Added: {key}")
            elif curr[key] != prev.get(key):
                changes.append(f"Changed: {key}")

        return changes

    def has(self, key: ContextKey | str) -> bool:
        """Check if a context key exists."""
        str_key = key.value if isinstance(key, ContextKey) else key
        return str_key in self.current_context

    def remove(self, key: ContextKey | str) -> None:
        """Remove a context key."""
        str_key = key.value if isinstance(key, ContextKey) else key
        self.current_context.pop(str_key, None)

    def clear_history(self) -> None:
        """Clear context history."""
        self.context_history = []

    def snapshot(self) -> dict[str, Any]:
        """Get a frozen snapshot of the current context."""
        return dict(self.current_context)
