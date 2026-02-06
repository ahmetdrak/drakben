# core/agent/brain_context.py
# DRAKBEN - Context Manager Module (extracted from brain.py)

from typing import Any


class ContextManager:
    """Bağlam yöneticisi - Sistem durumunu takip eder."""

    def __init__(self) -> None:
        self.current_context: dict = {}
        self.context_history: list[dict] = []

    def update(self, new_context: dict) -> None:
        """Update context with new system information."""
        self.context_history.append(self.current_context.copy())
        self.current_context.update(new_context)

    def get(self, key: str, default=None) -> Any:
        """Get context value."""
        return self.current_context.get(key, default)

    def get_full_context(self) -> dict:
        """Get complete context for AI."""
        return {
            "current": self.current_context,
            "previous": self.context_history[-1] if self.context_history else {},
            "changes": self._detect_changes(),
        }

    def _detect_changes(self) -> list[str]:
        """Detect what changed in context."""
        changes = []

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

    def clear_history(self) -> None:
        """Clear context history."""
        self.context_history = []
