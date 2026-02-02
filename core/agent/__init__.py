"""DRAKBEN Agent Submodules Package
Author: @drak_ben.

This package contains modularized components of the agent:
- error_diagnostics: Error pattern matching and diagnosis
- (future) self_healing: Automatic error recovery
- (future) state_manager: State management utilities
"""

from core.agent.error_diagnostics import ErrorDiagnosticsMixin

__all__ = [
    "ErrorDiagnosticsMixin",
]
