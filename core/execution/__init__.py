# core/execution/__init__.py
"""Execution module - command execution, sandboxing, and tool selection."""

from core.execution.execution_engine import (
    CommandSanitizer,
    ExecutionEngine,
    ExecutionResult,
    ExecutionStatus,
    SecurityError,
)
from core.execution.sandbox_manager import SandboxManager

# NOTE: ToolSelector and UniversalInterpreter are NOT re-exported here
# to avoid circular imports (tool_selector → core.agent → refactored_agent → tool_selector).
# Import them directly: ``from core.execution.tool_selector import ToolSelector``

__all__ = [
    "CommandSanitizer",
    "ExecutionEngine",
    "ExecutionResult",
    "ExecutionStatus",
    "SandboxManager",
    "SecurityError",
]
