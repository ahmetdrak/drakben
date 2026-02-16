# core/interfaces.py
# DRAKBEN — Formal Protocol Interfaces
#
# Runtime-checkable Protocol classes that document the contracts
# between major subsystems.  Concrete classes do NOT need to inherit
# from these; structural subtyping (duck typing) is sufficient.
#
# Usage:
#     isinstance(obj, LLMEngineProtocol)   # works at runtime
#     def process(engine: LLMEngineProtocol) -> None: ...  # mypy checks

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# LLM Engine
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMEngineProtocol(Protocol):
    """Contract for the unified LLM engine."""

    def query(
        self,
        prompt: str,
        system_prompt: str | None = None,
        *,
        timeout: int = 30,
        validate: bool = False,
        model_class: type | None = None,
    ) -> str | dict[str, Any]: ...

    def stream(
        self,
        prompt: str,
        system_prompt: str | None = None,
        *,
        timeout: int = 30,
    ) -> Any: ...  # Generator[str, None, None]

    def call_with_tools(
        self,
        prompt: str,
        tools: list[dict[str, Any]],
        system_prompt: str | None = None,
        *,
        timeout: int = 30,
    ) -> dict[str, Any]: ...

    def add_user_message(self, content: str) -> None: ...

    def add_assistant_message(self, content: str) -> None: ...

    def count_tokens(self, text: str) -> int: ...

    def get_stats(self) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Execution Engine
# ---------------------------------------------------------------------------


@runtime_checkable
class ExecutionEngineProtocol(Protocol):
    """Contract for command execution (SmartTerminal)."""

    def execute(
        self,
        command: str,
        timeout: int = 300,
        capture_output: bool = True,
        shell: bool = False,
    ) -> Any: ...  # ExecutionResult

    def execute_sandboxed(
        self,
        command: str,
        timeout: int = 300,
        sandbox_name: str | None = None,
    ) -> Any: ...

    def cancel_current(self) -> bool: ...

    def clear_history(self) -> None: ...


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------


@runtime_checkable
class ReportGeneratorProtocol(Protocol):
    """Contract for penetration test report generation."""

    def set_target(self, target: str) -> None: ...

    def start_assessment(self) -> None: ...

    def end_assessment(self) -> None: ...

    def add_finding(self, finding: Any) -> None: ...

    def add_scan_result(self, result: Any) -> None: ...

    def get_statistics(self) -> dict[str, Any]: ...

    def generate(self, format: Any, output_path: str) -> str: ...


# ---------------------------------------------------------------------------
# Tool Registry
# ---------------------------------------------------------------------------


@runtime_checkable
class ToolRegistryProtocol(Protocol):
    """Contract for tool discovery and execution."""

    def register(self, tool: Any) -> None: ...

    def get(self, name: str) -> Any | None: ...

    def list_tools(self, phase: Any | None = None) -> list[Any]: ...

    def list_names(self) -> list[str]: ...

    def execute(self, tool_name: str, target: str, **kwargs: Any) -> dict: ...  # type: ignore[type-arg]


# ---------------------------------------------------------------------------
# LLM Client (raw provider)
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMClientProtocol(Protocol):
    """Contract for raw LLM provider clients (OpenRouter, Ollama, etc.)."""

    def query(
        self,
        prompt: str,
        system_prompt: str = "",
        *,
        timeout: int = 30,
    ) -> str: ...


# ---------------------------------------------------------------------------
# Credential Store
# ---------------------------------------------------------------------------


@runtime_checkable
class CredentialStoreProtocol(Protocol):
    """Contract for secure secret storage."""

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> bool: ...

    def delete(self, key: str) -> bool: ...


# ---------------------------------------------------------------------------
# Health Checker
# ---------------------------------------------------------------------------


@runtime_checkable
class HealthCheckerProtocol(Protocol):
    """Contract for system health probes."""

    def check(self) -> Any: ...  # HealthReport

    def readiness(self) -> bool: ...
