# core/agent/tool_dispatch.py
# DRAKBEN — Tool Dispatch Registry (Strategy Pattern)
# Replaces the 15+ if/elif chain in RefactoredDrakbenAgent._execute_tool().
# Each tool type registers a handler → O(1) dispatch via dict lookup.

"""Tool dispatch registry for the autonomous agent.

Usage::

    from core.agent.tool_dispatch import ToolDispatcher

    dispatcher = ToolDispatcher(agent)
    result = dispatcher.dispatch("waf_bypass", args)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from core.agent.refactored_agent import RefactoredDrakbenAgent

logger = logging.getLogger(__name__)


class ToolHandler(Protocol):
    """Protocol for tool execution handlers."""

    def __call__(self, agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]: ...


class ToolDispatcher:
    """Registry-based tool dispatcher (Strategy Pattern).

    Replaces the monolithic ``_execute_tool()`` if/elif chain with
    a dict-based dispatch table. New tool types are registered via
    ``register()`` without modifying existing code.
    """

    def __init__(self, agent: RefactoredDrakbenAgent) -> None:
        self._agent = agent
        self._handlers: dict[str, ToolHandler] = {}
        self._prefix_handlers: list[tuple[str, ToolHandler]] = []
        self._register_defaults()

    def register(self, tool_name: str, handler: ToolHandler) -> None:
        """Register a handler for an exact tool name."""
        self._handlers[tool_name] = handler

    def register_prefix(self, prefix: str, handler: ToolHandler) -> None:
        """Register a handler for tool names starting with ``prefix``."""
        self._prefix_handlers.append((prefix, handler))

    def dispatch(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Dispatch tool execution to the appropriate handler.

        Resolution order:
        1. Exact name match
        2. Prefix match (first registered wins)
        3. Fallback to system tool execution
        """
        args = args or {}

        # 1. Check if tool is blocked
        if self._agent.tool_selector.is_tool_blocked(tool_name):
            return {
                "success": False,
                "error": f"Tool {tool_name} blocked due to repeated failures",
                "args": args,
            }

        # 2. Exact match
        handler = self._handlers.get(tool_name)
        if handler:
            return handler(self._agent, args)

        # 3. Prefix match
        for prefix, prefix_handler in self._prefix_handlers:
            if tool_name.startswith(prefix):
                # Pass tool_name in args for prefix handlers
                args_with_name = {**args, "_tool_name": tool_name}
                return prefix_handler(self._agent, args_with_name)

        # 4. Fallback: system tool via ToolSpec
        return self._execute_system_tool(tool_name, args)

    def _execute_system_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Fallback: execute via ToolSelector + ExecutionEngine."""
        from core.execution.tool_selector import ToolSpec  # noqa: TC001

        tool_spec: ToolSpec | None = self._agent.tool_selector.tools.get(tool_name)
        if not tool_spec:
            return {"success": False, "error": "Tool not found", "args": args}
        return self._agent._run_system_tool(tool_name, tool_spec, args)

    def _register_defaults(self) -> None:
        """Register all built-in tool handlers."""
        # Exact matches
        self.register("system_evolution", _handle_system_evolution)
        self.register("metasploit_exploit", _handle_metasploit)
        self.register("generate_payload", _handle_weapon_foundry)
        self.register("synthesize_code", _handle_singularity)
        self.register("waf_bypass", _handle_waf_bypass)
        self.register("c2_beacon", _handle_c2)
        self.register("subdomain_enum", _handle_subdomain_enum)
        self.register("cve_lookup", _handle_cve_lookup)
        self.register("nuclei_scan", _handle_nuclei_scan)

        # Prefix matches
        self.register_prefix("ad_", _handle_ad_attacks)
        self.register_prefix("hive_mind", _handle_hive_mind)
        self.register_prefix("osint_", _handle_osint)

    @property
    def registered_tools(self) -> list[str]:
        """List all registered exact tool names."""
        return list(self._handlers.keys())

    @property
    def registered_prefixes(self) -> list[str]:
        """List all registered prefixes."""
        return [p for p, _ in self._prefix_handlers]


# ---------------------------------------------------------------------------
# Handler functions (thin wrappers delegating to mixin methods)
# ---------------------------------------------------------------------------

def _handle_system_evolution(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._handle_system_evolution(args)


def _handle_metasploit(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_metasploit(args)


def _handle_weapon_foundry(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_weapon_foundry(args)


def _handle_singularity(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_singularity(args)


def _handle_waf_bypass(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_waf_bypass(args)


def _handle_c2(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_c2(args)


def _handle_subdomain_enum(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_subdomain_enum(args)


def _handle_cve_lookup(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_cve_lookup(args)


def _handle_nuclei_scan(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    return agent._execute_nuclei_scan(args)


def _handle_ad_attacks(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    tool_name = args.pop("_tool_name", "ad_unknown")
    return agent._execute_ad_attacks(tool_name, args)


def _handle_hive_mind(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    tool_name = args.pop("_tool_name", "hive_mind")
    return agent._execute_hive_mind(tool_name, args)


def _handle_osint(agent: RefactoredDrakbenAgent, args: dict[str, Any]) -> dict[str, Any]:
    tool_name = args.pop("_tool_name", "osint_unknown")
    return agent._execute_osint(tool_name, args)
