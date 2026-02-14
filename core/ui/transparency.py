# core/ui/transparency.py
# DRAKBEN — LLM Transparency Dashboard
# Shows the user WHAT the LLM is doing, WHY it chose a tool, and its analysis

from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

# ── Singleton ───────────────────────────────────────────────
_transparency: TransparencyDashboard | None = None


def get_transparency(console: Console | None = None) -> TransparencyDashboard:
    """Get or create the singleton TransparencyDashboard."""
    global _transparency
    if _transparency is None:
        _transparency = TransparencyDashboard(console or Console())
    elif console is not None:
        _transparency.console = console
    return _transparency


class TransparencyDashboard:
    """Real-time LLM transparency for the user.

    Shows:
    - What the LLM decided and WHY
    - Which tool was chosen and the reasoning
    - LLM analysis of tool output
    - Phase transitions with context
    - State changes (new ports, services, vulns)
    """

    BORDER_THINK = "bright_magenta"
    BORDER_TOOL = "cyan"
    BORDER_ANALYSIS = "bright_green"
    BORDER_STATE = "yellow"
    BORDER_PHASE = "bright_blue"

    # Rich style constants (SonarQube: avoid duplicate literals)
    _STYLE_BOLD_GREEN = "bold green"
    _STYLE_BOLD_CYAN = "bold cyan"
    _STYLE_BOLD_RED = "bold red"

    def __init__(self, console: Console) -> None:
        self.console = console
        self.enabled = True  # Can be toggled by user
        self._last_llm_prompt: str = ""
        self._last_llm_response: str = ""

    # ── LLM Thinking ────────────────────────────────────────

    def show_llm_thinking(self, prompt_summary: str, response: str, duration: float = 0.0) -> None:
        """Show what was sent to the LLM and what came back."""
        if not self.enabled:
            return

        # Truncate for display
        prompt_short = prompt_summary[:300]
        if len(prompt_summary) > 300:
            prompt_short += "..."

        response_short = response[:800]
        if len(response) > 800:
            response_short += f"\n... ({len(response) - 800} chars more)"

        content = Text()
        content.append("📤 Prompt: ", style="bold magenta")
        content.append(f"{prompt_short}\n\n", style="dim")
        content.append("📥 Response: ", style=self._STYLE_BOLD_GREEN)
        content.append(response_short, style="white")

        if duration > 0:
            content.append(f"\n\n⏱️ {duration:.1f}s", style="dim")

        self.console.print(Panel(
            content,
            title="🧠 LLM Thinking",
            border_style=self.BORDER_THINK,
            padding=(0, 1),
        ))

    # ── Tool Selection Reasoning ────────────────────────────

    def show_tool_reasoning(
        self,
        tool_name: str,
        action: str,
        reason: str,
        penalty: float = 0.0,
        profile_info: str = "",
    ) -> None:
        """Show WHY a specific tool was chosen."""
        if not self.enabled:
            return

        content = Text()
        content.append("🔧 Tool: ", style="bold")
        content.append(f"{tool_name}\n", style=self._STYLE_BOLD_CYAN)
        content.append("📋 Action: ", style="bold")
        content.append(f"{action}\n", style="white")
        content.append("💡 Reason: ", style="bold")
        content.append(f"{reason}\n", style="bright_yellow")

        if penalty > 0:
            content.append("⚖️  Penalty: ", style="bold")
            content.append(f"{penalty:.1f}\n", style="red" if penalty > 3 else "yellow")

        if profile_info:
            content.append("🎭 Profile: ", style="bold")
            content.append(f"{profile_info}", style="dim")

        self.console.print(Panel(
            content,
            title="🎯 Tool Decision",
            border_style=self.BORDER_TOOL,
            padding=(0, 1),
        ))

    # ── LLM Analysis of Output ──────────────────────────────

    def show_output_analysis(
        self,
        tool_name: str,
        analysis: dict[str, Any],
    ) -> None:
        """Show LLM's analysis of tool output."""
        if not self.enabled:
            return

        summary = analysis.get("summary", "No summary available")
        findings = analysis.get("findings", [])
        next_action = analysis.get("next_action")
        severity = analysis.get("severity", "info")

        severity_style = {
            "critical": self._STYLE_BOLD_RED,
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }.get(severity, "dim")

        content = Text()
        content.append("📊 Summary: ", style="bold")
        content.append(f"{summary}\n", style="white")

        if findings:
            content.append(f"\n🔍 Findings ({len(findings)}):\n", style=self._STYLE_BOLD_GREEN)
            for i, finding in enumerate(findings[:10], 1):
                content.append(f"   {i}. {finding}\n", style="white")

        content.append("\n⚠️  Severity: ", style="bold")
        content.append(severity.upper(), style=severity_style)

        if next_action:
            content.append("\n➡️  Suggested Next: ", style="bold")
            content.append(str(next_action), style="bright_cyan")

        self.console.print(Panel(
            content,
            title=f"🤖 LLM Analysis — {tool_name}",
            border_style=self.BORDER_ANALYSIS,
            padding=(0, 1),
        ))

    # ── Phase Transition ────────────────────────────────────

    def show_phase_transition(self, old_phase: str, new_phase: str, reason: str = "") -> None:
        """Show when the agent transitions to a new phase."""
        if not self.enabled:
            return

        content = Text()
        content.append(f"{old_phase}", style="dim")
        content.append(" \u2192 ", style="bold white")
        content.append(f"{new_phase}", style="bold bright_blue")
        if reason:
            content.append(f"\n💡 {reason}", style="dim")

        self.console.print(Panel(
            content,
            title="📍 Phase Transition",
            border_style=self.BORDER_PHASE,
            padding=(0, 1),
        ))

    # ── State Change ────────────────────────────────────────

    def show_state_change(self, change_type: str, details: dict[str, Any] | str) -> None:
        """Show when agent state changes (new ports, services, vulns)."""
        if not self.enabled:
            return

        icon = {
            "ports_discovered": "🔓",
            "service_detected": "🌐",
            "vulnerability_found": "⚠️",
            "foothold_gained": "🏴",
            "tool_success": "✅",
            "tool_failure": "❌",
        }.get(change_type, "📝")

        detail_str = str(details) if not isinstance(details, str) else details
        if len(detail_str) > 200:
            detail_str = detail_str[:200] + "..."

        self.console.print(
            f"   {icon} [bold]{change_type}[/]: {detail_str}",
            style="dim cyan",
        )

    # ── Services Table ──────────────────────────────────────

    def show_discovered_services(self, services: dict[int, Any]) -> None:
        """Show a table of newly discovered services."""
        if not self.enabled or not services:
            return

        table = Table(
            title="🔓 Discovered Services",
            show_header=True,
            header_style=self._STYLE_BOLD_CYAN,
            border_style="dim",
        )
        table.add_column("Port", style="bold", width=8)
        table.add_column("Protocol", width=6)
        table.add_column("Service", style="green")

        for port, svc in sorted(services.items()):
            proto = getattr(svc, "protocol", "tcp")
            service = getattr(svc, "service", "unknown")
            table.add_row(str(port), proto, service)

        self.console.print(table)

    # ── Dynamic Plan Injection ───────────────────────────────

    def show_plan_injection(
        self, injected_steps: list[dict[str, str]], source: str = "llm",
    ) -> None:
        """Show when new steps are injected into the plan by LLM or recovery."""
        if not self.enabled or not injected_steps:
            return

        content = Text()
        content.append("🧠 Source: ", style="bold")
        content.append(f"{source}\n", style="bright_magenta")
        content.append("📝 New Steps:\n", style="bold")
        for i, step in enumerate(injected_steps[:8], 1):
            action = step.get("action", "?")
            tool = step.get("tool", action)
            reason = step.get("reason", "")
            content.append(f"   {i}. ", style="dim")
            content.append(f"{action}", style=self._STYLE_BOLD_CYAN)
            content.append(f" ({tool})", style="dim")
            if reason:
                content.append(f" — {reason}", style="bright_yellow")
            content.append("\n")

        self.console.print(Panel(
            content,
            title="➕ Plan Adapted",
            border_style="bright_magenta",
            padding=(0, 1),
        ))

    # ── Approval Request ────────────────────────────────────

    def show_approval_request(
        self, tool_name: str, action: str, risk_level: str, approved: bool,
    ) -> None:
        """Show approval decision for dangerous operations."""
        if not self.enabled:
            return

        status = "✅ APPROVED" if approved else "⛔ SKIPPED"
        status_style = self._STYLE_BOLD_GREEN if approved else self._STYLE_BOLD_RED

        content = Text()
        content.append("🔧 Tool: ", style="bold")
        content.append(f"{tool_name}\n", style=self._STYLE_BOLD_CYAN)
        content.append("📋 Action: ", style="bold")
        content.append(f"{action}\n", style="white")
        content.append("⚠️  Risk: ", style="bold")
        content.append(f"{risk_level.upper()}\n", style=self._STYLE_BOLD_RED)
        content.append("📌 Status: ", style="bold")
        content.append(status, style=status_style)

        self.console.print(Panel(
            content,
            title="🛡️ Approval Check",
            border_style="bright_red",
            padding=(0, 1),
        ))

    # ── LLM Error Recovery ──────────────────────────────────

    def show_llm_recovery(
        self, tool_name: str, error_msg: str, llm_suggestion: str,
    ) -> None:
        """Show when LLM is consulted for error recovery."""
        if not self.enabled:
            return

        content = Text()
        content.append("❌ Failed Tool: ", style="bold")
        content.append(f"{tool_name}\n", style="red")
        content.append("💬 Error: ", style="bold")
        content.append(f"{error_msg[:200]}\n\n", style="dim")
        content.append("🧠 LLM Recovery: ", style="bold")
        content.append(llm_suggestion[:500], style="bright_yellow")

        self.console.print(Panel(
            content,
            title="🔄 Intelligent Recovery",
            border_style="bright_yellow",
            padding=(0, 1),
        ))

    # ── Tool Installation ───────────────────────────────────

    def show_tool_install(
        self, tool_name: str, method: str, success: bool,
    ) -> None:
        """Show tool installation progress and result."""
        if not self.enabled:
            return

        icon = "✅" if success else "❌"
        style = self._STYLE_BOLD_GREEN if success else self._STYLE_BOLD_RED
        self.console.print(
            f"   📦 {icon} [bold]{tool_name}[/] install via {method}",
            style=style,
        )

    # ── LLM Query Logging ───────────────────────────────────

    def log_llm_query(self, prompt: str, response: str, duration: float = 0.0) -> None:
        """Record LLM query for transparency (always, even if display disabled)."""
        self._last_llm_prompt = prompt
        self._last_llm_response = response
        logger.debug("LLM Query [%.1fs]: %s... → %s...", duration, prompt[:80], response[:80])
