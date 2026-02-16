"""Reflection and ReAct loop mixin for RefactoredDrakbenAgent.

Handles self-reflection checkpoints, the ReAct alternative scanning loop,
and the final execution report.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.agent._agent_protocol import AgentProtocol

    _MixinBase = AgentProtocol
else:
    _MixinBase = object

logger: logging.Logger = logging.getLogger(__name__)


class RAReflectionMixin(_MixinBase):
    """Mixin: self-reflection, ReAct loop, and final report."""

    def _show_final_report(self) -> None:
        """Show final execution report."""
        from rich.panel import Panel
        from rich.text import Text

        if not self.state:
            self.console.print("\n[yellow]No state available for report.[/yellow]")
            return

        self.console.print("\n" + "=" * 60, style="bold")
        self.console.print("\U0001f4ca FINAL REPORT", style=self.STYLE_GREEN)
        self.console.print("=" * 60, style="bold")

        report = Text()
        report.append(f"\U0001f3af Target: {self.state.target}\n", style="bold")
        report.append(
            f"\U0001f504 Iterations: {self.state.iteration_count}/{self.state.max_iterations}\n",
        )
        report.append(f"\U0001f4cd Final Phase: {self.state.phase.value}\n")
        report.append(f"\U0001f513 Services Found: {len(self.state.open_services)}\n")
        report.append(f"\u26a0\ufe0f  Vulnerabilities: {len(self.state.vulnerabilities)}\n")
        report.append(f"\U0001f3aa Foothold: {'YES' if self.state.has_foothold else 'NO'}\n")

        if self.state.has_foothold:
            report.append(f"   Method: {self.state.foothold_method}\n", style="green")

        if self.state.invariant_violations:
            report.append("\n\u274c Invariant Violations:\n", style=self.STYLE_RED)
            for violation in self.state.invariant_violations:
                report.append(f"   - {violation}\n", style="red")

        self.console.print(Panel(report, border_style="green", title="Summary"))

    def _run_self_reflection(self, iteration: int) -> None:
        """Run periodic self-reflection checkpoint (Intelligence v2)."""
        if not self.reflector or not self.state:
            return

        try:
            recent_actions = self._gather_recent_actions()

            entry = self.reflector.reflect(
                step=iteration,
                goal=f"Pentest {self.state.target}",
                recent_actions=recent_actions,
                agent_state=self.state,
            )

            self._display_reflection(iteration, entry)
            self._act_on_reflection(entry)

        except Exception as e:
            logger.debug("Self-reflection failed: %s", e)

    def _gather_recent_actions(self) -> list[dict[str, Any]]:
        """Gather recent actions from evolution memory for reflection."""
        if not self.evolution:
            return []
        recent_actions: list[dict[str, Any]] = []
        for r in self.evolution.get_recent_actions(count=8):
            recent_actions.append(
                {
                    "tool": r.tool if hasattr(r, "tool") else str(r),
                    "success": (r.outcome == "success") if hasattr(r, "outcome") else False,
                    "output": r.error_message[:100] if hasattr(r, "error_message") else "",
                }
            )
        return recent_actions

    def _display_reflection(self, iteration: int, entry: Any) -> None:
        """Display self-reflection result to console."""
        verdict_style = {
            "continue": "green",
            "pivot": "yellow",
            "escalate": "red",
        }.get(entry.verdict, "dim")

        self.console.print(
            f"\n\U0001fa9e Self-Reflection (Step {iteration}): "
            f"[{verdict_style}]{entry.verdict.upper()}[/{verdict_style}]",
            style="bold",
        )
        if entry.reasoning:
            self.console.print(f"   \U0001f4ad {entry.reasoning[:200]}", style="dim")
        if entry.blind_spots:
            self.console.print(f"   \U0001f50d Blind spots: {', '.join(entry.blind_spots[:3])}", style="dim")
        if entry.suggested_changes:
            self.console.print(f"   \U0001f4a1 Suggestions: {', '.join(entry.suggested_changes[:3])}", style="dim")

    def _act_on_reflection(self, entry: Any) -> None:
        """Act on reflection verdict if strategy change is needed."""
        if entry.verdict != "pivot" or not self.current_strategy:
            return
        self.console.print(
            "   \U0001f504 Reflection suggests strategy change \u2014 triggering replan",
            style="yellow",
        )
        current_step = self.planner.get_next_step()
        if current_step:
            self.planner.replan(current_step.step_id)

    def run_react_loop(self, target: str) -> dict:
        """Run the ReAct loop as an alternative to plan-based scanning.

        This uses tight Observe\u2192Think\u2192Act cycles where the LLM
        decides EVERY step based on real tool output.

        Usage from menu: /react <target>
        """
        if not self.react_loop:
            self.console.print("\u274c ReAct Loop not available", style="red")
            return {"success": False, "error": "ReAct Loop not initialized"}

        from core.agent.state import reset_state

        if not self.state:
            self.state = reset_state(target)

        self.console.print(
            f"\n\U0001f9e0 Starting ReAct Loop for {target}...",
            style=self.STYLE_MAGENTA,
        )
        self.console.print(
            "   [dim]LLM decides each step dynamically based on observations[/dim]",
        )

        result = self.react_loop.run(
            goal=f"Pentest {target} \u2014 discover services, find vulnerabilities, attempt exploitation",
            target=target,
            agent_state=self.state,
        )

        # Display result
        if result.get("success"):
            self.console.print(
                f"\n\u2705 ReAct completed in {result.get('steps_taken', 0)} steps",
                style="green",
            )
        else:
            self.console.print(
                f"\n\u26a0\ufe0f ReAct stopped after {result.get('steps_taken', 0)} steps",
                style="yellow",
            )

        if result.get("final_answer"):
            self.console.print(f"   \U0001f4cb {result['final_answer'][:500]}", style="dim")

        tools_used = result.get("tools_used", [])
        if tools_used:
            self.console.print(f"   \U0001f527 Tools used: {', '.join(tools_used)}", style="dim")

        return result
