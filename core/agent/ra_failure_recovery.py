"""Failure recovery mixin for RefactoredDrakbenAgent.

Handles step success/failure recording, error categorization, tool
installation recovery, LLM-assisted recovery, and replanning.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.agent._agent_protocol import AgentProtocol
    from core.agent.planner import PlanStep

    _MixinBase = AgentProtocol
else:
    _MixinBase = object

logger: logging.Logger = logging.getLogger(__name__)

# Error message constant (SonarCloud compliance)
_ERR_UNKNOWN = "Unknown error"


class RAFailureRecoveryMixin(_MixinBase):
    """Mixin: step result recording and failure recovery pipeline."""

    def _record_action(
        self,
        step: PlanStep,
        success: bool,
        penalty: float,
        execution_result: dict[str, Any],
    ) -> None:
        """Record action to evolution memory."""
        from core.intelligence.evolution_memory import ActionRecord
        from core.security.security_utils import audit_command

        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        target: str | None = self.state.target
        record = ActionRecord(
            goal=f"pentest_{target}",
            plan_id=self.planner.current_plan_id or "unknown",
            step_id=step.step_id,
            action_name=step.action,
            tool=step.tool,
            parameters=json.dumps(step.params),
            outcome="success" if success else "failure",
            timestamp=time.time(),
            penalty_score=penalty,
            error_message=execution_result.get("stderr", "")[:200],
        )
        self.evolution.record_action(record)

        # Log to secure audit trail
        audit_command(
            command=f"{step.tool} {json.dumps(step.params)}",
            target=self.state.target or "unknown",
            success=success,
            details={
                "step_id": step.step_id,
                "penalty": penalty,
                "duration": execution_result.get("duration", 0),
                "error": str(execution_result.get("error", "")),
            },
        )

    def _handle_step_success(
        self,
        step: PlanStep,
        execution_result: dict[str, Any],
    ) -> None:
        """Handle successful step execution."""
        self.planner.mark_step_success(
            step.step_id,
            execution_result.get("stdout", "")[:200],
        )
        self.console.print("\u2705 Step succeeded", style="green")
        self.stagnation_counter = 0

        # Update profile outcome on success
        if self.current_profile:
            self.refining_engine.update_profile_outcome(
                self.current_profile.profile_id,
                True,
            )

    def _categorize_error(self, error_msg: str) -> str:
        """Categorize error type from error message."""
        error_lower = error_msg.lower()
        if "timeout" in error_lower:
            return "timeout"
        if "connection refused" in error_lower:
            return "connection_refused"
        if "permission" in error_lower:
            return "permission_denied"
        if "not found" in error_lower or "not recognized" in error_lower:
            return "tool_missing"
        return "unknown"

    def _attempt_tool_recovery(self, tool_name: str) -> bool:
        """Attempt to install a missing tool with user-visible progress.

        Shows the user exactly what is being installed, via which package
        manager, and whether it succeeded \u2014 no silent force installs.
        """
        try:
            from core.intelligence.universal_adapter import get_universal_adapter
            adapter = get_universal_adapter()
            if not adapter:
                return False

            # Step 1: Tell the user what we're about to do
            self.console.print(
                f"\n   \U0001f4e6 [bold yellow]Tool '{tool_name}' not found \u2014 attempting install...[/]",
            )

            # Step 2: Check if it's in the registry (known tool)
            from core.intelligence.universal_adapter import TOOL_REGISTRY
            tool_def = TOOL_REGISTRY.get(tool_name)
            if tool_def:
                pm = adapter.resolver.package_manager
                method = pm.value if pm else "auto"
                self.console.print(
                    f"   \U0001f4e6 Install method: [cyan]{method}[/] ({tool_def.description})",
                    style="dim",
                )

            # Step 3: Attempt installation
            install_result = adapter.resolver.install_tool(tool_name, force=True)
            success = install_result.get("success", False)
            method = install_result.get("method", "unknown")

            # Step 4: Show result transparently
            self.transparency.show_tool_install(tool_name, method, success)

            if success:
                self.console.print(
                    f"   \u2705 [bold green]{tool_name} installed via {method}![/]",
                )
                return True

            if install_result.get("requires_approval"):
                # Dynamic discovery found it but needs explicit approval
                proposal = install_result.get("proposal", {})
                self.console.print(
                    f"   \u26a0\ufe0f  Found on {proposal.get('source', '?')}: {proposal.get('description', '')}",
                    style="yellow",
                )
                self.console.print(
                    f"   \U0001f4ac Install command: {proposal.get('install_cmd', '?')}",
                    style="dim",
                )
                try:
                    answer = input("   Install? [Y/n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = "n"

                if answer in ("", "y", "yes", "e", "evet"):
                    force_result = adapter.resolver.install_tool(tool_name, force=True)
                    if force_result.get("success"):
                        self.console.print(f"   \u2705 {tool_name} installed!", style="green")
                        return True

            self.console.print(
                f"   \u274c Install failed: {install_result.get('message', 'Unknown')}",
                style="red",
            )
            return False
        except (ImportError, OSError, RuntimeError, ValueError) as e:
            logger.exception("Dynamic recovery crashed: %s", e)
            return False

    def _attempt_llm_recovery(
        self, step: PlanStep, error_msg: str,
    ) -> list[dict[str, str]]:
        """Ask the LLM how to recover from a tool failure.

        Instead of relying purely on pattern-matching ("connection refused" ->
        hardcoded recovery), we send the error to the LLM and let it suggest
        concrete recovery steps that get injected into the plan.

        Returns:
            List of recovery action dicts, empty if LLM unavailable or failed.
        """
        import re as _re

        llm_client = getattr(self.brain, "llm_client", None)
        if not llm_client:
            return []

        try:
            target = self.state.target if self.state else "N/A"
            phase = self.state.phase.value if self.state else "unknown"

            prompt = (
                f"Tool '{step.tool}' (action: {step.action}) failed on target {target} "
                f"(phase: {phase}).\n"
                f"ERROR: {error_msg[:500]}\n\n"
                f"Suggest 1-3 alternative recovery steps. Respond ONLY in JSON:\n"
                f'[{{"action": "action_name", "tool": "tool_name", "reason": "why this helps"}}]\n\n'
                f"Available tools: nmap_port_scan, nmap_service_scan, nmap_vuln_scan, "
                f"nikto_web_scan, gobuster, sqlmap_scan, hydra, searchsploit, ffuf, "
                f"enum4linux, passive_recon. "
                f"Only suggest tools that could actually help recover from this error."
            )

            t0 = time.time()
            response = llm_client.query(prompt, timeout=15)
            duration = time.time() - t0

            self.transparency.show_llm_thinking(
                prompt_summary=f"Recovery for {step.tool} failure",
                response=response[:400],
                duration=duration,
            )

            # Parse the JSON array response
            m = _re.search(r"```(?:json)?\s*(\[[^\]]*\])\s*```", response, _re.DOTALL)
            text = m.group(1) if m else response
            try:
                steps_list = json.loads(text)
                if isinstance(steps_list, list):
                    # Show recovery suggestion to user
                    suggestion_text = "; ".join(
                        f"{s.get('action', '?')} ({s.get('reason', '')})"
                        for s in steps_list[:3]
                    )
                    self.transparency.show_llm_recovery(step.tool, error_msg[:200], suggestion_text)
                    return steps_list[:3]
            except json.JSONDecodeError:
                pass

            # Fallback: if response is plain text, show it anyway
            self.transparency.show_llm_recovery(step.tool, error_msg[:200], response[:300])

        except (OSError, ValueError, RuntimeError, AttributeError) as e:
            logger.debug("LLM recovery attempt failed: %s", e)

        return []

    def _handle_step_failure(
        self,
        step: PlanStep,
        execution_result: dict[str, Any],
    ) -> bool:
        """Handle failed step execution with intelligent recovery.

        Recovery priority:
        1. Tool missing -> attempt install (with user visibility)
        2. LLM available -> ask LLM what to do, inject suggestions into plan
        3. Fallback -> pattern-match replan
        """
        stderr_msg = execution_result.get("stderr", _ERR_UNKNOWN)
        should_replan: bool = self.planner.mark_step_failed(step.step_id, stderr_msg[:200])
        self.console.print(f"\u274c Step failed: {stderr_msg[:200]}", style="red")

        error_type = self._categorize_error(stderr_msg[:100])

        # Priority 1: Tool missing \u2192 install
        if error_type == "tool_missing":
            self.console.print(
                f"\u26a0\ufe0f Tool '{step.tool}' missing, attempting install...",
                style=self.STYLE_YELLOW,
            )
            if self._attempt_tool_recovery(step.tool):
                self.planner.replan(step.step_id)
                return True
            self.console.print(f"\U0001f6d1 CRITICAL: Tool '{step.tool}' irreparably missing.", style=self.STYLE_RED)
            self.running = False
            return False

        # Priority 2: Ask LLM for smart recovery
        llm_recovery_steps = self._attempt_llm_recovery(step, stderr_msg)
        if llm_recovery_steps and self.state:
            n_injected = self.planner.inject_dynamic_steps(
                new_actions=llm_recovery_steps,
                target=self.state.target or "",
                source="llm_recovery",
            )
            if n_injected > 0:
                self.transparency.show_plan_injection(llm_recovery_steps[:n_injected], source="llm_recovery")
                self.console.print(
                    f"   \U0001f9e0 LLM suggested {n_injected} recovery step(s)",
                    style="bold yellow",
                )
                return True

        # Priority 3: Record failure + pattern-based replan
        if self.current_profile:
            self._record_failure_learning(step, error_type, stderr_msg)

        if should_replan:
            self._handle_replan(step, stderr_msg)

        return True

    def _record_failure_learning(self, step: PlanStep, error_type: str, error_msg: str) -> None:
        """Record failure detail to refining engine."""

        failure_id: str = self.refining_engine.record_failure(
            target_signature=self.target_signature,
            strategy_name=self.current_strategy.name
            if self.current_strategy
            else "unknown",
            profile_id=self.current_profile.profile_id,
            error_type=error_type,
            error_message=error_msg,
            tool_name=step.tool,
            context_data={"action": step.action, "params": step.params},
        )

        # Try to learn policy from this failure
        policy_id: str | None = self.refining_engine.learn_policy_from_failure(
            failure_id,
        )
        if policy_id:
            self.console.print(
                f"\U0001f4da Learned: avoid {step.tool} for {error_type} errors",
                style="dim",
            )

        # Update profile outcome (may trigger retirement)
        retired_profile = (
            self.refining_engine.update_profile_outcome(
                self.current_profile.profile_id,
                False,
            )
        )
        if retired_profile:
            strategy_name = self.current_strategy.name if self.current_strategy else "unknown"
            self.console.print(
                f"\u26a0\ufe0f  Strategy '{strategy_name}' underperforming \u2014 switching to alternative...",
                style="yellow",
            )
            # LOGIC FIX: Don't keep using a retired profile. Resync immediately.
            try:
                self.current_strategy, self.current_profile = (
                    self.refining_engine.select_strategy_and_profile(self.state.target)
                )
                self.planner.replan(
                    step.step_id,
                )  # Force items to be reconsidered under new profile
            except (KeyError, ValueError, TypeError, RuntimeError) as e:
                logger.exception("Failed to resync profile after retirement: %s", e)

    def _handle_replan(self, step: PlanStep, error_msg: str) -> None:
        """Handle replanning logic and AI tool creation backup."""
        from core.agent.planner import StepStatus

        self.console.print("\U0001f504 Triggering replan...", style="yellow")
        replan_success: bool = self.planner.replan(step.step_id)

        if not replan_success:
            self.console.print(
                "\U0001f4dd Replan failed - will select different profile next time",
                style="yellow",
            )

        # === SELF-CODING: If replan failed, try to create new tool ===
        if not replan_success and self.tools_created_this_session < 3:
            self.console.print(
                "\U0001f9e0 No alternative tool found. Attempting to CREATE one...",
                style=self.STYLE_MAGENTA,
            )

            create_result = self.coder.create_alternative_tool(
                failed_tool=step.tool,
                action=step.action,
                target=self.state.target,
                error_message=error_msg,
            )

            if create_result.get("success"):
                new_tool_name = create_result["tool_name"]
                self.console.print(
                    f"\u2728 Created new tool: {new_tool_name}",
                    style=self.STYLE_GREEN,
                )
                self.tools_created_this_session += 1

                # Register in tool_selector
                self.tool_selector.register_dynamic_tool(
                    name=new_tool_name,
                    phase=self.state.phase,
                    command_template=f"DYNAMIC:{new_tool_name}",
                )

                # Update step
                step.tool = new_tool_name
                step.status = StepStatus.PENDING
                step.retry_count = 0
            else:
                self.console.print(
                    f"\u26a0\ufe0f  Could not create tool: {create_result.get('error')}",
                    style="yellow",
                )
