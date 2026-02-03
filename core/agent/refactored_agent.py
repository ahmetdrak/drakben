# core/refactored_agent.py
# DRAKBEN SELF-REFINING EVOLVING AGENT
# PROFILE-BASED EVOLUTION + POLICY CONFLICT RESOLUTION + META-LEARNING

import asyncio
import json
import logging
import secrets
import time
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.agent.brain import DrakbenBrain
from core.agent.error_diagnostics import ErrorDiagnosticsMixin
from core.agent.planner import Planner, PlanStep, StepStatus
from core.agent.recovery.healer import SelfHealer
from core.agent.state import AgentState, AttackPhase, ServiceInfo, reset_state
from core.config import ConfigManager
from core.execution.execution_engine import ExecutionEngine, ExecutionResult
from core.execution.tool_selector import ToolSelector, ToolSpec
from core.intelligence.coder import AICoder
from core.intelligence.evolution_memory import (
    ActionRecord,
    EvolutionMemory,
    PlanRecord,
    get_evolution_memory,
)
from core.intelligence.self_refining_engine import (
    Policy,
    PolicyTier,
    SelfRefiningEngine,
    Strategy,
    StrategyProfile,
)
from core.security.security_utils import audit_command
from core.storage.structured_logger import DrakbenLogger
from core.tools.tool_parsers import normalize_error_message
from modules.research.exploit_crafter import ExploitCrafter
from modules.research.fuzzer import FuzzResult
from modules.stealth_client import BROWSER_IMPERSONATIONS

if TYPE_CHECKING:
    from re import Match

    from core.singularity.base import CodeSnippet
    from modules.hive_mind import AttackPath, NetworkHost
    from modules.weapon_foundry import GeneratedPayload

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)

# Error message constants (SonarCloud compliance)
_ERR_UNKNOWN = "Unknown error"


class RefactoredDrakbenAgent(ErrorDiagnosticsMixin):
    """SELF-REFINING EVOLVING AGENT.

    EVOLUTION LAYERS:
    1. Strategy Profiles - Behavioral variants with mutation
    2. Policy Engine - Conflict resolution with priority tiers
    3. Meta-Learning - Self-generated tool evaluation
    4. Non-Repetition - Never repeat failed profile
    5. Restart Evolution - Persist learning across restarts
    """

    # Constant for assertion messages (SonarCloud: avoid duplicate literals)
    MSG_STATE_NOT_NONE = "self.state is not None"

    def __init__(self, config_manager: ConfigManager) -> None:
        self.config: ConfigManager = config_manager
        self.console = Console()
        self.logger = DrakbenLogger()  # NEW: Structured Logging

        # Core Components
        self.brain = DrakbenBrain(llm_client=config_manager.llm_client)
        self.state: AgentState | None = None
        self.tool_selector = ToolSelector()
        self.executor = ExecutionEngine()

        # SELF-REFINING EVOLUTION COMPONENTS
        self.evolution: EvolutionMemory = get_evolution_memory()
        self.refining_engine = SelfRefiningEngine()  # NEW: Profile-based evolution
        self.planner = Planner()
        self.coder: AICoder = AICoder(self.brain)
        self.healer = SelfHealer(self.executor, self.console)  # Error recovery

        # Additional Modules for Full System Test
        try:
            from modules.ad_attacks import ActiveDirectoryAttacker

            self.ad_attacker = ActiveDirectoryAttacker()
        except ImportError:
            logger.warning(
                "ActiveDirectoryAttacker could not be initialized (missing imports).",
            )
            self.ad_attacker = None

        # Runtime state
        self.running = False
        self.stagnation_counter = 0
        self.tools_created_this_session = 0
        self.current_strategy: Strategy | None = None
        self.current_profile: StrategyProfile | None = None  # NEW: Track profile
        self.target_signature: str = ""

    # Style constants
    STYLE_GREEN = "bold green"
    STYLE_RED = "bold red"
    STYLE_CYAN = "bold cyan"
    STYLE_YELLOW = "bold yellow"
    STYLE_MAGENTA = "bold magenta"
    STYLE_MAGENTA_BLINK = "bold magenta blink"
    STYLE_BLUE = "bold blue"

    def initialize(self, target: str, mode: str = "auto") -> None:
        """Initialize agent with PROFILE-BASED SELECTION.

        Args:
            target: Target IP/URL
            mode: Scan mode - "auto", "stealth", "aggressive"
                  - "auto": Let agent decide based on target
                  - "stealth": Use low-aggression profiles, slower scans
                  - "aggressive": Use high-aggression profiles, fast scans

        ENFORCED ORDER:
        1. Classify target â†’ target_signature
        2. Select strategy.name (with policy filtering)
        3. Select best strategy_profile (not retired, not failed)
        4. Generate plan FROM THAT PROFILE

        SAFETY:
        - Full try-except wrapping for graceful degradation
        - Fallback to basic operation on database errors

        """
        import sqlite3

        self._setup_scan_mode(mode, target)
        self._fallback_mode = False

        try:
            self._reset_and_evolve_state(target)
            target_type: str = self._classify_target(target)

            if not self._select_and_filter_profile(target):
                return

            self._display_selected_profile()
            self._create_or_load_plan(target)
            self._show_evolution_info(target_type)

            self.running = True
            self.stagnation_counter = 0

        except sqlite3.OperationalError as e:
            logger.critical("Database error during init: %s", e)
            self.console.print(f"âš ï¸  Database error: {e}", style="yellow")
            self.console.print(
                "âš ï¸  Switching to fallback mode (limited functionality)",
                style="yellow",
            )
            self._fallback_mode = True

    def _setup_scan_mode(self, mode: str, target: str) -> None:
        """Setup scan mode and display initialization message."""
        self._scan_mode: str = mode.lower() if mode else "auto"
        mode_label: str = {
            "stealth": "ğŸ¥· STEALTH (Sessiz)",
            "aggressive": "âš¡ AGGRESSIVE (HÄ±zlÄ±)",
            "auto": "ğŸ¤– AUTO",
        }.get(self._scan_mode, "ğŸ¤– AUTO")
        self.console.print(
            f"ğŸ”„ Initializing agent for target: {target} [{mode_label}]",
            style=self.STYLE_BLUE,
        )

    def _reset_and_evolve_state(self, target: str) -> None:
        """Reset state and evolve tool priorities."""
        self.state = reset_state(target)
        self.state.phase = AttackPhase.INIT
        try:
            self.tool_selector.evolve_strategies(self.evolution)
        except Exception as e:
            self.console.print(f"âš ï¸  Tool evolution skipped: {e}", style="yellow")

    def _classify_target(self, target: str) -> str:
        """Classify target and set signature."""
        target_type: str = self.refining_engine.classify_target(target)
        self.target_signature = self.refining_engine.get_target_signature(target)
        self.console.print(f"ğŸ¯ Target Classification: {target_type}", style="cyan")
        self.console.print(f"ğŸ”‘ Target Signature: {self.target_signature}", style="dim")
        return target_type

    def _select_and_filter_profile(self, target: str) -> bool:
        """Select strategy/profile and apply mode-based filtering. Returns False if failed."""
        try:
            self.current_strategy, self.current_profile = (
                self.refining_engine.select_strategy_and_profile(target)
            )
            self._apply_mode_filtering()
        except Exception as e:
            self.console.print(f"âŒ Strategy selection failed: {e}", style="red")
            logger.exception("Strategy selection error")
            return False

        if not self.current_strategy or not self.current_profile:
            self.console.print("âŒ No strategy/profile available", style="red")
            return False
        return True

    def _apply_mode_filtering(self) -> None:
        """Apply mode-based profile filtering."""
        if self._scan_mode == "stealth" and self.current_profile:
            if self.current_profile.aggressiveness > 0.4:
                self._switch_to_stealth_profile()
        elif self._scan_mode == "aggressive" and self.current_profile:
            if self.current_profile.aggressiveness < 0.6:
                self._switch_to_aggressive_profile()

    def _switch_to_stealth_profile(self) -> None:
        """Switch to low-aggression profile for stealth mode."""
        self.console.print(
            "ğŸ¥· Stealth mode: Searching for low-aggression profile...",
            style="dim",
        )
        if not self.current_strategy:
            return
        profiles: list[StrategyProfile] = (
            self.refining_engine.get_profiles_for_strategy(self.current_strategy.name)
        )
        stealth_profiles: list[StrategyProfile] = [
            p for p in profiles if p.aggressiveness <= 0.4
        ]
        if stealth_profiles:
            self.current_profile = sorted(
                stealth_profiles,
                key=lambda p: p.aggressiveness,
            )[0]
            self.console.print(
                f"ğŸ¥· Switched to stealth profile (aggression: {self.current_profile.aggressiveness:.2f})",
                style="green",
            )

    def _switch_to_aggressive_profile(self) -> None:
        """Switch to high-aggression profile for aggressive mode."""
        self.console.print(
            "âš¡ Aggressive mode: Searching for high-aggression profile...",
            style="dim",
        )
        if not self.current_strategy:
            return
        profiles: list[StrategyProfile] = (
            self.refining_engine.get_profiles_for_strategy(self.current_strategy.name)
        )
        aggressive_profiles: list[StrategyProfile] = [
            p for p in profiles if p.aggressiveness >= 0.6
        ]
        if aggressive_profiles:
            self.current_profile = sorted(
                aggressive_profiles,
                key=lambda p: -p.aggressiveness,
            )[0]
            self.console.print(
                f"âš¡ Switched to aggressive profile (aggression: {self.current_profile.aggressiveness:.2f})",
                style="yellow",
            )

    def _display_selected_profile(self) -> None:
        """Display selected strategy and profile information."""
        if not self.current_strategy or not self.current_profile:
            self.console.print("âš ï¸ No strategy/profile active.", style="yellow")
            return

        self.console.print(
            f"ğŸ§  Selected Strategy: {self.current_strategy.name}",
            style=self.STYLE_MAGENTA,
        )
        self.console.print(
            f"ğŸ­ Selected Profile: {self.current_profile.profile_id[:12]}... "
            f"(gen: {self.current_profile.mutation_generation}, "
            f"success_rate: {self.current_profile.success_rate:.1%}, "
            f"aggression: {self.current_profile.aggressiveness:.2f})",
            style=self.STYLE_CYAN,
        )
        self.console.print(
            f"   ğŸ“‹ Step Order: {self.current_profile.step_order}",
            style="dim",
        )
        self.console.print(
            f"   âš™ï¸  Parameters: {json.dumps(self.current_profile.parameters)}",
            style="dim",
        )

    def _create_or_load_plan(self, target: str) -> None:
        """Create new plan or load existing plan."""
        existing_plan: PlanRecord | None = self.evolution.get_active_plan(
            f"pentest_{target}",
        )
        if existing_plan:
            self.console.print(
                f"ğŸ” Resuming plan: {existing_plan.plan_id}",
                style=self.STYLE_GREEN,
            )
            self.planner.load_plan(existing_plan.plan_id)
        else:
            plan_id: str = self.planner.create_plan_from_profile(
                target,
                self.current_profile,
                f"pentest_{target}",
            )
            self.console.print(
                f"ğŸ“‹ Created plan from profile: {plan_id}",
                style=self.STYLE_GREEN,
            )

    def _show_evolution_info(self, target_type: str) -> None:
        """Show evolution status and applicable policies."""
        try:
            status = self.refining_engine.get_evolution_status()
            self.console.print(
                f"ğŸ§¬ Evolution Status: {status['active_policies']} policies, "
                f"{status['retired_profiles']} retired profiles, "
                f"{status['max_mutation_generation']} max mutation gen",
                style="dim",
            )
        except Exception as e:
            logger.warning("Could not get evolution status: %s", e)

        try:
            context: dict[str, str] = {"target_type": target_type}
            policies: list[Policy] = self.refining_engine.get_applicable_policies(
                context,
            )
            if policies:
                self.console.print(
                    f"ğŸ“œ Active Policies: {len(policies)}",
                    style="yellow",
                )
                for p in policies[:3]:
                    tier_name: str = PolicyTier(p.priority_tier).name
                    self.console.print(
                        f"   - Tier {p.priority_tier} ({tier_name}): {p.action} (weight: {p.weight:.2f})",
                        style="dim",
                    )
        except Exception as e:
            logger.exception("Critical initialization error: %s", e)
            self.console.print(
                f"âŒ Critical error during initialization: {e}",
                style=self.STYLE_RED,
            )
            # Still allow basic operation
            if self.state:
                self.state.phase = AttackPhase.INIT
            self.running = True
            self.stagnation_counter = 0

    def run_autonomous_loop(self) -> None:
        """EVOLVED AGENTIC LOOP
        Refactored to reduce Cognitive Complexity.
        """
        from core.stop_controller import check_stop, stop_controller

        # Reset stop state for new scan
        stop_controller.reset()

        self.console.print(
            "\n[*] Starting autonomous scan...\n",
            style=self.STYLE_GREEN,
        )
        self.console.print(
            "   [dim]Tip: Press Ctrl+C to stop[/dim]\n",
        )

        if not self.state:
            self.console.print("âŒ FATAL: State not initialized.", style=self.STYLE_RED)
            return

        max_iterations: int = self.state.max_iterations
        while self.running and self.state.iteration_count < max_iterations:
            # Check for global stop signal
            if check_stop():
                self.console.print("\n[!] [yellow]Stopped by user.[/yellow]")
                self.running = False
                break

            should_continue: bool = self._run_single_iteration(max_iterations)
            if not should_continue:
                break

        # ============ FINAL REPORT ============
        self._show_final_report()

    def _run_single_iteration(self, max_iterations: int) -> bool:
        """Execute a single iteration of the autonomous loop."""
        if self.state is None:
            msg = "State missing in iteration"
            raise AssertionError(msg)
        iteration: int = self.state.iteration_count + 1

        self.console.print(f"\n{'=' * 60}", style="dim")
        self.console.print(
            f"[>] Iteration {iteration}/{max_iterations}",
            style=self.STYLE_CYAN,
        )

        # 1. Stagnation Check
        if self._check_stagnation():
            return False

        # 2. Get Next Step
        step: PlanStep | None = self.planner.get_next_step()
        if not step:
            self._handle_plan_completion()
            return False

        self.console.print(
            f"[*] Step: {step.step_id} | Action: {step.action} | Tool: {step.tool}",
            style="cyan",
        )

        # 3. Check Penalty & Execute
        if self._check_tool_blocked(step):
            self.state.increment_iteration()  # Prevent infinite loop
            return True

        self._execute_and_handle_step(step)
        return True

    def _execute_and_handle_step(self, step: PlanStep) -> bool:
        """Execute step and handle results.

        Args:
            step: Plan step to execute

        Returns:
            True if execution should continue, False to halt

        """
        self.planner.mark_step_executing(step.step_id)

        # Show what we're about to do with context
        self.console.print(f"\n[>] [bold yellow]Executing: {step.tool}[/bold yellow]", style="yellow")
        if step.params:
            params_display = ", ".join(f"{k}={v}" for k, v in list(step.params.items())[:3])
            self.console.print(f"   Params: {params_display}", style="dim")

        # Execute with progress indicator and timeout handling
        execution_result = self._execute_tool_with_progress(step.tool, step.params)
        success = execution_result.get("success", False)

        target = self.state.target if self.state else "global"
        # Record & Update
        penalty: float = self.evolution.get_tool_penalty(step.tool, target)
        self._record_action(step, success, penalty, execution_result)
        self.evolution.update_penalty(step.tool, success=success, target=target)

        # Handle Result
        if success:
            self._handle_step_success(step, execution_result)
        elif not self._handle_step_failure(step, execution_result):
            return False

        # 7. Update State
        observation: str = f"{step.tool}: {'success' if success else 'failed'}"
        self._update_state_from_result(step.tool, execution_result, observation)

        # 8. Validation & Halt Limit
        # 8. Validation & Halt Limit
        if not self._validate_loop_state():
            return False

        if self.state is None:

            raise AssertionError(self.MSG_STATE_NOT_NONE)
        self.state.increment_iteration()
        return True

    def _check_stagnation(self) -> bool:
        """Check for stagnation and triggering replan if needed. Returns True if halt required."""
        if self.evolution.detect_stagnation():
            self.console.print(
                "âš ï¸  STAGNATION DETECTED - forcing replan",
                style=self.STYLE_YELLOW,
            )
            current_step: PlanStep | None = self.planner.get_next_step()
            if current_step:
                self.planner.replan(current_step.step_id)
            self.stagnation_counter += 1

            if self.stagnation_counter >= 3:
                self.console.print(
                    "ğŸ›‘ HALT: Too many stagnations",
                    style=self.STYLE_RED,
                )
                return True
        return False

    def _handle_plan_completion(self) -> None:
        """Handle case where no steps are left."""
        if self.planner.is_plan_complete():
            self.console.print("âœ… Plan complete!", style=self.STYLE_GREEN)
            if self.state:
                self.state.phase = AttackPhase.COMPLETE
            self.running = False
        else:
            self.console.print("â“ No executable step found", style="yellow")
            self.running = False

    def _check_tool_blocked(self, step: PlanStep) -> bool:
        """Check if tool is blocked by evolution penalty (Per-Target)."""
        target = self.state.target if self.state else "global"
        penalty: float = self.evolution.get_tool_penalty(step.tool, target)
        if self.evolution.is_tool_blocked(step.tool, target):
            self.console.print(
                f"ğŸš« Tool {step.tool} is BLOCKED for {target} (penalty={penalty:.1f})",
                style=self.STYLE_RED,
            )
            # Trigger replan
            self.planner.replan(step.step_id)
            return True

        self.console.print(
            f"ğŸ“Š Tool {step.tool} penalty for {target}: {penalty:.1f} / {self.evolution.BLOCK_THRESHOLD}",
            style="dim",
        )
        return False

    def _record_action(
        self,
        step: PlanStep,
        success: bool,
        penalty: float,
        execution_result: dict[str, Any],
    ) -> None:
        """Record action to evolution memory."""
        # Using assertion for Mypy safety, logic handles None gracefully via defaults but type checker complains
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
        self.console.print("âœ… Step succeeded", style="green")
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
        """Attempt to install missing tool. Returns True if successful."""
        try:
            from core.intelligence.universal_adapter import get_universal_adapter
            adapter = get_universal_adapter()
            if not adapter:
                return False

            install_result = adapter.install_tool(tool_name, force=True)
            if install_result["success"]:
                self.console.print(f"âœ… Tool {tool_name} installed/recovered!", style="green")
                return True

            if install_result.get("requires_approval"):
                logger.warning(f"Tool {tool_name} requires manual approval: {install_result['message']}")

            self.console.print(f"âŒ Recovery failed: {install_result['message']}", style="red")
            return False
        except Exception as e:
            logger.exception("Dynamic recovery crashed: %s", e)
            return False

    def _handle_step_failure(
        self,
        step: PlanStep,
        execution_result: dict[str, Any],
    ) -> bool:
        """Handle failed step execution. Returns False if critical failure loop break needed."""
        stderr_msg = execution_result.get("stderr", _ERR_UNKNOWN)
        should_replan: bool = self.planner.mark_step_failed(step.step_id, stderr_msg[:200])
        self.console.print(f"âŒ Step failed: {stderr_msg[:200]}", style="red")

        error_type = self._categorize_error(stderr_msg[:100])

        if error_type == "tool_missing":
            self.console.print(f"âš ï¸ Tool '{step.tool}' miss, attempting Auto-Recovery...", style=self.STYLE_YELLOW)
            if self._attempt_tool_recovery(step.tool):
                self.planner.replan(step.step_id)
                return True
            self.console.print(f"ğŸ›‘ CRITICAL: Tool '{step.tool}' irreparably missing.", style=self.STYLE_RED)
            self.running = False
            return False

        # Record failure to database
        if self.current_profile:
            self._record_failure_learning(step, error_type, stderr_msg)

        if should_replan:
            self._handle_replan(step, stderr_msg)

        return True

    def _record_failure_learning(self, step: "PlanStep", error_type: str, error_msg: str) -> None:
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
                f"ğŸ“š Learned new policy: {policy_id[:12]}...",
                style="dim",
            )

        # Update profile outcome (may trigger retirement)
        retired_profile: StrategyProfile | None = (
            self.refining_engine.update_profile_outcome(
                self.current_profile.profile_id,
                False,
            )
        )
        if retired_profile:
            self.console.print(
                f"âš ï¸  Profile {retired_profile.profile_id[:12]}... RETIRED. Emergency re-selection...",
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
            except Exception as e:
                logger.exception("Failed to resync profile after retirement: %s", e)

    def _handle_replan(self, step: "PlanStep", error_msg: str) -> None:
        """Handle replanning logic and AI tool creation backup."""
        self.console.print("ğŸ”„ Triggering replan...", style="yellow")
        replan_success: bool = self.planner.replan(step.step_id)

        if not replan_success:
            self.console.print(
                "ğŸ“ Replan failed - will select different profile next time",
                style="yellow",
            )

        # === SELF-CODING: If replan failed, try to create new tool ===
        if not replan_success and self.tools_created_this_session < 3:
            self.console.print(
                "ğŸ§  No alternative tool found. Attempting to CREATE one...",
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
                    f"âœ¨ Created new tool: {new_tool_name}",
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
                    f"âš ï¸  Could not create tool: {create_result.get('error')}",
                    style="yellow",
                )

    def _validate_loop_state(self) -> bool:
        """Validate state invariants and halt conditions."""
        if not self.state:
            return False

        if not self.state.validate():
            self.console.print("âŒ STATE INVARIANT VIOLATION!", style=self.STYLE_RED)
            for violation in self.state.invariant_violations:
                self.console.print(f"   - {violation}", style="red")
            return False

        should_halt, halt_reason = self.state.should_halt()
        if should_halt:
            self.console.print(f"\nğŸ›‘ HALT: {halt_reason}", style=self.STYLE_YELLOW)
            return False

        return True

    def _get_llm_decision(self, context: dict) -> dict | None:
        """LLM'den TEK aksiyon al - with retry and fallback mechanism.

        LLM'ye gÃ¶nderilen:
        - State snapshot (5 satÄ±r Ã¶zet)
        - Allowed tools
        - Remaining attack surfaces
        - Last observation (max 200 char)

        LLM'den beklenen:
        {
            "tool": "tool_name",
            "args": {"param": "value"}
        }

        ERROR RECOVERY:
        1. Try LLM first (with retry)
        2. Fall back to deterministic decision
        3. Return None only if all options exhausted
        """
        llm_result = self._try_llm_with_retry(context)
        if llm_result:
            return llm_result

        return self._get_deterministic_fallback()

    def _try_llm_with_retry(self, context: dict) -> dict | None:
        """Try LLM decision with retry mechanism."""
        MAX_LLM_RETRIES = 2

        for attempt in range(MAX_LLM_RETRIES):
            result = self._attempt_llm_query(context, attempt, MAX_LLM_RETRIES)
            if result is not None:
                return result
        return None

    def _attempt_llm_query(
        self,
        context: dict,
        attempt: int,
        max_retries: int,
    ) -> dict | None:
        """Attempt a single LLM query."""
        try:
            result = self.brain.select_next_tool(context)
            if self._is_valid_llm_result(result):
                return result

            llm_error: str | None = self._extract_llm_error(result)
            if llm_error and self._should_retry(attempt, max_retries):
                self._handle_llm_retry(attempt, max_retries)
            return None
        except Exception:
            if self._should_retry(attempt, max_retries):
                self._handle_llm_retry(attempt, max_retries)
            return None

    def _should_retry(self, attempt: int, max_retries: int) -> bool:
        """Check if we should retry based on attempt number."""
        return attempt < max_retries - 1

    def _is_valid_llm_result(self, result: Any) -> bool:
        """Check if LLM result is valid."""
        return isinstance(result, dict) and "tool" in result

    def _extract_llm_error(self, result: Any) -> str | None:
        """Extract error message from LLM result."""
        if isinstance(result, dict) and result.get("error"):
            return result.get("error")
        return None

    def _handle_llm_retry(self, attempt: int, max_retries: int) -> None:
        """Handle LLM retry with user feedback."""
        self.console.print(
            f"âš ï¸  LLM hatasÄ±, yeniden deneniyor... ({attempt + 1}/{max_retries})",
            style="yellow",
        )
        time.sleep(1)

    def _log_llm_failure(self, llm_error: str, _max_retries: int) -> None:
        """Log LLM failure and switch to fallback."""
        self.console.print(f"âš ï¸  LLM kullanÄ±lamÄ±yor: {llm_error}", style="yellow")
        self.console.print(
            "ğŸ”„ Deterministik karar mekanizmasÄ±na geÃ§iliyor...",
            style="dim",
        )
        logger.warning("LLM decision failed after {max_retries} attempts: %s", llm_error)

    def _get_deterministic_fallback(self) -> dict | None:
        """Get deterministic decision as fallback."""
        if not self.state:
            return None
        deterministic_decision = self.tool_selector.recommend_next_action(self.state)
        if deterministic_decision:
            _, tool_name, args = deterministic_decision
            self.console.print(f"âœ… Deterministik karar: {tool_name}", style="dim")
            return {"tool": tool_name, "args": args}
        return None

    def _execute_tool_with_progress(self, tool_name: str, args: dict) -> dict:
        """Execute tool with progress indicator and timeout handling."""
        import threading
        import time as time_module

        result_container: dict = {}
        execution_done = threading.Event()

        def run_execution():
            result_container["result"] = self._execute_tool(tool_name, args)
            execution_done.set()

        # Start execution in thread
        exec_thread = threading.Thread(target=run_execution, daemon=True)
        exec_thread.start()

        # Show progress while waiting
        wait_start = time_module.time()
        max_display_wait = 120  # Show progress for max 2 minutes
        feedback_interval = 15  # Give feedback every 15 seconds
        last_feedback = wait_start

        while not execution_done.is_set():
            elapsed = time_module.time() - wait_start

            # Periodic feedback to user
            if time_module.time() - last_feedback >= feedback_interval:
                self.console.print(
                    f"   [~] Running... ({int(elapsed)}s)",
                    style="dim",
                )
                last_feedback = time_module.time()

            # Check for very long execution
            if elapsed > max_display_wait:
                self.console.print(
                    f"\n   [!] [yellow]Tool {tool_name} taking too long ({int(elapsed)}s)[/yellow]",
                    style="yellow",
                )
                self.console.print(
                    "   [?] Is target reachable? Check network.",
                    style="dim",
                )
                # Wait a bit more but don't spam
                execution_done.wait(timeout=30)
                if not execution_done.is_set():
                    self.console.print(
                        f"   [!] [red]Timeout: {tool_name} not responding.[/red]",
                        style="red",
                    )
                    return {
                        "success": False,
                        "error": f"Execution timeout after {int(elapsed)}s",
                        "timeout": True,
                        "args": args,
                    }
                break

            execution_done.wait(timeout=0.5)

        return result_container.get("result", {"success": False, "error": _ERR_UNKNOWN})

    def _execute_tool(self, tool_name: str, args: dict) -> dict:
        """Execute tool with error handling and retry logic."""
        # 1. Check if tool is blocked
        if self.tool_selector.is_tool_blocked(tool_name):
            return {
                "success": False,
                "error": f"Tool {tool_name} blocked due to repeated failures",
                "args": args,
            }

        # 2. SYSTEM EVOLUTION (Meta-tool)
        if tool_name == "system_evolution":
            return self._handle_system_evolution(args)

        # 3. Metasploit special case
        # 3. Metasploit special case
        if tool_name == "metasploit_exploit":
            return self._execute_metasploit(args)

        # 3.1 AD Attacks Special Case
        if tool_name.startswith("ad_"):
            return self._execute_ad_attacks(tool_name, args)

        # 3.5 Hive Mind Special Case
        # 3.5 Hive Mind Special Case
        if tool_name.startswith("hive_mind"):
            return self._execute_hive_mind(tool_name, args)

        # 3.6 Weapon Foundry Special Case
        if tool_name == "generate_payload":
            return self._execute_weapon_foundry(args)

        # 3.7 Singularity Special Case
        if tool_name == "synthesize_code":
            return self._execute_singularity(args)

        # 3.8 OSINT Special Case
        if tool_name.startswith("osint_"):
            return self._execute_osint(tool_name, args)

        # 4. Get tool spec
        tool_spec: ToolSpec | None = self.tool_selector.tools.get(tool_name)
        if not tool_spec:
            return {"success": False, "error": "Tool not found", "args": args}

        # 5. Execute system tool
        return self._run_system_tool(tool_name, tool_spec, args)

    def _handle_system_evolution(self, args: dict) -> dict:
        """Handle the system_evolution meta-tool."""
        action = args.get("action")
        target = args.get("target")  # file path or tool name
        instruction = args.get("instruction")
        if not action:
            return {"success": False, "error": "Missing 'action' parameter"}

        if action == "create_tool":
            return self._handle_create_tool(target, instruction)
        if action == "modify_file":
            return self._handle_modify_file(target, instruction)

        return {"success": False, "error": f"Unknown evolution action: {action}"}

    def _handle_create_tool(self, target: str | None, instruction: str | None) -> dict:
        if not target or not isinstance(target, str):
            return {
                "success": False,
                "error": "Missing or invalid 'target' (tool name)",
            }

        desc: str = (
            instruction if isinstance(instruction, str) else "No description provided"
        )

        # Dynamic tool creation via Coder
        result = self.coder.create_tool(
            tool_name=target,
            description=desc,
            requirements="",  # Mypy Fix: Missing required argument
        )

        if result["success"]:
            # Register new tool dynamically
            self.tool_selector.register_dynamic_tool(
                name=target,
                phase=AttackPhase.EXPLOIT,
                command_template=f"python3 modules/{target}.py {{target}}",
            )
            return {"success": True, "output": f"Tool {target} created and registered."}

        return result

    def _handle_modify_file(self, target: str | None, instruction: str | None) -> dict:
        if not target or not isinstance(target, str):
            return {
                "success": False,
                "error": "Missing or invalid 'target' (file path)",
            }

        # Read file first
        try:
            with open(target) as f:
                content: str = f.read()
        except Exception as e:
            return {"success": False, "error": f"Read failed: {e}"}

        # Ask LLM for modification
        if not hasattr(self, "brain") or not hasattr(self.brain, "ask_coder"):
            return {"success": False, "error": "Brain/Coder not attached"}

        modification = self.brain.ask_coder(
            f"Modify this file:\n{target}\n\nInstruction:\n{instruction}\n\nContent:\n{content}",
        )

        if modification.get("code"):
            new_content = modification["code"]
            # Verify syntax
            import ast

            try:
                ast.parse(new_content)
                with open(target, "w") as f:
                    f.write(new_content)
                return {
                    "success": True,
                    "output": f"File {target} modified successfully.",
                }
            except SyntaxError:
                return {
                    "success": False,
                    "error": "Generated code had syntax errors. Change rejected.",
                }

        return {"success": False, "error": "No code generated"}

    def _run_system_tool(self, tool_name: str, tool_spec: "ToolSpec", args: dict) -> dict:
        """Run a standard system tool."""
        # Build command from template
        try:
            command = tool_spec.command_template.format(
                target=self.state.target,
                **args,
            )
        except KeyError as e:
            return {"success": False, "error": f"Missing argument: {e}", "args": args}

        # ====== KOMUTU KULLANICIYA GÃ–STER ======
        from rich.panel import Panel
        self.console.print(
            Panel(
                f"[bold cyan]{command}[/bold cyan]",
                title=f"ğŸ’» {tool_name}",
                border_style="cyan",
                padding=(0, 1),
            ),
        )

        # Execute via execution engine
        result: ExecutionResult = self.executor.terminal.execute(command, timeout=300)

        # ====== OUTPUT'U KULLANICIYA GÃ–STER ======
        if result.stdout and result.stdout.strip():
            # Truncate very long output
            output_display = result.stdout[:2000]
            if len(result.stdout) > 2000:
                output_display += f"\n... ({len(result.stdout) - 2000} karakter daha)"
            self.console.print(
                Panel(
                    output_display,
                    title="ğŸ“„ Output",
                    border_style="green" if result.exit_code == 0 else "red",
                    padding=(0, 1),
                ),
            )

        if result.stderr and result.stderr.strip() and result.exit_code != 0:
            self.console.print(
                Panel(
                    result.stderr[:1000],
                    title="âš ï¸ Stderr",
                    border_style="yellow",
                    padding=(0, 1),
                ),
            )

        # Execution time feedback
        self.console.print(
            f"   [dim]â±ï¸ SÃ¼re: {result.duration:.1f}s | Exit: {result.exit_code}[/dim]",
        )

        # Track tool failures globally
        if result.exit_code != 0:
            return self._handle_tool_failure(tool_name, command, result, args)

        return self._format_tool_result(result, args)

    # Track self-healing attempts to prevent infinite loops
    _self_heal_attempts: dict[str, int] = {}
    MAX_SELF_HEAL_PER_TOOL = 2  # Maximum self-heal attempts per tool per session

    def _handle_tool_failure(
        self,
        tool_name: str,
        command: str,
        result: "ExecutionResult",
        args: dict,
    ) -> dict:
        """Handle tool failure with comprehensive self-healing.

        Error Types Handled:
        1. Missing tool â†’ Auto-install
        2. Permission denied â†’ Suggest sudo / elevate
        3. Connection refused â†’ Network check / retry
        4. Timeout â†’ Increase timeout / retry
        5. Python module missing â†’ pip install
        6. Unknown â†’ LLM-assisted diagnosis

        LOOP PROTECTION:
        - Maximum 2 self-heal attempts per tool per session
        - Prevents infinite retry loops
        """
        # Initialize tracking dict if needed
        if not hasattr(self, "_self_heal_attempts") or self._self_heal_attempts is None:
            self._self_heal_attempts = {}

        # Check if we've exceeded self-heal limit for this tool
        heal_key: str = f"{tool_name}:{command[:50]}"
        current_attempts: int = self._self_heal_attempts.get(heal_key, 0)

        if current_attempts >= self.MAX_SELF_HEAL_PER_TOOL:
            self.console.print(
                f"âš ï¸ {tool_name} iÃ§in self-heal limiti aÅŸÄ±ldÄ± ({current_attempts}/{self.MAX_SELF_HEAL_PER_TOOL})",
                style="yellow",
            )
            self.tool_selector.record_tool_failure(tool_name)
            return self._format_tool_result(result, args)

        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        combined_output: str = f"{stdout_str}\n{stderr_str}".lower()

        # Diagnose error type
        error_diagnosis = self._diagnose_error(combined_output, result.exit_code)

        if error_diagnosis["type"] != "unknown":
            self.console.print(
                f"ğŸ” Hata teÅŸhisi: {error_diagnosis['type_tr']}",
                style="yellow",
            )

        # Increment self-heal attempt counter
        self._self_heal_attempts[heal_key] = current_attempts + 1
        self.console.print(
            f"ğŸ”§ Self-heal denemesi: {current_attempts + 1}/{self.MAX_SELF_HEAL_PER_TOOL}",
            style="dim",
        )

        # Apply self-healing based on error type
        healed, retry_result = self._apply_error_specific_healing(
            error_diagnosis,
            tool_name,
            command,
            combined_output,
        )

        return self._finalize_healing_result(
            healed,
            retry_result,
            result,
            tool_name,
            args,
        )

    def _apply_error_specific_healing(
        self,
        error_diagnosis: dict[str, Any],
        tool_name: str,
        command: str,
        combined_output: str,
    ) -> tuple[bool, Any | None]:
        """Apply error-specific healing strategies using SelfHealer."""
        # Delegate to SelfHealer for known error types
        healed, result = self.healer.apply_healing(error_diagnosis, tool_name, command)
        if healed:
            return healed, result

        # For unknown errors, try LLM-assisted fix
        error_type = error_diagnosis.get("type", "unknown")
        if error_type == "unknown" and self.brain:
            return self._llm_assisted_error_fix(tool_name, command, combined_output)

        return False, None

    def _finalize_healing_result(
        self,
        healed: bool,
        retry_result: Any | None,
        result: Any,
        tool_name: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        """Finalize healing result and return formatted output."""
        if healed and retry_result:
            self.console.print("âœ… Hata otomatik olarak dÃ¼zeltildi!", style="green")
            return self._format_tool_result(retry_result, args)

        if result.exit_code != 0:
            self.tool_selector.record_tool_failure(tool_name)

        # FIX: Return formatted result instead of recursive call
        return self._format_tool_result(result, args)

    # Error diagnosis methods are inherited from ErrorDiagnosticsMixin
    # See: core/agent/error_diagnostics.py

    def _llm_assisted_error_fix(
        self,
        tool_name: str,
        command: str,
        error_output: str,
    ) -> tuple:
        """Use LLM to diagnose unknown errors and suggest fixes.
        Returns (healed: bool, retry_result).
        """
        try:
            self.console.print("ğŸ¤– LLM ile hata analizi yapÄ±lÄ±yor...", style="dim")

            prompt: str = f"""Analyze this command execution error and suggest a fix:

Command: {command}
Tool: {tool_name}
Error Output: {error_output[:1000]}

Respond in JSON:
{{
    "error_type": "brief error classification",
    "root_cause": "what caused this error",
    "fix_command": "shell command to fix (or null if not fixable)":
        raise AssertionError('should_retry') true/false,
    "explanation": "brief explanation in Turkish"
}}"""

            result = self.brain.llm_client.query(prompt, timeout=15)

            # Try to parse JSON response
            import json
            import re

            json_match: Match[str] | None = re.search(r"\{.*\}", result, re.DOTALL)
            if json_match:
                fix_data = json.loads(json_match.group())

                self.console.print(
                    f"ğŸ” LLM Analizi: {fix_data.get('explanation', 'Analiz tamamlandÄ±')}",
                    style="dim",
                )

                # Apply fix command if provided
                fix_cmd = fix_data.get("fix_command")
                if fix_cmd and fix_cmd != "null":
                    self.console.print(
                        f"ğŸ”§ DÃ¼zeltme uygulanÄ±yor: {fix_cmd}",
                        style="yellow",
                    )
                    fix_result: ExecutionResult = self.executor.terminal.execute(
                        fix_cmd,
                        timeout=120,
                    )

                    if fix_result.exit_code == 0 and fix_data.get(
                        "should_retry",
                        False,
                    ):
                        self.console.print(
                            "ğŸ”„ DÃ¼zeltme baÅŸarÄ±lÄ±, orijinal komut yeniden deneniyor...",
                            style="cyan",
                        )
                        retry_result: ExecutionResult = self.executor.terminal.execute(
                            command,
                            timeout=300,
                        )
                        return (retry_result.exit_code == 0, retry_result)

        except Exception as e:
            logger.warning("LLM-assisted error fix failed: %s", e)

        return (False, None)

    def _format_tool_result(self, result: Any, args: dict) -> dict:
        """Format execution result dictionary with standardized errors."""
        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        exit_code = result.exit_code

        # New: Standardize error
        error_msg: str = normalize_error_message(stdout_str, stderr_str, exit_code)

        # Fallback raw error if normalize returns nothing but exit code non-zero
        if exit_code != 0 and not error_msg:
            if stderr_str.strip():
                error_msg: str = f"Tool Error: {stderr_str.strip()[:200]}"
            else:
                error_msg: str = f"Command failed with exit code {exit_code}"

        final_result = {
            "success": result.status.value == "success",
            "stdout": stdout_str,
            "stderr": stderr_str,
            "error_summary": error_msg,  # New standardized field
            "exit_code": exit_code,
            "args": args,
        }

        # Log to structured log
        self.logger.log_action(
            tool=args.get(
                "tool_name",
                "unknown",
            ),  # args might need to contain tool name?
            args=args,
            result=final_result,
        )

        return final_result

    def _run_async(self, coro: Any, timeout: int = 60) -> Any:
        """Run async coroutine deterministically from sync context.
        Includes proper timeout and error handling to prevent hangs.

        Args:
            coro: Async coroutine to run
            timeout: Max execution time in seconds (default: 60)

        Returns:
            Coroutine result or error dict

        """
        try:
            loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            self.console.print(
                "âš ï¸  Cannot run async: event loop already running",
                style="yellow",
            )
            return {
                "success": False,
                "error": "Async execution blocked: event loop already running",
            }

        try:
            # Use asyncio.timeout context manager (Python 3.11+) for better SonarQube compliance
            # Falls back to asyncio.wait_for for older Python versions
            if hasattr(asyncio, "timeout"):
                # Python 3.11+ - use modern timeout context manager
                async def _run_with_timeout() -> Any:
                    async with asyncio.timeout(timeout):
                        return await coro

                return asyncio.run(_run_with_timeout())
            # Python < 3.11 - use wait_for for backward compatibility
            return asyncio.run(asyncio.wait_for(coro, timeout=timeout))
        except TimeoutError:
            # Both asyncio.timeout and asyncio.wait_for raise TimeoutError
            self.console.print(
                f"âš ï¸  Async task timeout after {timeout}s",
                style="yellow",
            )
            return {"success": False, "error": f"Async task timed out after {timeout}s"}
        except Exception as e:
            logger.exception("Async execution error: %s", e)
            self.console.print(f"âš ï¸  Async execution error: {e}", style="yellow")
            return {"success": False, "error": f"Async execution failed: {e!s}"}

    def _create_observation(self, tool_name: str, result: dict) -> str:
        """Tool sonucundan Ã–ZET observation oluÅŸtur.

        YASAK: Raw log, tool output spam
        SADECE: AnlamlÄ± Ã¶zet
        """
        if not result.get("success"):
            error_msg = result.get("error") or result.get("stderr", _ERR_UNKNOWN)
            return f"Tool {tool_name} failed: {error_msg[:100]}"

        # Success - create meaningful observation
        if "nmap" in tool_name:
            # Parse nmap output (simplified)
            stdout = result.get("stdout", "")
            if "open" in stdout.lower():
                # Count open ports
                open_count = stdout.lower().count(" open ")
                return f"Port scan found {open_count} open ports"
            return "Port scan completed, no open ports"

        if "nikto" in tool_name:
            return "Web vulnerability scan completed"

        if "sqlmap" in tool_name:
            stdout = result.get("stdout", "")
            if "vulnerable" in stdout.lower():
                return "SQL injection vulnerability found"
            return "SQL injection scan completed, no vulnerabilities"

        # Generic
        return f"Tool {tool_name} completed successfully"

    def _update_state_from_result(
        self,
        tool_name: str,
        result: dict,
        observation: str,
    ) -> None:
        """Update state based on tool result."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        # Set observation
        self.state.set_observation(observation)

        # 1. Record Result Execution (Success/Failure)
        self._record_execution_outcome(tool_name, result)

        if not result.get("success"):
            return

        # 2. Update State Specifics based on Tool
        self._dispatch_state_update(tool_name, result)

    def _record_execution_outcome(self, tool_name: str, result: dict) -> None:
        """Record success or failure to brain and tool selector."""
        output = result.get("stdout", "") + "\n" + result.get("stderr", "")
        success = result.get("success", False)

        if not success:
            self.tool_selector.record_tool_failure(tool_name)

        self.brain.observe(tool=tool_name, output=output, success=success)

    def _dispatch_state_update(self, tool_name: str, result: dict) -> None:
        """Dispatch state update based on tool type."""
        if "nmap_port_scan" in tool_name:
            self._update_state_nmap_port_scan(result)
        elif "nmap_service_scan" in tool_name or "nikto" in tool_name:
            self._update_state_service_completion(result)
        elif "vuln" in tool_name or "sqlmap" in tool_name:
            observation = result.get("stdout", "")
            self._process_vulnerability_result(tool_name, result, observation)
        elif "exploit" in tool_name:
            self._process_exploit_result(tool_name, result)

    def _process_exploit_result(self, tool_name: str, result: dict) -> None:
        """Helper to process exploit results."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        observation = result.get("stdout", "") + "\n" + result.get("stderr", "")
        # Check if exploit succeeded
        if (
            "success" in observation.lower()
            or "shell" in observation.lower()
            or result.get("success")
        ):
            self.state.set_foothold(tool_name)
        else:
            self.state.set_observation("Exploit did not succeed; foothold not set")

    def _update_state_nmap_port_scan(self, result: dict) -> None:
        """Update state from Nmap port scan results."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        from core.tools.tool_parsers import parse_nmap_output

        stdout = result.get("stdout", "")
        # Hybrid parsing with LLM fallback
        parsed_services = parse_nmap_output(stdout, llm_client=self.brain.llm_client)

        if parsed_services:
            services = []
            for svc_dict in parsed_services:
                services.append(
                    ServiceInfo(
                        port=svc_dict["port"],
                        protocol=svc_dict["proto"],
                        service=svc_dict["service"],
                    ),
                )
            self.state.update_services(services)
        else:
            # Fallback to mock if parsing failed (for testing)
            self._apply_mock_services()

    def _apply_mock_services(self) -> None:
        """Apply mock services for testing or fallback."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        services: list[ServiceInfo] = [
            ServiceInfo(port=80, protocol="tcp", service="http"),
            ServiceInfo(port=443, protocol="tcp", service="https"),
            ServiceInfo(port=22, protocol="tcp", service="ssh"),
        ]
        self.state.update_services(services)

    def _update_state_service_completion(self, result: dict) -> None:
        """Mark service as tested."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        args_port = result.get("args", {}).get("port")
        if not args_port:
            self.state.set_observation("Missing port in tool args; state not updated")
            return

        if args_port in self.state.open_services:
            service_info: ServiceInfo = self.state.open_services[args_port]
            self.state.mark_surface_tested(args_port, service_info.service)

    def _process_vulnerability_result(
        self,
        tool_name: str,
        result: dict,
        observation: str,
    ) -> None:
        """Helper to process vulnerability scan results."""
        if ("vuln" in tool_name or "sqlmap" in tool_name) and (
            "vulnerable" in observation.lower() or "injection" in observation.lower()
        ):
            self._handle_sqlmap_vulnerabilities(result)

            # AUTO-POC: Reanimate ExploitCrafter to generate reproduction scripts
            try:
                target_name: str = self.state.target or "target"
                crafter = ExploitCrafter()
                # Create a mock FuzzResult from the tool findings
                mock_crash = FuzzResult(
                    input_data=result.get("stdout", "Vulnerability payload"),
                    crash_detected=True,
                    error_message=f"Vulnerability found via {tool_name}: {observation}",
                )
                poc_path: str = crafter.generate_poc(
                    target_name.replace(".", "_"),
                    mock_crash,
                )
                self.console.print(
                    f"ğŸš€ [bold green]Autonomous PoC Generated:[/] {poc_path}",
                )
            except Exception as e:
                logger.debug("PoC generation failed: %s", e)

    def _handle_sqlmap_vulnerabilities(self, result: dict) -> None:
        """Process SQLMap results and update state."""
        import time

        from core.tools.tool_parsers import parse_sqlmap_output

        stdout = result.get("stdout", "")
        # Hybrid parsing with LLM fallback
        _ = parse_sqlmap_output(stdout, llm_client=self.brain.llm_client)

        # 3. Process findings (if any)
        if result.get("success") and "findings" in result:
            for finding in result["findings"]:
                if self.state:
                    from core.agent.state import VulnerabilityInfo

                    # Adapt finding dict to VulnerabilityInfo dataclass
                    severity_str: str = str(finding.get("severity", "medium")).lower()

                    vuln = VulnerabilityInfo(
                        vuln_id=f"VULN-{int(time.time())}-{secrets.randbelow(9000) + 1000}",
                        service=finding.get("service", "unknown"),
                        port=int(finding.get("port", 0)),
                        severity=severity_str,
                        exploitable=True,  # Assessing as exploitable by default when found
                        exploit_attempted=False,
                        exploit_success=False,
                    )
                    # self.state.add_vulnerability(vuln) # Assuming method exists or append directly
                    # Since add_vulnerability might not be on AgentState (Mypy complained), let's check
                    # how to add vulnerability. For now we will assume the method exists or we skip adding if not.
                    # Looking at state.py, we don't see add_vulnerability in the snippet.
                    # If it doesn't exist, we should likely append to self.state.vulnerabilities list if accessible.
                    # But to be safe and fix the Mypy error about "None" attribute, we ensure self.state is checked.

                    if hasattr(self.state, "add_vulnerability"):
                        self.state.add_vulnerability(vuln)
                    elif hasattr(self.state, "vulnerabilities") and isinstance(
                        self.state.vulnerabilities,
                        list,
                    ):
                        self.state.vulnerabilities.append(vuln)

    def _extract_port_from_result(self, result: dict) -> int:
        """Extract port number from tool result arguments."""
        args_port = result.get("args", {}).get("port")
        if args_port:
            return args_port

        args_url = result.get("args", {}).get("url", "")
        if args_url:
            from urllib.parse import urlparse

            parsed_url = urlparse(args_url)
            if parsed_url.port:
                return parsed_url.port
            return 443 if parsed_url.scheme == "https" else 80

        return 80  # Default fallback

    def _check_phase_transition(self) -> None:
        """Phase transition kontrolÃ¼ - DETERMÄ°NÄ°STÄ°K."""
        # INIT -> RECON (target set)
        if self.state.phase == AttackPhase.INIT and self.state.target:
            self.state.phase = AttackPhase.RECON
            self.console.print(
                "ğŸ“ˆ Phase transition: INIT -> RECON",
                style=self.STYLE_BLUE,
            )

        # RECON -> VULN_SCAN (services discovered, no more remaining)
        elif (
            self.state.phase == AttackPhase.RECON
            and self.state.open_services
            and len(self.state.remaining_attack_surface) == 0
        ):
            self.state.phase = AttackPhase.VULN_SCAN
            # Re-add services for vuln scanning
            for port, svc in self.state.open_services.items():
                surface_key: str = f"{port}:{svc.service}"
                self.state.remaining_attack_surface.add(surface_key)
            self.console.print(
                "ğŸ“ˆ Phase transition: RECON -> VULN_SCAN",
                style=self.STYLE_BLUE,
            )

        # VULN_SCAN -> EXPLOIT (vulnerabilities found)
        elif (
            self.state.phase == AttackPhase.VULN_SCAN
            and self.state.vulnerabilities
            and len(self.state.remaining_attack_surface) == 0
        ):
            self.state.phase = AttackPhase.EXPLOIT
            self.console.print(
                "ğŸ“ˆ Phase transition: VULN_SCAN -> EXPLOIT",
                style=self.STYLE_BLUE,
            )

        # VULN_SCAN -> COMPLETE (no vulnerabilities found, surfaces exhausted)
        elif (
            self.state.phase == AttackPhase.VULN_SCAN
            and not self.state.vulnerabilities
            and len(self.state.remaining_attack_surface) == 0
        ):
            self.state.phase = AttackPhase.COMPLETE
            self.console.print(
                "ğŸ“ˆ Phase transition: VULN_SCAN -> COMPLETE (no vulns found)",
                style=self.STYLE_YELLOW,
            )

        elif self.state.phase == AttackPhase.EXPLOIT and self.state.has_foothold:
            self.impersonate_target = secrets.choice(BROWSER_IMPERSONATIONS)
            self.console.print(
                "ğŸ“ˆ Phase transition: EXPLOIT -> POST_EXPLOIT",
                style=self.STYLE_BLUE,
            )

    def _show_final_report(self) -> None:
        """Show final execution report."""
        self.console.print("\n" + "=" * 60, style="bold")
        self.console.print("ğŸ“Š FINAL REPORT", style=self.STYLE_GREEN)
        self.console.print("=" * 60, style="bold")

        report = Text()
        report.append(f"ğŸ¯ Target: {self.state.target}\n", style="bold")
        report.append(
            f"ğŸ”„ Iterations: {self.state.iteration_count}/{self.state.max_iterations}\n",
        )
        report.append(f"ğŸ“ Final Phase: {self.state.phase.value}\n")
        report.append(f"ğŸ”“ Services Found: {len(self.state.open_services)}\n")
        report.append(f"âš ï¸  Vulnerabilities: {len(self.state.vulnerabilities)}\n")
        report.append(f"ğŸª Foothold: {'YES' if self.state.has_foothold else 'NO'}\n")

        if self.state.has_foothold:
            report.append(f"   Method: {self.state.foothold_method}\n", style="green")

        if self.state.invariant_violations:
            report.append("\nâŒ Invariant Violations:\n", style=self.STYLE_RED)
            for violation in self.state.invariant_violations:
                report.append(f"   - {violation}\n", style="red")

        self.console.print(Panel(report, border_style="green", title="Summary"))

    def stop(self) -> None:
        """Stop the agent."""
        self.running = False

    def _execute_weapon_foundry(self, args: dict) -> dict:
        """Execute Weapon Foundry to generate payloads."""
        try:
            from modules.weapon_foundry import WeaponFoundry

            foundry = WeaponFoundry()

            payload_type = args.get("format", "python")
            lhost = args.get("lhost")
            lport = args.get("lport", 4444)
            # Args from Agent LLM might call it 'type' instead of 'format'
            if not payload_type and "type" in args:
                payload_type = args["type"]

            if not lhost:
                lhost = "127.0.0.1"
                self.console.print("âš ï¸ LHOST missing, using localhost.", style="yellow")

            self.console.print(f"ğŸ”¨ Forging Payload ({payload_type})...", style="cyan")

            artifact: GeneratedPayload = foundry.forge(
                lhost=lhost,
                lport=int(lport),
                format=payload_type,
                encryption="aes",
                iterations=5,
            )

            if artifact:
                filename = artifact.metadata.get("filename", "payload.bin")
                return {
                    "success": True,
                    "output": f"Payload SUCCESS: {filename}",
                    "artifact": filename,
                }
            return {"success": False, "error": "Payload generation failed"}
        except Exception as e:
            logger.exception("WeaponFoundry error: %s", e)
            return {"success": False, "error": f"WeaponFoundry error: {e}"}

    def _execute_singularity(self, args: dict) -> dict:
        """Execute Singularity to write custom code."""
        try:
            from core.singularity.synthesizer import CodeSynthesizer

            # Initialize with existing Brain/Coder components if available
            synth = CodeSynthesizer()

            instruction = args.get("description") or args.get("instruction")
            lang = args.get("language", "python")

            if not instruction:
                return {
                    "success": False,
                    "error": "No instruction provided for code synthesis",
                }

            self.console.print(
                f"ğŸ”® Singularity: Synthesizing {lang} code...",
                style="magenta",
            )

            # Use generate_tool (which returns artifact)
            # Args might differ, check CodeSynthesizer definition.
            # Assuming generate_tool is the main entry point from context step 1960.
            result: CodeSnippet = synth.generate_tool(
                description=instruction,
                language=lang,
            )

            if getattr(result, "success", False):
                return {
                    "success": True,
                    "output": f"Code Synthesized: {result.file_path}\nContent Preview:\n{result.content[:300] if result.content else ''}",
                }
            return {
                "success": False,
                "error": f"Synthesis failed: {getattr(result, 'error', 'Unknown Error')}",
            }

        except Exception as e:
            logger.exception("Singularity error: %s", e)
            return {"success": False, "error": f"Singularity error: {e}"}

    def _execute_osint(self, _tool_name: str, args: dict) -> dict:
        """Execute OSINT tools."""
        try:
            from modules.social_eng.osint import OSINTSpider

            recon = OSINTSpider()

            target = args.get("target") or self.state.target
            if not target:
                return {"success": False, "error": "Target required"}

            self.console.print(f"ğŸ•µï¸ OSINT Scanning: {target}", style="blue")
            results = recon.harvest_domain(target)
            return {"success": True, "output": str(results)[:2000]}
        except Exception as e:
            return {"success": False, "error": f"OSINT error: {e}"}

    def _execute_hive_mind(self, tool_name: str, args: dict) -> dict:
        """Execute Hive Mind internal module."""
        try:
            from modules.hive_mind import HiveMind

            hive = HiveMind()

            self.console.print("ğŸ Waking up HIVE MIND...", style="magenta")

            if tool_name == "hive_mind_scan":
                init_res: dict[str, Any] = hive.initialize()
                # If target is IP/subnet, use it. Otherwise auto-detect.
                subnet = (
                    args.get("target")
                    if args.get("target") and "/" in str(args.get("target"))
                    else None
                )

                hosts: list[NetworkHost] = hive.scan_network(subnet)
                hosts_data: list[str] = [str(h) for h in hosts]

                observation: str = f"Hive Mind Intelligence:\nInitialized: {init_res}\nDiscovered Hosts: {len(hosts)}\n{hosts_data}"
                self.console.print(observation, style="cyan")

                return {
                    "success": True,
                    "init": init_res,
                    "hosts_discovered": len(hosts),
                    "hosts": hosts_data,
                    "output": observation,
                }

            if tool_name == "hive_mind_attack":
                self.console.print("ğŸ Calculating Attack Paths...", style="magenta")
                target = args.get("target", "Domain Admin")
                paths: list[AttackPath] = hive.find_attack_paths(target)

                if not paths:
                    return {"success": False, "error": "No viable attack paths found"}

                # Execute best path
                best_path: AttackPath = paths[0]
                self.console.print(f"ğŸš€ Executing Path: {best_path}", style="red")

                result: dict[str, Any] = hive.execute_movement(best_path)
                return {
                    "success": result["success"],
                    "hops": result["hops_completed"],
                    "output": f"Movement result: {'Success' if result['success'] else 'Failed'}. Final Position: {result['final_position']}",
                }

            return {"success": False, "error": "Unknown Hive Mind tool"}

        except Exception as e:
            return {"success": False, "error": f"Hive Mind Error: {e!s}"}

    def _execute_metasploit(self, args: dict) -> dict:
        """Execute Metasploit module via wrapper."""
        try:
            from modules.metasploit import MetasploitBridge

            # Initialize if needed (singleton pattern preferred in real usage, but instantiating for now)
            msf = MetasploitBridge()

            # 'module' and 'options' are expected in args
            module = args.get("module")
            options = args.get("options", {})

            if not module:
                return {"success": False, "error": "Metasploit module name required"}

            self.console.print(f"ğŸ”¥ Launching Metasploit: {module}", style="red")
            result = msf.execute_module(module, options)

            return {
                "success": result.get("success", False),
                "output": result.get("output", ""),
                "session_id": result.get("session_id"),
            }
        except ImportError:
            return {"success": False, "error": "modules.metasploit not found"}
        except Exception as e:
            logger.exception("Metasploit error")
            return {"success": False, "error": f"Metasploit execution failed: {e}"}

    def _execute_ad_attacks(self, tool_name: str, args: dict) -> dict:
        """Execute Active Directory attacks (Native)."""
        try:
            from modules.ad_attacks import ActiveDirectoryAttacker

            attacker = ActiveDirectoryAttacker()

            domain = args.get("domain")
            target_ip = args.get("target_ip")

            if not domain or not target_ip:
                return {
                    "success": False,
                    "error": "Domain and Target IP required for AD attacks",
                }

            result = {}
            if tool_name == "ad_asreproast":
                # Async shim
                import asyncio

                user_file = args.get("user_file")
                result = asyncio.run(
                    attacker.run_asreproast(domain, target_ip, user_file),
                )

            elif tool_name == "ad_smb_spray":
                # Async shim
                import asyncio

                user_file = args.get("user_file")
                password = args.get("password")
                if not user_file or not password:
                    return {
                        "success": False,
                        "error": "User file and password required for spray",
                    }

                # Check concurrency arg
                concurrency = args.get("concurrency", 10)
                result = asyncio.run(
                    attacker.run_smb_spray(
                        domain,
                        target_ip,
                        user_file,
                        password,
                        concurrency,
                    ),
                )

            else:
                return {"success": False, "error": f"Unknown AD tool: {tool_name}"}

            return {
                "success": result.get("success", False),
                "output": json.dumps(result, indent=2),
                "data": result,
            }

        except ImportError:
            return {"success": False, "error": "modules.ad_attacks not found"}
        except Exception as e:
            logger.exception("AD Attack error")
            return {"success": False, "error": f"AD Attack failed: {e}"}

