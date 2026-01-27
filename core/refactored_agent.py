# core/refactored_agent.py
# DRAKBEN SELF-REFINING EVOLVING AGENT
# PROFILE-BASED EVOLUTION + POLICY CONFLICT RESOLUTION + META-LEARNING

from core.self_healer import SelfHealer  # NEW: Imported SelfHealer
from modules.ad_attacks import ActiveDirectoryAttacker  # NEW: AD Module Import
from modules import payload as payload_module
from modules import exploit as exploit_module
from core.structured_logger import DrakbenLogger
from core.tool_parsers import normalize_error_message
from core.tool_selector import ToolSelector
from core.self_refining_engine import (
    SelfRefiningEngine,
    Strategy,
    StrategyProfile,
    PolicyTier
)
from modules.report_generator import FindingSeverity
from core.state import (
    AgentState,
    AttackPhase,
    reset_state,
    ServiceInfo,
    VulnerabilityInfo)
from core.planner import Planner, PlanStep, StepStatus
from core.execution_engine import ExecutionEngine
from core.evolution_memory import ActionRecord, get_evolution_memory
from core.config import ConfigManager
from core.coder import AICoder
from core.brain import DrakbenBrain
from rich.text import Text
from rich.panel import Panel
from rich.console import Console
import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Any, Callable

# Setup logger
logger = logging.getLogger(__name__)


class RefactoredDrakbenAgent:
    """
    SELF-REFINING EVOLVING AGENT

    EVOLUTION LAYERS:
    1. Strategy Profiles - Behavioral variants with mutation
    2. Policy Engine - Conflict resolution with priority tiers
    3. Meta-Learning - Self-generated tool evaluation
    4. Non-Repetition - Never repeat failed profile
    5. Restart Evolution - Persist learning across restarts
    """

    def __init__(
            self,
            config_manager: ConfigManager,
            brain=None,
            planner=None,
            execution_engine=None):
        self.config = config_manager
        self.console = Console()
        self.logger = DrakbenLogger()  # NEW: Structured Logging

        # Core Components - DI Support
        self.brain = brain if brain else DrakbenBrain(
            llm_client=config_manager.llm_client)
        self.state: Optional[AgentState] = None
        self.tool_selector = ToolSelector()
        self.executor = execution_engine if execution_engine else ExecutionEngine()

        # SELF-REFINING EVOLUTION COMPONENTS
        self.evolution = get_evolution_memory()
        self.refining_engine = SelfRefiningEngine()  # NEW: Profile-based evolution
        self.planner = planner if planner else Planner()
        self.coder = AICoder(self.brain)
        self.healer = SelfHealer(self)
        self.ad_attacker = ActiveDirectoryAttacker(
            executor_callback=lambda cmd, timeout: self.executor.terminal.execute(
                cmd, timeout=timeout))  # NEW: AD Module Init  # NEW: Initialize SelfHealer

        # Runtime state
        self.running = False
        self.stagnation_counter = 0
        self.tools_created_this_session = 0
        self.current_strategy: Optional[Strategy] = None
        # NEW: Track profile
        self.current_profile: Optional[StrategyProfile] = None
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
        """
        Initialize agent with PROFILE-BASED SELECTION

        Args:
            target: Target IP/URL
            mode: Scan mode - "auto", "stealth", "aggressive"
                  - "auto": Let agent decide based on target
                  - "stealth": Use low-aggression profiles, slower scans
                  - "aggressive": Use high-aggression profiles, fast scans

        ENFORCED ORDER:
        1. Classify target → target_signature
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
            target_type = self._classify_target(target)

            # Try to select profile, but don't stop if it fails - use default
            # plan
            if not self._select_and_filter_profile(target):
                self.console.print(
                    "⚠️  No strategy profile selected - switching to DEFAULT plan",
                    style="yellow")
            else:
                self._display_selected_profile()

            self._create_or_load_plan(target)
            self._show_evolution_info(target_type)

            self.running = True
            self.stagnation_counter = 0

        except sqlite3.OperationalError as e:
            logger.critical(f"Database error during init: {e}")
            self.console.print(f"⚠️  Database error: {e}", style="yellow")
            self.console.print(
                "⚠️  Switching to fallback mode (limited functionality)",
                style="yellow")
            self._fallback_mode = True

    def _setup_scan_mode(self, mode: str, target: str) -> None:
        """Setup scan mode and display initialization message"""
        self._scan_mode = mode.lower() if mode else "auto"
        mode_label = {
            "stealth": "🥷 STEALTH (Sessiz)",
            "aggressive": "⚡ AGGRESSIVE (Hızlı)",
            "auto": "🤖 AUTO"
        }.get(self._scan_mode, "🤖 AUTO")
        self.console.print(
            f"🔄 Initializing agent for target: {target} [{mode_label}]",
            style=self.STYLE_BLUE
        )

    def _reset_and_evolve_state(self, target: str) -> None:
        """Reset state and evolve tool priorities"""
        self.state = reset_state(target)
        self.state.phase = AttackPhase.INIT
        try:
            self.tool_selector.evolve_strategies(self.evolution)
        except Exception as e:
            self.console.print(
                f"⚠️  Tool evolution skipped: {e}",
                style="yellow")

    def _classify_target(self, target: str) -> str:
        """Classify target and set signature"""
        target_type = self.refining_engine.classify_target(target)
        self.target_signature = self.refining_engine.get_target_signature(
            target)
        self.console.print(
            f"🎯 Target Classification: {target_type}",
            style="cyan")
        self.console.print(
            f"🔑 Target Signature: {
                self.target_signature}",
            style="dim")
        return target_type

    def _select_and_filter_profile(self, target: str) -> bool:
        """Select strategy/profile and apply mode-based filtering. Returns False if failed."""
        try:
            self.current_strategy, self.current_profile = self.refining_engine.select_strategy_and_profile(
                target)
            self._apply_mode_filtering()
        except Exception as e:
            self.console.print(
                f"❌ Strategy selection failed: {e}",
                style="red")
            logger.exception("Strategy selection error")
            return False

        if not self.current_strategy or not self.current_profile:
            self.console.print("❌ No strategy/profile available", style="red")
            return False
        return True

    def _apply_mode_filtering(self) -> None:
        """Apply mode-based profile filtering"""
        if self._scan_mode == "stealth" and self.current_profile:
            if self.current_profile.aggressiveness > 0.4:
                self._switch_to_stealth_profile()
        elif self._scan_mode == "aggressive" and self.current_profile:
            if self.current_profile.aggressiveness < 0.6:
                self._switch_to_aggressive_profile()

    def _switch_to_stealth_profile(self) -> None:
        """Switch to low-aggression profile for stealth mode"""
        self.console.print(
            "🥷 Stealth mode: Searching for low-aggression profile...",
            style="dim")
        profiles = self.refining_engine.get_profiles_for_strategy(
            self.current_strategy.name)
        stealth_profiles = [p for p in profiles if p.aggressiveness <= 0.4]
        if stealth_profiles:
            self.current_profile = sorted(
                stealth_profiles, key=lambda p: p.aggressiveness)[0]
            self.console.print(
                f"🥷 Switched to stealth profile (aggression: {
                    self.current_profile.aggressiveness:.2f})",
                style="green")

    def _switch_to_aggressive_profile(self) -> None:
        """Switch to high-aggression profile for aggressive mode"""
        self.console.print(
            "⚡ Aggressive mode: Searching for high-aggression profile...",
            style="dim")
        # Global aggressive config override (optional)
        # self.config.set("scan_delay", 0) 
        
        profiles = self.refining_engine.get_profiles_for_strategy(
            self.current_strategy.name)
        aggressive_profiles = [p for p in profiles if p.aggressiveness >= 0.6]
        if aggressive_profiles:
            self.current_profile = sorted(
                aggressive_profiles,
                key=lambda p: -p.aggressiveness)[0]
            self.console.print(
                f"⚡ Switched to aggressive profile (aggression: {
                    self.current_profile.aggressiveness:.2f})",
                style="yellow")

    def _display_selected_profile(self) -> None:
        """Display selected strategy and profile information"""
        self.console.print(
            f"🧠 Selected Strategy: {
                self.current_strategy.name}",
            style=self.STYLE_MAGENTA)
        self.console.print(
            f"🎭 Selected Profile: {self.current_profile.profile_id[:12]}... "
            f"(gen: {self.current_profile.mutation_generation}, "
            f"success_rate: {self.current_profile.success_rate:.1%}, "
            f"aggression: {self.current_profile.aggressiveness:.2f})",
            style=self.STYLE_CYAN
        )
        self.console.print(
            f"   📋 Step Order: {
                self.current_profile.step_order}",
            style="dim")
        self.console.print(
            f"   ⚙️  Parameters: {
                json.dumps(
                    self.current_profile.parameters)}",
            style="dim")

    def _create_or_load_plan(self, target: str) -> None:
        """Create new plan or load existing plan"""
        existing_plan = self.evolution.get_active_plan(f"pentest_{target}")
        if existing_plan:
            self.console.print(
                f"🔁 Plan devam ettiriliyor: {
                    existing_plan.plan_id}",
                style=self.STYLE_GREEN)
            self.planner.load_plan(existing_plan.plan_id)
        else:
            if self.current_profile:
                plan_id = self.planner.create_plan_from_profile(
                    target, self.current_profile, f"pentest_{target}")
                self.console.print(
                    f"📋 Yeni plan oluşturuldu: {plan_id}",
                    style=self.STYLE_GREEN)
            else:
                # FALLBACK: Create default plan if no profile
                plan_id = self.planner.create_plan_for_target(
                    target, f"pentest_{target}")
                self.console.print(
                    f"📋 Standart plan oluşturuldu: {plan_id}",
                    style=self.STYLE_CYAN)

    def _show_evolution_info(self, target_type: str) -> None:
        """Show evolution status and applicable policies"""
        try:
            status = self.refining_engine.get_evolution_status()
            self.console.print(
                f"🧬 Evolution Status: {status['active_policies']} policies, "
                f"{status['retired_profiles']} retired profiles, "
                f"{status['max_mutation_generation']} max mutation gen",
                style="dim"
            )
        except Exception as e:
            logger.warning(f"Could not get evolution status: {e}")

        try:
            context = {"target_type": target_type}
            policies = self.refining_engine.get_applicable_policies(context)
            if policies:
                self.console.print(
                    f"📜 Active Policies: {
                        len(policies)}",
                    style="yellow")
                for p in policies[:3]:
                    tier_name = PolicyTier(p.priority_tier).name
                    self.console.print(
                        f"   - Tier {p.priority_tier} ({tier_name}): {p.action} (weight: {p.weight:.2f})",
                        style="dim"
                    )
        except Exception as e:
            logger.exception(f"Critical initialization error: {e}")
            self.console.print(
                f"❌ Critical error during initialization: {e}",
                style=self.STYLE_RED)
            # Still allow basic operation
            if self.state:
                self.state.phase = AttackPhase.INIT
            self.running = True
            self.stagnation_counter = 0

    def run_autonomous_loop(self) -> None:
        """
        EVOLVED AGENTIC LOOP
        Refactored to reduce Cognitive Complexity.
        """
        self.console.print(
            "\n🚀 Starting evolved autonomous loop...\n", style=self.STYLE_GREEN
        )

        if not self.state:
            self.console.print(
                "❌ Agent state not initialized. Run initialize() first.",
                style=self.STYLE_RED)
            return

        max_iterations = self.state.max_iterations
        while self.running and self.state.iteration_count < max_iterations:
            should_continue = self._run_single_iteration(max_iterations)
            if not should_continue:
                break

        # ============ FINAL REPORT ============
        self._show_final_report()

    def _run_single_iteration(self, max_iterations: int) -> bool:
        """Execute a single iteration of the autonomous loop"""
        iteration = self.state.iteration_count + 1

        self.console.print(f"\n{'=' * 60}", style="dim")
        self.console.print(
            f"⚡ Iteration {iteration}/{max_iterations}",
            style=self.STYLE_CYAN,
        )

        # 1. Stagnation Check
        if self._check_stagnation():
            return False

        # 2. Get Next Step
        step = self.planner.get_next_step()
        if not step:
            self._handle_plan_completion()
            return False

        self.console.print(
            f"📋 Plan Step: {
                step.step_id} | Action: {
                step.action} | Tool: {
                step.tool}",
            style="cyan")

        # 3. Check Penalty & Execute
        if self._check_tool_blocked(step):
            return True

        self._execute_and_handle_step(step)
        return True

    def _execute_and_handle_step(self, step: PlanStep) -> bool:
        """
        Execute step and handle results.

        Args:
            step: Plan step to execute

        Returns:
            True if execution should continue, False to halt
        """
        self.planner.mark_step_executing(step.step_id)
        self.console.print(f"🔧 Executing: {step.tool}...", style="yellow")

        # Merge context into args for tool execution
        tool_args = step.params.copy() if step.params else {}
        if step.target and "target" not in tool_args:
            tool_args["target"] = step.target
        if step.action and "action" not in tool_args:
            tool_args["action"] = step.action

        execution_result = self._execute_tool(step.tool, tool_args)
        success = execution_result.get("success", False)

        # Record & Update
        penalty = self.evolution.get_tool_penalty(step.tool)
        self._record_action(step, success, penalty, execution_result)
        self.evolution.update_penalty(step.tool, success=success)

        # Handle Result
        if success:
            self._handle_step_success(step, execution_result)
        else:
            if not self._handle_step_failure(step, execution_result):
                return False

        # 7. Update State
        observation = f"{step.tool}: {'success' if success else 'failed'}"
        self._update_state_from_result(
            step.tool, execution_result, observation)

        # 8. Validation & Halt Limit
        if not self._validate_loop_state():
            return False

        self.state.increment_iteration()
        return True

    def _check_stagnation(self) -> bool:
        """Check for stagnation and triggering replan if needed. Returns True if halt required."""
        if getattr(self, "_fallback_mode", False):
            return False

        if self.evolution.detect_stagnation():
            self.console.print(
                "⚠️  STAGNATION DETECTED - forcing replan",
                style=self.STYLE_YELLOW)
            current_step = self.planner.get_next_step()
            if current_step:
                self.planner.replan(current_step.step_id)
            self.stagnation_counter += 1

            if self.stagnation_counter >= 3:
                self.console.print(
                    "🛑 HALT: Too many stagnations",
                    style=self.STYLE_RED)
                return True
        return False

    def _handle_plan_completion(self) -> None:
        """Handle case where no steps are left."""
        if self.planner.is_plan_complete():
            self.console.print("✅ Plan complete!", style=self.STYLE_GREEN)
            self.state.phase = AttackPhase.COMPLETE
        else:
            self.console.print("❓ No executable step found", style="yellow")

    def _check_tool_blocked(self, step: PlanStep) -> bool:
        """Check if tool is blocked by evolution penalty."""
        if getattr(self, "_fallback_mode", False):
            return False

        penalty = self.evolution.get_tool_penalty(step.tool)
        if self.evolution.is_tool_blocked(step.tool):
            self.console.print(
                f"🚫 Tool {step.tool} is BLOCKED (penalty={penalty:.1f})",
                style=self.STYLE_RED
            )
            # Trigger replan
            self.planner.replan(step.step_id)
            return True

        self.console.print(
            f"📊 Tool penalty: {penalty:.1f} / {self.evolution.BLOCK_THRESHOLD}",
            style="dim"
        )
        return False

    def _record_action(self,
                       step: PlanStep,
                       success: bool,
                       penalty: float,
                       execution_result: Dict[str,
                                              Any]) -> None:
        """Record action to evolution memory."""
        if getattr(self, "_fallback_mode", False):
            return

        target = self.state.target if self.state else "unknown"
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
            error_message=execution_result.get("stderr", "")[:200]
        )
        self.evolution.record_action(record)

    def _handle_step_success(self, step: PlanStep,
                             execution_result: Dict[str, Any]) -> None:
        """Handle successful step execution."""
        self.planner.mark_step_success(
            step.step_id, execution_result.get(
                "stdout", "")[
                :200])
        self.console.print("✅ Step succeeded", style="green")
        self.stagnation_counter = 0

        # Update profile outcome on success
        if self.current_profile and not getattr(self, "_fallback_mode", False):
            self.refining_engine.update_profile_outcome(
                self.current_profile.profile_id, True)

    def _handle_step_failure(self, step: PlanStep,
                             execution_result: Dict[str, Any]) -> bool:
        """Handle failed step execution. Returns False if critical failure loop break needed."""
        stderr_msg = execution_result.get("stderr", "Unknown error")
        should_replan = self.planner.mark_step_failed(
            step.step_id, stderr_msg[:200])
        self.console.print(f"❌ Step failed: {stderr_msg[:200]}", style="red")

        # === RECORD FAILURE + POLICY LEARNING ===
        error_msg = stderr_msg[:100]
        error_type = "unknown"
        if "timeout" in error_msg.lower():
            error_type = "timeout"
        elif "connection refused" in error_msg.lower():
            error_type = "connection_refused"
        elif "permission" in error_msg.lower():
            error_type = "permission_denied"
        elif "not found" in error_msg.lower() or "not recognized" in error_msg.lower():
            self.console.print(
                f"🛑 CRITICAL: Tool '{
                    step.tool}' not found! Please install it.",
                style=self.STYLE_RED)
            self.running = False
            return False

        # Record failure to database
        if self.current_profile:
            self._record_failure_learning(step, error_type, error_msg)

        if should_replan:
            self._handle_replan(step, error_msg)

        return True

    def _record_failure_learning(self, step, error_type, error_msg):
        """Record failure detail to refining engine."""
        if getattr(self, "_fallback_mode", False):
            return

        failure_id = self.refining_engine.record_failure(
            target_signature=self.target_signature,
            strategy_name=self.current_strategy.name if self.current_strategy else "unknown",
            profile_id=self.current_profile.profile_id,
            error_type=error_type,
            error_message=error_msg,
            tool_name=step.tool,
            context_data={
                "action": step.action,
                "params": step.params})

        # Try to learn policy from this failure
        policy_id = self.refining_engine.learn_policy_from_failure(failure_id)
        if policy_id:
            self.console.print(
                f"📚 Learned new policy: {policy_id[:12]}...",
                style="dim"
            )

        # Update profile outcome (may trigger retirement)
        retired_profile = self.refining_engine.update_profile_outcome(
            self.current_profile.profile_id, False
        )
        if retired_profile:
            self.console.print(
                f"⚠️  Profile {retired_profile.profile_id[:12]}... RETIRED due to low success rate",
                style="yellow"
            )

    def _handle_replan(self, step, error_msg):
        """Handle replanning logic and AI tool creation backup."""
        self.console.print("🔄 Triggering replan...", style="yellow")
        replan_success = self.planner.replan(step.step_id)

        if not replan_success:
            self.console.print(
                "📝 Replan failed - will select different profile next time",
                style="yellow"
            )

        # === SELF-CODING: If replan failed, try to create new tool ===
        if not replan_success and self.tools_created_this_session < 3:
            self.console.print(
                "🧠 No alternative tool found. Attempting to CREATE one...",
                style=self.STYLE_MAGENTA
            )

            create_result = self.coder.create_alternative_tool(
                failed_tool=step.tool,
                action=step.action,
                target=self.state.target,
                error_message=error_msg
            )

            if create_result.get("success"):
                new_tool_name = create_result["tool_name"]
                self.console.print(
                    f"✨ Created new tool: {new_tool_name}",
                    style=self.STYLE_GREEN
                )
                self.tools_created_this_session += 1

                # Register in tool_selector
                self.tool_selector.register_dynamic_tool(
                    name=new_tool_name,
                    phase=self.state.phase,
                    command_template=f"DYNAMIC:{new_tool_name}"
                )

                # Update step
                step.tool = new_tool_name
                step.status = StepStatus.PENDING
                step.retry_count = 0
            else:
                self.console.print(
                    f"⚠️  Could not create tool: {create_result.get('error')}",
                    style="yellow"
                )

    def _validate_loop_state(self) -> bool:
        """Validate state invariants and halt conditions."""
        if not self.state.validate():
            self.console.print(
                "❌ STATE INVARIANT VIOLATION!",
                style=self.STYLE_RED)
            for violation in self.state.invariant_violations:
                self.console.print(f"   - {violation}", style="red")
            return False

        should_halt, halt_reason = self.state.should_halt()
        if should_halt:
            self.console.print(
                f"\n🛑 HALT: {halt_reason}",
                style=self.STYLE_YELLOW)
            return False

        return True

    def _get_llm_decision(self, context: Dict) -> Optional[Dict]:
        """
        LLM'den TEK aksiyon al - with retry and fallback mechanism

        LLM'ye gönderilen:
        - State snapshot (5 satır özet)
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

    def _try_llm_with_retry(self, context: Dict) -> Optional[Dict]:
        """Try LLM decision with retry mechanism"""
        MAX_LLM_RETRIES = 2

        for attempt in range(MAX_LLM_RETRIES):
            result = self._attempt_llm_query(context, attempt, MAX_LLM_RETRIES)
            if result is not None:
                return result
        return None

    def _attempt_llm_query(
            self,
            context: Dict,
            attempt: int,
            max_retries: int) -> Optional[Dict]:
        """Attempt a single LLM query"""
        try:
            result = self.brain.select_next_tool(context)
            if self._is_valid_llm_result(result):
                return result

            llm_error = self._extract_llm_error(result)
            if llm_error and self._should_retry(attempt, max_retries):
                self._handle_llm_retry(attempt, max_retries)
            return None
        except Exception:
            if self._should_retry(attempt, max_retries):
                self._handle_llm_retry(attempt, max_retries)
            return None

    def _should_retry(self, attempt: int, max_retries: int) -> bool:
        """Check if we should retry based on attempt number"""
        return attempt < max_retries - 1

    def _is_valid_llm_result(self, result: Any) -> bool:
        """Check if LLM result is valid"""
        return isinstance(result, dict) and "tool" in result

    def _extract_llm_error(self, result: Any) -> Optional[str]:
        """Extract error message from LLM result"""
        if isinstance(result, dict) and result.get("error"):
            return result.get("error")
        return None

    def _handle_llm_retry(self, attempt: int, max_retries: int) -> None:
        """Handle LLM retry with user feedback"""
        self.console.print(
            f"⚠️  LLM hatası, yeniden deneniyor... ({
                attempt + 1}/{max_retries})",
            style="yellow")
        time.sleep(1)

    def _log_llm_failure(self, llm_error: str, max_retries: int) -> None:
        """Log LLM failure and switch to fallback"""
        self.console.print(
            f"⚠️  LLM kullanılamıyor: {llm_error}",
            style="yellow")
        self.console.print(
            "🔄 Deterministik karar mekanizmasına geçiliyor...",
            style="dim")
        logger.warning(
            f"LLM decision failed after {max_retries} attempts: {llm_error}")

    def _get_deterministic_fallback(self) -> Optional[Dict]:
        """Get deterministic decision as fallback"""
        deterministic_decision = self.tool_selector.recommend_next_action(
            self.state)
        if deterministic_decision:
            _, tool_name, args = deterministic_decision
            self.console.print(
                f"✅ Deterministik karar: {tool_name}",
                style="dim")
            return {"tool": tool_name, "args": args}
        return None

    def _install_tool(self, tool_name: str) -> bool:
        """
        Attempt to automatically install a missing tool.
        Supports: Linux (apt), MacOS (brew), Windows (choco/winget)
        """
        import platform

        # Map internal tool names to package names
        tool_pkg_map = {
            # Nmap variants
            "nmap_port_scan": "nmap",
            "nmap_service_scan": "nmap",
            "nmap_vuln_scan": "nmap",
            "nmap": "nmap",
            # SQLMap
            "sqlmap_scan": "sqlmap",
            "sqlmap_exploit": "sqlmap",
            "sqlmap": "sqlmap",
            # Web scanners
            "nikto_web_scan": "nikto",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "dirb": "dirb",
            "wfuzz": "wfuzz",
            # Network tools
            "netcat": "netcat",
            "nc": "netcat",
            "hydra": "hydra",
            "medusa": "medusa",
            # Metasploit
            "msfconsole": "metasploit-framework",
            "msfvenom": "metasploit-framework",
            "msfvenom_payload": "metasploit-framework",
            # Other common tools
            "whatweb": "whatweb",
            "wpscan": "wpscan",
            "masscan": "masscan",
            "john": "john",
            "hashcat": "hashcat",
            "aircrack-ng": "aircrack-ng",
            "wireshark": "wireshark",
            "tcpdump": "tcpdump",
            "curl": "curl",
            "wget": "wget",
        }

        pkg = tool_pkg_map.get(tool_name)
        if not pkg:
            # Try using tool_name directly as package name
            pkg = tool_name.split("_")[0]  # nmap_port_scan -> nmap

        system = platform.system().lower()
        self.console.print(
            f"🛠️ Attempting to auto-install '{pkg}'...",
            style="yellow")

        install_cmd = ""
        if system == "linux":
            install_cmd = f"sudo apt-get update && sudo apt-get install -y {pkg}"
        elif system == "darwin":  # MacOS
            install_cmd = f"brew install {pkg}"
        elif system == "windows":
            # Try winget first (standard on modern Windows)
            install_cmd = f"winget install {pkg} --accept-source-agreements --accept-package-agreements"

        if not install_cmd:
            return False

        # Execute install
        try:
            res = self.executor.terminal.execute(install_cmd, timeout=300)
            if res.exit_code == 0:
                self.console.print(
                    f"✅ Successfully installed {pkg}",
                    style="green")
                return True
            else:
                self.console.print(
                    f"❌ Auto-install failed: {res.stderr}", style="red")
                return False
        except Exception as e:
            self.console.print(f"❌ Auto-install error: {e}", style="red")
            return False

    def _execute_tool(self, tool_name: str, args: Dict) -> Dict:
        """
        Execute tool with error handling and retry logic
        """
        # 1. Check if tool is blocked
        if self.tool_selector.is_tool_blocked(tool_name):
            return {
                "success": False,
                "error": f"Tool {tool_name} blocked due to repeated failures",
                "args": args,
            }

        # 1.5 AD Module Routing
        if tool_name in ["kerbrute", "impacket", "crackmapexec", "netexec"]:
            return self._handle_ad_tool(tool_name, args)

        # 2. SYSTEM EVOLUTION (Meta-tool)
        if tool_name == "system_evolution":
            return self._handle_system_evolution(args)

        # 3. Metasploit special case
        if tool_name == "metasploit_exploit":
            return {
                "success": False,
                "error": "Metasploit integration blocked: no state-aware wrapper",
                "args": args,
            }

        # 4. Get tool spec
        tool_spec = self.tool_selector.tools.get(tool_name)
        if not tool_spec:
            return {"success": False, "error": "Tool not found", "args": args}

        # 5. Execute system tool
        return self._run_system_tool(tool_name, tool_spec, args)

    def _handle_ad_tool(self, tool_name: str, args: Dict) -> Dict:
        """Handle execution of AD-related tools"""
        self.console.print(
            f"🏢 Routing {tool_name} to Active Directory Module...",
            style="cyan")
        domain = args.get("target") or args.get("domain")
        dc_ip = args.get("dc_ip")

        # Handle nested params if strictly passed that way
        if not dc_ip and "params" in args and isinstance(
                args["params"], dict):
            dc_ip = args["params"].get("dc_ip")

        if not domain:
            return {
                "success": False,
                "error": "Missing target domain for AD attack",
                "args": args}

        if tool_name == "kerbrute":
            if not dc_ip:
                return {
                    "success": False,
                    "error": "Missing DC IP for Kerbrute",
                    "args": args}
            return self.ad_attacker.run_kerbrute_userenum(
                domain, dc_ip, args.get("user_list", "users.txt"))

        elif tool_name == "impacket":
            if args.get("action") == "ad_asreproast":
                if not dc_ip:
                    return {
                        "success": False,
                        "error": "Missing DC IP for AS-REP Roast",
                        "args": args}
                return self.ad_attacker.run_asreproast(domain, dc_ip)
            return {
                "success": False,
                "error": f"Unknown Impacket action: {
                    args.get('action')}",
                "args": args}

        elif tool_name in ["crackmapexec", "netexec"]:
            return self.ad_attacker.run_smb_spray(
                domain, args.get(
                    "target_ip", dc_ip), args.get(
                    "user_file", ""), args.get(
                    "password", ""))
        
        return {"success": False, "error": f"Unsupported AD tool: {tool_name}", "args": args}

    def _handle_system_evolution(self, args: Dict) -> Dict:
        """Handle the system_evolution meta-tool"""
        action = args.get("action")
        target = args.get("target")  # file path or tool name
        instruction = args.get("instruction")

        if action == "create_tool":
            # Dynamic tool creation via Coder
            result = self.coder.create_tool(
                tool_name=str(target), 
                description=str(instruction),
                requirements="standard library only"
            )
            if result["success"]:
                # Register new tool dynamically
                self.tool_selector.register_dynamic_tool(
                    name=str(target),
                    phase=AttackPhase.EXPLOIT,
                    command_template=f"python3 modules/{target}.py {{target}}"
                )
                return {
                    "success": True,
                    "output": f"Tool {target} created and registered."}
            return result

        elif action == "modify_file":
            # Self-modification
            # Security check: only allow modifying non-core files?
            # For now, allow all (God Mode)

            # Read file first
            try:
                with open(target, 'r') as f:
                    content = f.read()
            except Exception as e:
                return {"success": False, "error": f"Read failed: {e}"}

            # Ask LLM for modification
            modification = self.brain.ask_coder(
                f"Modify this file:\n{target}\n\nInstruction:\n{instruction}\n\nContent:\n{content}")

            if modification.get("code"):
                new_content = modification["code"]
                # Verify syntax
                import ast
                try:
                    ast.parse(new_content)
                    with open(target, 'w') as f:
                        f.write(new_content)
                    return {
                        "success": True,
                        "output": f"File {target} modified successfully."}
                except SyntaxError:
                    return {
                        "success": False,
                        "error": "Generated code had syntax errors. Change rejected.",
                    }
            return {"success": False, "error": "No code generated"}

        return {"success": False, "error": "Unknown evolution action"}

    def _run_system_tool(self, tool_name: str, tool_spec, args: Dict) -> Dict:
        """Run a standard system tool"""
        # Build command from template
        try:
            command = tool_spec.command_template.format(**args)
        except KeyError as e:
            return {
                "success": False,
                "error": f"Missing argument: {e}",
                "args": args}

        # Execute via execution engine
        result = self.executor.terminal.execute(command, timeout=300)

        # Track tool failures globally
        if result.exit_code != 0:
            # DELEGATE TO SELF_HEALER
            return self.healer.handle_tool_failure(
                tool_name, command, result, args, self._format_tool_result
            )

        return self._format_tool_result(result, args)

    def _format_tool_result(self, result, args: Dict) -> Dict:
        """Format execution result dictionary with standardized errors"""
        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        exit_code = result.exit_code

        # New: Standardize error
        error_msg = normalize_error_message(stdout_str, stderr_str, exit_code)

        # Fallback raw error if normalize returns nothing but exit code
        # non-zero
        if exit_code != 0 and not error_msg:
            if stderr_str.strip():
                error_msg = f"Tool Error: {stderr_str.strip()[:200]}"
            else:
                error_msg = f"Command failed with exit code {exit_code}"

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
            # args might need to contain tool name?
            tool=args.get("tool_name", "unknown"),
            args=args,
            result=final_result
        )

        return final_result

    def _run_async(self, coro, timeout: int = 60):
        """
        Run async coroutine deterministically from sync context.
        Includes proper timeout and error handling to prevent hangs.

        Args:
            coro: Async coroutine to run
            timeout: Max execution time in seconds (default: 60)

        Returns:
            Coroutine result or error dict
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            self.console.print(
                "⚠️  Cannot run async: event loop already running",
                style="yellow")
            return {
                "success": False,
                "error": "Async execution blocked: event loop already running",
            }

        try:
            # Use asyncio.timeout context manager (Python 3.11+) for better SonarQube compliance
            # Falls back to asyncio.wait_for for older Python versions
            if hasattr(asyncio, 'timeout'):
                # Python 3.11+ - use modern timeout context manager
                async def _run_with_timeout():
                    async with asyncio.timeout(timeout):
                        return await coro
                return asyncio.run(_run_with_timeout())
            else:
                # Python < 3.11 - use wait_for for backward compatibility
                return asyncio.run(asyncio.wait_for(coro, timeout=timeout))
        except TimeoutError:
            # asyncio.timeout raises TimeoutError (Python 3.11+)
            self.console.print(
                f"⚠️  Async task timeout after {timeout}s", style="yellow"
            )
            return {
                "success": False,
                "error": f"Async task timed out after {timeout}s"}
        except asyncio.TimeoutError:
            # asyncio.wait_for raises asyncio.TimeoutError (Python < 3.11)
            self.console.print(
                f"⚠️  Async task timeout after {timeout}s", style="yellow"
            )
            return {
                "success": False,
                "error": f"Async task timed out after {timeout}s"}
        except Exception as e:
            logger.exception(f"Async execution error: {e}")
            self.console.print(
                f"⚠️  Async execution error: {e}",
                style="yellow")
            return {
                "success": False,
                "error": f"Async execution failed: {
                    str(e)}"}

    def _create_observation(self, tool_name: str, result: Dict) -> str:
        """
        Tool sonucundan ÖZET observation oluştur

        YASAK: Raw log, tool output spam
        SADECE: Anlamlı özet
        """
        if not result.get("success"):
            error_msg = result.get("error") or result.get(
                "stderr", "Unknown error")
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

        elif "nikto" in tool_name:
            return "Web vulnerability scan completed"

        elif "sqlmap" in tool_name:
            stdout = result.get("stdout", "")
            if "vulnerable" in stdout.lower():
                return "SQL injection vulnerability found"
            return "SQL injection scan completed, no vulnerabilities"

        # Generic
        return f"Tool {tool_name} completed successfully"

    def _update_state_from_result(
            self,
            tool_name: str,
            result: Dict,
            observation: str):
        """
        Update state based on tool result.
        """
        # Set observation
        self.state.set_observation(observation)

        # 1. Record Result Execution (Success/Failure)
        self._record_execution_outcome(tool_name, result)

        if not result.get("success"):
            return

        # 2. Update State Specifics based on Tool
        self._dispatch_state_update(tool_name, result)

    def _record_execution_outcome(self, tool_name: str, result: Dict):
        """Record success or failure to brain and tool selector"""
        output = result.get("stdout", "") + "\n" + result.get("stderr", "")
        success = result.get("success", False)

        if not success:
            self.tool_selector.record_tool_failure(tool_name)

        self.brain.observe(tool=tool_name, output=output, success=success)

    def _dispatch_state_update(self, tool_name: str, result: Dict):
        """Dispatch state update based on tool type"""
        if "nmap_port_scan" in tool_name:
            self._update_state_nmap_port_scan(result)
        elif "nmap_service_scan" in tool_name or "nikto" in tool_name:
            self._update_state_service_completion(result)
        elif "vuln" in tool_name or "sqlmap" in tool_name:
            observation = result.get("stdout", "")
            self._process_vulnerability_result(tool_name, result, observation)
        elif "exploit" in tool_name:
            self._process_exploit_result(tool_name, result)

    def _process_exploit_result(self, tool_name: str, result: Dict):
        """Helper to process exploit results"""
        observation = result.get("stdout", "") + "\n" + \
            result.get("stderr", "")
        # Check if exploit succeeded
        if "success" in observation.lower(
        ) or "shell" in observation.lower() or result.get("success"):
            self.state.set_foothold(tool_name)
        else:
            self.state.set_observation(
                "Exploit did not succeed; foothold not set")

    def _update_state_nmap_port_scan(self, result: Dict):
        """Update state from Nmap port scan results"""
        from core.tool_parsers import parse_nmap_output

        stdout = result.get("stdout", "")
        # Hybrid parsing with LLM fallback
        parsed_services = parse_nmap_output(
            stdout, llm_client=self.brain.llm_client
        )

        if parsed_services:
            services = []
            for svc_dict in parsed_services:
                services.append(
                    ServiceInfo(
                        port=svc_dict["port"],
                        protocol=svc_dict["proto"],
                        service=svc_dict["service"],
                    )
                )
            self.state.update_services(services)
        else:
            # Fallback to mock if parsing failed (for testing)
            self._apply_mock_services()

    def _apply_mock_services(self):
        """Apply mock services for testing or fallback"""
        services = [
            ServiceInfo(port=80, protocol="tcp", service="http"),
            ServiceInfo(port=443, protocol="tcp", service="https"),
            ServiceInfo(port=22, protocol="tcp", service="ssh"),
        ]
        self.state.update_services(services)

    def _update_state_service_completion(self, result: Dict):
        """Mark service as tested"""
        args_port = result.get("args", {}).get("port")
        if not args_port:
            self.state.set_observation(
                "Missing port in tool args; state not updated"
            )
            return

        if args_port in self.state.open_services:
            service_info = self.state.open_services[args_port]
            self.state.mark_surface_tested(args_port, service_info.service)

    def _process_vulnerability_result(
            self,
            tool_name: str,
            result: Dict,
            observation: str):
        """Helper to process vulnerability scan results"""
        if "vuln" in tool_name or "sqlmap" in tool_name:
            if "vulnerable" in observation.lower() or "injection" in observation.lower():
                self._handle_sqlmap_vulnerabilities(result)

    def _handle_sqlmap_vulnerabilities(self, result: Dict):
        """Process SQLMap results and update state"""
        from core.tool_parsers import parse_sqlmap_output

        stdout = result.get("stdout", "")
        # Hybrid parsing with LLM fallback
        parsed_vulns = parse_sqlmap_output(
            stdout, llm_client=self.brain.llm_client)

        if parsed_vulns:
            target_port = self._extract_port_from_result(result)

            for vuln_dict in parsed_vulns:
                vuln = VulnerabilityInfo(
                    vuln_id=f"sqli_{vuln_dict.get('parameter', 'unknown')}",
                    service="http",
                    port=target_port,
                    severity=str(FindingSeverity.CRITICAL.value),
                    exploitable=True
                )
                self.state.add_vulnerability(vuln)

    def _extract_port_from_result(self, result: Dict) -> int:
        """Extract port number from tool result arguments"""
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

    def _check_phase_transition(self):
        """
        Phase transition kontrolü - DETERMİNİSTİK
        """
        # INIT -> RECON (target set)
        if self.state.phase == AttackPhase.INIT and self.state.target:
            self.state.phase = AttackPhase.RECON
            self.console.print(
                "📈 Phase transition: INIT -> RECON",
                style=self.STYLE_BLUE)

        # RECON -> VULN_SCAN (services discovered, no more remaining)
        elif (
            self.state.phase == AttackPhase.RECON
            and self.state.open_services
            and len(self.state.remaining_attack_surface) == 0
        ):
            self.state.phase = AttackPhase.VULN_SCAN
            # Re-add services for vuln scanning
            for port, svc in self.state.open_services.items():
                surface_key = f"{port}:{svc.service}"
                self.state.remaining_attack_surface.add(surface_key)
            self.console.print(
                "📈 Phase transition: RECON -> VULN_SCAN", style=self.STYLE_BLUE
            )

        # VULN_SCAN -> EXPLOIT (vulnerabilities found)
        elif (
            self.state.phase == AttackPhase.VULN_SCAN
            and self.state.vulnerabilities
            and len(self.state.remaining_attack_surface) == 0
        ):
            self.state.phase = AttackPhase.EXPLOIT
            self.console.print(
                "📈 Phase transition: VULN_SCAN -> EXPLOIT",
                style=self.STYLE_BLUE)

        # VULN_SCAN -> COMPLETE (no vulnerabilities found, surfaces exhausted)
        elif (
            self.state.phase == AttackPhase.VULN_SCAN
            and not self.state.vulnerabilities
            and len(self.state.remaining_attack_surface) == 0
        ):
            self.state.phase = AttackPhase.COMPLETE
            self.console.print(
                "📈 Phase transition: VULN_SCAN -> COMPLETE (no vulns found)",
                style=self.STYLE_YELLOW,
            )

        # EXPLOIT -> POST_EXPLOIT (foothold achieved)
        elif self.state.phase == AttackPhase.EXPLOIT and self.state.has_foothold:
            self.state.phase = AttackPhase.POST_EXPLOIT
            self.console.print(
                "📈 Phase transition: EXPLOIT -> POST_EXPLOIT",
                style=self.STYLE_BLUE)

    def _show_final_report(self):
        """Show final execution report"""
        self.console.print("\n" + "=" * 60, style="bold")
        self.console.print("📊 FINAL REPORT", style=self.STYLE_GREEN)
        self.console.print("=" * 60, style="bold")

        report = Text()
        report.append(f"🎯 Target: {self.state.target}\n", style="bold")
        report.append(
            f"🔄 Iterations: {self.state.iteration_count}/{self.state.max_iterations}\n"
        )
        report.append(f"📍 Final Phase: {self.state.phase.value}\n")
        report.append(f"🔓 Services Found: {len(self.state.open_services)}\n")
        report.append(
            f"⚠️  Vulnerabilities: {len(self.state.vulnerabilities)}\n")
        report.append(
            f"🎪 Foothold: {
                'YES' if self.state.has_foothold else 'NO'}\n")

        if self.state.has_foothold:
            report.append(
                f"   Method: {
                    self.state.foothold_method}\n",
                style="green")

        if self.state.invariant_violations:
            report.append("\n❌ Invariant Violations:\n", style=self.STYLE_RED)
            for violation in self.state.invariant_violations:
                report.append(f"   - {violation}\n", style="red")

        self.console.print(
            Panel(
                report,
                border_style="green",
                title="Summary"))

    def stop(self) -> None:
        """Stop the agent"""
        self.running = False
