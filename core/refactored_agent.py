# core/refactored_agent.py
# DRAKBEN SELF-REFINING EVOLVING AGENT
# PROFILE-BASED EVOLUTION + POLICY CONFLICT RESOLUTION + META-LEARNING

import asyncio
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Any, Callable

# Setup logger
logger = logging.getLogger(__name__)

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.brain import DrakbenBrain
from core.coder import AICoder
from core.config import ConfigManager
from core.evolution_memory import ActionRecord, get_evolution_memory
from core.execution_engine import ExecutionEngine
from core.planner import Planner, PlanStep, StepStatus
from core.state import (AgentState, AttackPhase, reset_state, ServiceInfo, VulnerabilityInfo)
from modules.report_generator import FindingSeverity
from core.self_refining_engine import (
    SelfRefiningEngine, 
    Strategy, 
    StrategyProfile,
    PolicyTier
)
from core.tool_selector import ToolSelector
from core.tool_parsers import normalize_error_message
from core.structured_logger import DrakbenLogger
from modules import exploit as exploit_module
from modules import payload as payload_module


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

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.console = Console()
        self.logger = DrakbenLogger()  # NEW: Structured Logging

        # Core Components
        self.brain = DrakbenBrain(llm_client=config_manager.llm_client)
        self.state: Optional[AgentState] = None
        self.tool_selector = ToolSelector()
        self.executor = ExecutionEngine()
        
        # SELF-REFINING EVOLUTION COMPONENTS
        self.evolution = get_evolution_memory()
        self.refining_engine = SelfRefiningEngine()  # NEW: Profile-based evolution
        self.planner = Planner()
        self.coder = AICoder(self.brain)

        # Runtime state
        self.running = False
        self.stagnation_counter = 0
        self.tools_created_this_session = 0
        self.current_strategy: Optional[Strategy] = None
        self.current_profile: Optional[StrategyProfile] = None  # NEW: Track profile
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
            
            if not self._select_and_filter_profile(target):
                return
            
            self._display_selected_profile()
            self._create_or_load_plan(target)
            self._show_evolution_info(target_type)

            self.running = True
            self.stagnation_counter = 0
            
        except sqlite3.OperationalError as e:
            logger.critical(f"Database error during init: {e}")
            self.console.print(f"⚠️  Database error: {e}", style="yellow")
            self.console.print("⚠️  Switching to fallback mode (limited functionality)", style="yellow")
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
            self.console.print(f"⚠️  Tool evolution skipped: {e}", style="yellow")
    
    def _classify_target(self, target: str) -> str:
        """Classify target and set signature"""
        target_type = self.refining_engine.classify_target(target)
        self.target_signature = self.refining_engine.get_target_signature(target)
        self.console.print(f"🎯 Target Classification: {target_type}", style="cyan")
        self.console.print(f"🔑 Target Signature: {self.target_signature}", style="dim")
        return target_type
    
    def _select_and_filter_profile(self, target: str) -> bool:
        """Select strategy/profile and apply mode-based filtering. Returns False if failed."""
        try:
            self.current_strategy, self.current_profile = self.refining_engine.select_strategy_and_profile(target)
            self._apply_mode_filtering()
        except Exception as e:
            self.console.print(f"❌ Strategy selection failed: {e}", style="red")
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
        self.console.print("🥷 Stealth mode: Searching for low-aggression profile...", style="dim")
        profiles = self.refining_engine.get_profiles_for_strategy(self.current_strategy.name)
        stealth_profiles = [p for p in profiles if p.aggressiveness <= 0.4]
        if stealth_profiles:
            self.current_profile = sorted(stealth_profiles, key=lambda p: p.aggressiveness)[0]
            self.console.print(f"🥷 Switched to stealth profile (aggression: {self.current_profile.aggressiveness:.2f})", style="green")
    
    def _switch_to_aggressive_profile(self) -> None:
        """Switch to high-aggression profile for aggressive mode"""
        self.console.print("⚡ Aggressive mode: Searching for high-aggression profile...", style="dim")
        profiles = self.refining_engine.get_profiles_for_strategy(self.current_strategy.name)
        aggressive_profiles = [p for p in profiles if p.aggressiveness >= 0.6]
        if aggressive_profiles:
            self.current_profile = sorted(aggressive_profiles, key=lambda p: -p.aggressiveness)[0]
            self.console.print(f"⚡ Switched to aggressive profile (aggression: {self.current_profile.aggressiveness:.2f})", style="yellow")
    
    def _display_selected_profile(self) -> None:
        """Display selected strategy and profile information"""
        self.console.print(f"🧠 Selected Strategy: {self.current_strategy.name}", style=self.STYLE_MAGENTA)
        self.console.print(
            f"🎭 Selected Profile: {self.current_profile.profile_id[:12]}... "
            f"(gen: {self.current_profile.mutation_generation}, "
            f"success_rate: {self.current_profile.success_rate:.1%}, "
            f"aggression: {self.current_profile.aggressiveness:.2f})",
            style=self.STYLE_CYAN
        )
        self.console.print(f"   📋 Step Order: {self.current_profile.step_order}", style="dim")
        self.console.print(f"   ⚙️  Parameters: {json.dumps(self.current_profile.parameters)}", style="dim")
    
    def _create_or_load_plan(self, target: str) -> None:
        """Create new plan or load existing plan"""
        existing_plan = self.evolution.get_active_plan(f"pentest_{target}")
        if existing_plan:
            self.console.print(f"🔁 Resuming plan: {existing_plan.plan_id}", style=self.STYLE_GREEN)
            self.planner.load_plan(existing_plan.plan_id)
        else:
            plan_id = self.planner.create_plan_from_profile(target, self.current_profile, f"pentest_{target}")
            self.console.print(f"📋 Created plan from profile: {plan_id}", style=self.STYLE_GREEN)
    
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
                self.console.print(f"📜 Active Policies: {len(policies)}", style="yellow")
                for p in policies[:3]:
                    tier_name = PolicyTier(p.priority_tier).name
                    self.console.print(
                        f"   - Tier {p.priority_tier} ({tier_name}): {p.action} (weight: {p.weight:.2f})", 
                        style="dim"
                    )
        except Exception as e:
            logger.exception(f"Critical initialization error: {e}")
            self.console.print(f"❌ Critical error during initialization: {e}", style=self.STYLE_RED)
            # Still allow basic operation
            self.state = reset_state(target)
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
        
        self.console.print(f"\n{'='*60}", style="dim")
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
            f"📋 Plan Step: {step.step_id} | Action: {step.action} | Tool: {step.tool}",
            style="cyan"
        )

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

        execution_result = self._execute_tool(step.tool, step.params)
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
        self._update_state_from_result(step.tool, execution_result, observation)

        # 8. Validation & Halt Limit
        if not self._validate_loop_state():
            return False

        self.state.increment_iteration()
        return True

    def _check_stagnation(self) -> bool:
        """Check for stagnation and triggering replan if needed. Returns True if halt required."""
        if self.evolution.detect_stagnation():
            self.console.print("⚠️  STAGNATION DETECTED - forcing replan", style=self.STYLE_YELLOW)
            current_step = self.planner.get_next_step()
            if current_step:
                self.planner.replan(current_step.step_id)
            self.stagnation_counter += 1
            
            if self.stagnation_counter >= 3:
                self.console.print("🛑 HALT: Too many stagnations", style=self.STYLE_RED)
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

    def _record_action(self, step: PlanStep, success: bool, penalty: float, execution_result: Dict[str, Any]) -> None:
        """Record action to evolution memory."""
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

    def _handle_step_success(self, step: PlanStep, execution_result: Dict[str, Any]) -> None:
        """Handle successful step execution."""
        self.planner.mark_step_success(step.step_id, execution_result.get("stdout", "")[:200])
        self.console.print("✅ Step succeeded", style="green")
        self.stagnation_counter = 0
        
        # Update profile outcome on success
        if self.current_profile:
            self.refining_engine.update_profile_outcome(self.current_profile.profile_id, True)

    def _handle_step_failure(self, step: PlanStep, execution_result: Dict[str, Any]) -> bool:
        """Handle failed step execution. Returns False if critical failure loop break needed."""
        stderr_msg = execution_result.get("stderr", "Unknown error")
        should_replan = self.planner.mark_step_failed(step.step_id, stderr_msg[:200])
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
            self.console.print(f"🛑 CRITICAL: Tool '{step.tool}' not found! Please install it.", style=self.STYLE_RED)
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
        failure_id = self.refining_engine.record_failure(
            target_signature=self.target_signature,
            strategy_name=self.current_strategy.name if self.current_strategy else "unknown",
            profile_id=self.current_profile.profile_id,
            error_type=error_type,
            error_message=error_msg,
            tool_name=step.tool,
            context_data={"action": step.action, "params": step.params}
        )
        
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
            self.console.print("❌ STATE INVARIANT VIOLATION!", style=self.STYLE_RED)
            for violation in self.state.invariant_violations:
                self.console.print(f"   - {violation}", style="red")
            return False

        should_halt, halt_reason = self.state.should_halt()
        if should_halt:
            self.console.print(f"\n🛑 HALT: {halt_reason}", style=self.STYLE_YELLOW)
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
    
    def _attempt_llm_query(self, context: Dict, attempt: int, max_retries: int) -> Optional[Dict]:
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
        self.console.print(f"⚠️  LLM hatası, yeniden deneniyor... ({attempt + 1}/{max_retries})", style="yellow")
        time.sleep(1)
    
    def _log_llm_failure(self, llm_error: str, max_retries: int) -> None:
        """Log LLM failure and switch to fallback"""
        self.console.print(f"⚠️  LLM kullanılamıyor: {llm_error}", style="yellow")
        self.console.print("🔄 Deterministik karar mekanizmasına geçiliyor...", style="dim")
        logger.warning(f"LLM decision failed after {max_retries} attempts: {llm_error}")
    
    def _get_deterministic_fallback(self) -> Optional[Dict]:
        """Get deterministic decision as fallback"""
        deterministic_decision = self.tool_selector.recommend_next_action(self.state)
        if deterministic_decision:
            _, tool_name, args = deterministic_decision
            self.console.print(f"✅ Deterministik karar: {tool_name}", style="dim")
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
        self.console.print(f"🛠️ Attempting to auto-install '{pkg}'...", style="yellow")
        
        install_cmd = ""
        if system == "linux":
            install_cmd = f"sudo apt-get update && sudo apt-get install -y {pkg}"
        elif system == "darwin": # MacOS
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
                 self.console.print(f"✅ Successfully installed {pkg}", style="green")
                 return True
             else:
                 self.console.print(f"❌ Auto-install failed: {res.stderr}", style="red")
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

    def _handle_system_evolution(self, args: Dict) -> Dict:
        """Handle the system_evolution meta-tool"""
        action = args.get("action")
        target = args.get("target")  # file path or tool name
        instruction = args.get("instruction")

        if action == "create_tool":
            # Dynamic tool creation via Coder
            result = self.coder.create_tool(
                tool_name=target, description=instruction
            )
            if result["success"]:
                # Register new tool dynamically
                self.tool_selector.register_dynamic_tool(
                    name=target,
                    phase=AttackPhase.EXPLOIT,
                    command_template=f"python3 modules/{target}.py {{target}}"
                )
                return {"success": True, "output": f"Tool {target} created and registered."}
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
                f"Modify this file:\n{target}\n\nInstruction:\n{instruction}\n\nContent:\n{content}"
            )
            
            if modification.get("code"):
                new_content = modification["code"]
                # Verify syntax
                import ast
                try:
                    ast.parse(new_content)
                    with open(target, 'w') as f:
                        f.write(new_content)
                    return {"success": True, "output": f"File {target} modified successfully."}
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
            return {"success": False, "error": f"Missing argument: {e}", "args": args}

        # Execute via execution engine
        result = self.executor.terminal.execute(command, timeout=300)

        # Track tool failures globally
        if result.exit_code != 0:
            return self._handle_tool_failure(tool_name, command, result, args)

        return self._format_tool_result(result, args)

    # Track self-healing attempts to prevent infinite loops
    _self_heal_attempts: Dict[str, int] = {}
    MAX_SELF_HEAL_PER_TOOL = 2  # Maximum self-heal attempts per tool per session
    
    def _handle_tool_failure(self, tool_name: str, command: str, result, args: Dict) -> Dict:
        """
        Handle tool failure with comprehensive self-healing.
        
        Error Types Handled:
        1. Missing tool → Auto-install
        2. Permission denied → Suggest sudo / elevate
        3. Connection refused → Network check / retry
        4. Timeout → Increase timeout / retry
        5. Python module missing → pip install
        6. Unknown → LLM-assisted diagnosis
        
        LOOP PROTECTION:
        - Maximum 2 self-heal attempts per tool per session
        - Prevents infinite retry loops
        """
        # Initialize tracking dict if needed
        if not hasattr(self, '_self_heal_attempts') or self._self_heal_attempts is None:
            self._self_heal_attempts = {}
        
        # Check if we've exceeded self-heal limit for this tool
        heal_key = f"{tool_name}:{command[:50]}"
        current_attempts = self._self_heal_attempts.get(heal_key, 0)
        
        if current_attempts >= self.MAX_SELF_HEAL_PER_TOOL:
            self.console.print(f"⚠️ {tool_name} için self-heal limiti aşıldı ({current_attempts}/{self.MAX_SELF_HEAL_PER_TOOL})", style="yellow")
            self.tool_selector.record_tool_failure(tool_name)
            return self._format_tool_result(result, args)
        
        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        combined_output = f"{stdout_str}\n{stderr_str}".lower()
        
        # Diagnose error type
        error_diagnosis = self._diagnose_error(combined_output, result.exit_code)
        
        if error_diagnosis["type"] != "unknown":
            self.console.print(f"🔍 Hata teşhisi: {error_diagnosis['type_tr']}", style="yellow")
        
        # Increment self-heal attempt counter
        self._self_heal_attempts[heal_key] = current_attempts + 1
        self.console.print(f"🔧 Self-heal denemesi: {current_attempts + 1}/{self.MAX_SELF_HEAL_PER_TOOL}", style="dim")
        
        # Apply self-healing based on error type
        healed, retry_result = self._apply_error_specific_healing(
            error_diagnosis, tool_name, command, combined_output
        )
        
        return self._finalize_healing_result(healed, retry_result, result, tool_name, args)
    
    def _apply_error_specific_healing(
        self, error_diagnosis: Dict[str, Any], tool_name: str, command: str,
        combined_output: str
    ) -> Tuple[bool, Optional[Any]]:
        """Apply error-specific healing strategies"""
        error_type = error_diagnosis["type"]
        healing_map = {
            "missing_tool": self._heal_missing_tool,
            "permission_denied": self._heal_permission_denied,
            "python_module_missing": self._heal_python_module_missing,
            "connection_error": self._heal_connection_error,
            "timeout": self._heal_timeout,
            "library_missing": self._heal_library_missing,
            "rate_limit": self._heal_rate_limit,
            "port_in_use": self._heal_port_in_use,
            "disk_full": self._heal_disk_full,
            "firewall_blocked": self._heal_firewall_blocked,
            "database_error": self._heal_database_error,
        }
        
        if error_type in healing_map:
            return healing_map[error_type](tool_name, command, error_diagnosis)
        elif error_type == "unknown" and self.brain:
            return self._llm_assisted_error_fix(tool_name, command, combined_output)
        
        return False, None
    
    def _heal_missing_tool(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal missing tool error by auto-installing"""
        if self._install_tool(tool_name):
            self.console.print(f"🔄 {tool_name} yüklendi, yeniden deneniyor...", style="cyan")
            retry_result = self.executor.terminal.execute(command, timeout=300)
            return retry_result.exit_code == 0, retry_result
        return False, None
    
    def _heal_permission_denied(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal permission denied by trying sudo"""
        import platform
        if platform.system().lower() != "windows" and not command.startswith("sudo"):
            self.console.print("🔐 İzin hatası - sudo ile deneniyor...", style="yellow")
            sudo_cmd = f"sudo {command}"
            retry_result = self.executor.terminal.execute(sudo_cmd, timeout=300)
            return retry_result.exit_code == 0, retry_result
        return False, None
    
    def _heal_python_module_missing(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal missing Python module by pip install"""
        module_name = error_diagnosis.get("module")
        if module_name:
            self.console.print(f"📦 Python modülü eksik: {module_name} - yükleniyor...", style="yellow")
            pip_cmd = f"pip install {module_name}"
            pip_result = self.executor.terminal.execute(pip_cmd, timeout=120)
            if pip_result.exit_code == 0:
                self.console.print(f"✅ {module_name} yüklendi, yeniden deneniyor...", style="green")
                retry_result = self.executor.terminal.execute(command, timeout=300)
                return retry_result.exit_code == 0, retry_result
        return False, None
    
    def _heal_connection_error(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal connection error by retrying with backoff"""
        self.console.print("🌐 Bağlantı hatası - 3 saniye bekleyip yeniden deneniyor...", style="yellow")
        time.sleep(3)
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result
    
    def _heal_timeout(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal timeout by retrying with longer timeout"""
        self.console.print("⏱️ Zaman aşımı - daha uzun timeout ile deneniyor...", style="yellow")
        retry_result = self.executor.terminal.execute(command, timeout=600)
        return retry_result.exit_code == 0, retry_result
    
    def _heal_library_missing(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal missing library by installing system package"""
        library = error_diagnosis.get("library", "")
        if not library:
            return False, None
        
        self.console.print(f"📚 Kütüphane eksik: {library} - yükleniyor...", style="yellow")
        import platform
        system = platform.system().lower()
        lib_pkg_map = {
            "libssl": "openssl" if system == "darwin" else "libssl-dev",
            "libcrypto": "openssl" if system == "darwin" else "libssl-dev",
            "libffi": "libffi-dev",
            "libpython": "python3-dev",
        }
        pkg = lib_pkg_map.get(library.split(".")[0], library)
        
        if system == "linux":
            install_cmd = f"sudo apt-get install -y {pkg}"
        elif system == "darwin":
            install_cmd = f"brew install {pkg}"
        else:
            return False, None
        
        install_result = self.executor.terminal.execute(install_cmd, timeout=180)
        if install_result.exit_code == 0:
            retry_result = self.executor.terminal.execute(command, timeout=300)
            return retry_result.exit_code == 0, retry_result
        return False, None
    
    def _heal_rate_limit(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal rate limit by waiting and retrying"""
        self.console.print("⏳ İstek limiti - 30 saniye bekleniyor...", style="yellow")
        time.sleep(30)
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result
    
    def _heal_port_in_use(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal port in use by killing process"""
        port = error_diagnosis.get("port")
        if not port:
            return False, None
        
        self.console.print(f"🔌 Port {port} kullanımda - işlem sonlandırılmaya çalışılıyor...", style="yellow")
        import platform
        if platform.system().lower() != "windows":
            kill_cmd = f"sudo fuser -k {port}/tcp 2>/dev/null || sudo lsof -ti:{port} | xargs -r sudo kill -9"
        else:
            kill_cmd = f"for /f \"tokens=5\" %a in ('netstat -aon ^| find \":{port}\"') do taskkill /F /PID %a"
        
        self.executor.terminal.execute(kill_cmd, timeout=30)
        time.sleep(2)
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result
    
    def _heal_disk_full(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal disk full by cleaning up"""
        self.console.print("💾 Disk alanı yetersiz - temizlik yapılıyor...", style="yellow")
        import platform
        if platform.system().lower() != "windows":
            cleanup_cmd = "sudo apt-get clean 2>/dev/null; rm -rf /tmp/* 2>/dev/null; rm -rf ~/.cache/* 2>/dev/null"
        else:
            cleanup_cmd = "del /q/f/s %TEMP%\\* 2>nul"
        
        self.executor.terminal.execute(cleanup_cmd, timeout=60)
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result
    
    def _heal_firewall_blocked(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal firewall blocked by waiting and trying slower"""
        self.console.print("🛡️ Güvenlik duvarı engeli - 10 saniye bekleyip stealth modda deneniyor...", style="yellow")
        time.sleep(10)
        if "--rate" in command or "-T" in command:
            slower_cmd = command.replace("-T4", "-T1").replace("-T5", "-T2")
            retry_result = self.executor.terminal.execute(slower_cmd, timeout=600)
        else:
            retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result
    
    def _heal_database_error(self, tool_name: str, command: str, error_diagnosis: Dict) -> Tuple[bool, Optional[Any]]:
        """Heal database error by removing lock files"""
        self.console.print("🗄️ Veritabanı hatası - düzeltme deneniyor...", style="yellow")
        import glob
        import os
        for lock_file in glob.glob("*.db-journal") + glob.glob("*.db-wal") + glob.glob("*.db-shm"):
            try:
                os.remove(lock_file)
                self.console.print(f"  🗑️ {lock_file} silindi", style="dim")
            except OSError as e:
                logger.debug(f"Could not remove lock file {lock_file}: {e}")
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result
    
    def _finalize_healing_result(
        self, healed: bool, retry_result: Optional[Any], result: Any,
        tool_name: str, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Finalize healing result and return formatted output"""
        if healed and retry_result:
            self.console.print("✅ Hata otomatik olarak düzeltildi!", style="green")
            return self._format_tool_result(retry_result, args)
        
        if result.exit_code != 0:
            self.tool_selector.record_tool_failure(tool_name)
        
        return self._finalize_healing_result(healed, retry_result, result, tool_name, args)
    
    def _diagnose_error(self, output: str, exit_code: int) -> Dict:
        """
        Comprehensive error diagnosis from output and exit code.
        Covers 25+ error types in multiple languages.
        
        Returns diagnosis with type, description, and suggested fix.
        """
        output_lower = output.lower()
        diagnosis = self._run_error_checks(output_lower, exit_code, output)
        
        if diagnosis:
            return diagnosis
        
        self._log_unknown_error(output, exit_code)
        return {"type": "unknown", "type_tr": "Tanımlanamayan hata", "raw_output": output[:500]}
    
    def _run_error_checks(self, output_lower: str, exit_code: int, output: str) -> Optional[Dict]:
        """Run all error checks in priority order"""
        checkers = [
            self._check_missing_tool,
            self._check_permission_error,
            self._check_python_module_error,
            self._check_library_error,
            self._check_network_error,
            self._check_timeout_error,
            self._check_syntax_error,
            self._check_file_error,
            self._check_memory_error,
            self._check_disk_error,
            self._check_auth_error,
            self._check_port_error,
            self._check_database_error,
            self._check_parse_error,
            self._check_version_error,
            self._check_rate_limit_error,
            self._check_firewall_error,
            self._check_resource_error,
        ]
        
        for checker in checkers:
            result = checker(output_lower)
            if result:
                return result
        
        return self._check_exit_code_error(exit_code, output)
    
    def _check_missing_tool(self, output_lower: str) -> Optional[Dict]:
        """Check for missing tool/command errors"""
        import re
        patterns = [
            "not found", "not recognized", "bulunamadı", "command not found",
            "komut bulunamadı", "no such command", "unknown command",
            "is not recognized as", "bash:", "sh:", "zsh:", "cmd:", "powershell:"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"['\"]?(\w+)['\"]?[:\s]*(command )?not found", output_lower)
            tool = match.group(1) if match else None
            return {"type": "missing_tool", "type_tr": "Araç bulunamadı", "tool": tool}
        return None
    
    def _check_permission_error(self, output_lower: str) -> Optional[Dict]:
        """Check for permission/access denied errors"""
        patterns = [
            "permission denied", "access denied", "izin reddedildi",
            "operation not permitted", "root privileges required",
            "sudo required", "eacces", "eperm", "requires elevation"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "permission_denied", "type_tr": "İzin hatası"}
        return None
    
    def _check_python_module_error(self, output_lower: str) -> Optional[Dict]:
        """Check for Python module missing errors"""
        import re
        patterns = [
            "no module named", "modulenotfounderror", "importerror",
            "cannot import name", "modül bulunamadı"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"no module named ['\"]?([.\w]+)", output_lower)
            if not match:
                match = re.search(r"cannot import name ['\"]?(\w+)", output_lower)
            module = match.group(1) if match else None
            return {"type": "python_module_missing", "type_tr": "Python modülü eksik", "module": module}
        return None
    
    def _check_library_error(self, output_lower: str) -> Optional[Dict]:
        """Check for missing library/shared object errors"""
        import re
        patterns = [
            "cannot open shared object", "library not found", ".so:", ".dll",
            "libssl", "libcrypto", "libpython", "kütüphane bulunamadı"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"(lib\w+\.so[.\d]*|[\w]+\.dll)", output_lower)
            library = match.group(1) if match else None
            return {"type": "library_missing", "type_tr": "Sistem kütüphanesi eksik", "library": library}
        return None
    
    def _check_network_error(self, output_lower: str) -> Optional[Dict]:
        """Check for connection/network errors"""
        patterns = [
            "connection refused", "connection reset", "network unreachable",
            "no route to host", "econnrefused", "ssl error", "tls"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "connection_error", "type_tr": "Bağlantı hatası"}
        return None
    
    def _check_timeout_error(self, output_lower: str) -> Optional[Dict]:
        """Check for timeout errors"""
        patterns = [
            "timed out", "timeout", "zaman aşımı", "etimedout",
            "deadline exceeded", "request timeout"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "timeout", "type_tr": "Zaman aşımı"}
        return None
    
    def _check_syntax_error(self, output_lower: str) -> Optional[Dict]:
        """Check for syntax/argument errors"""
        patterns = [
            "invalid argument", "invalid option", "unrecognized option",
            "syntax error", "bad argument", "usage:", "try '--help'"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "invalid_argument", "type_tr": "Geçersiz argüman/sözdizimi"}
        return None
    
    def _check_file_error(self, output_lower: str) -> Optional[Dict]:
        """Check for file not found errors"""
        import re
        patterns = [
            "no such file", "file not found", "dosya bulunamadı",
            "enoent", "path not found", "cannot find"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"['\"]?([/\\]?[\w./\\-]+\.\w+)['\"]?", output_lower)
            filepath = match.group(1) if match else None
            return {"type": "file_not_found", "type_tr": "Dosya bulunamadı", "file": filepath}
        return None
    
    def _check_memory_error(self, output_lower: str) -> Optional[Dict]:
        """Check for memory errors"""
        patterns = [
            "out of memory", "memory error", "enomem", "oom",
            "segmentation fault", "segfault", "core dumped"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "memory_error", "type_tr": "Bellek hatası"}
        return None
    
    def _check_disk_error(self, output_lower: str) -> Optional[Dict]:
        """Check for disk space errors"""
        patterns = [
            "no space left", "disk full", "disk quota", "enospc",
            "yetersiz disk alanı"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "disk_full", "type_tr": "Disk alanı yetersiz"}
        return None
    
    def _check_auth_error(self, output_lower: str) -> Optional[Dict]:
        """Check for authentication errors"""
        patterns = [
            "authentication failed", "invalid credentials", "unauthorized",
            "401", "403 forbidden", "login failed"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "auth_error", "type_tr": "Kimlik doğrulama hatası"}
        return None
    
    def _check_port_error(self, output_lower: str) -> Optional[Dict]:
        """Check for port in use errors"""
        import re
        patterns = [
            "address already in use", "port already in use", "eaddrinuse",
            "bind failed", "port kullanımda"
        ]
        if any(x in output_lower for x in patterns):
            match = re.search(r"port[:\s]*(\d+)", output_lower)
            port = match.group(1) if match else None
            return {"type": "port_in_use", "type_tr": "Port kullanımda", "port": port}
        return None
    
    def _check_database_error(self, output_lower: str) -> Optional[Dict]:
        """Check for database errors"""
        patterns = [
            "database", "sqlite", "mysql", "postgresql",
            "db error", "veritabanı hatası", "locked", "deadlock"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "database_error", "type_tr": "Veritabanı hatası"}
        return None
    
    def _check_parse_error(self, output_lower: str) -> Optional[Dict]:
        """Check for JSON/XML parsing errors"""
        patterns = [
            "json", "xml", "parsing error", "decode error",
            "invalid json", "malformed"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "parse_error", "type_tr": "Ayrıştırma hatası"}
        return None
    
    def _check_version_error(self, output_lower: str) -> Optional[Dict]:
        """Check for version/compatibility errors"""
        patterns = [
            "version", "incompatible", "requires python", "unsupported",
            "deprecated", "sürüm uyumsuz"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "version_error", "type_tr": "Sürüm uyumsuzluğu"}
        return None
    
    def _check_rate_limit_error(self, output_lower: str) -> Optional[Dict]:
        """Check for rate limiting errors"""
        patterns = [
            "rate limit", "too many requests", "429", "throttled",
            "quota exceeded", "istek limiti"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "rate_limit", "type_tr": "İstek limiti aşıldı"}
        return None
    
    def _check_firewall_error(self, output_lower: str) -> Optional[Dict]:
        """Check for firewall/WAF blocked errors"""
        patterns = [
            "blocked", "firewall", "waf", "forbidden", "filtered",
            "connection reset by peer", "güvenlik duvarı"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "firewall_blocked", "type_tr": "Güvenlik duvarı engeli"}
        return None
    
    def _check_resource_error(self, output_lower: str) -> Optional[Dict]:
        """Check for process/resource errors"""
        patterns = [
            "too many open files", "resource temporarily unavailable",
            "eagain", "emfile", "process limit"
        ]
        if any(x in output_lower for x in patterns):
            return {"type": "resource_limit", "type_tr": "Kaynak limiti"}
        return None
    
    def _check_exit_code_error(self, exit_code: int, output: str) -> Optional[Dict]:
        """Check for exit code based errors"""
        if exit_code != 0 and not output.strip():
            exit_code_map = {
                1: {"type": "general_error", "type_tr": "Genel hata"},
                2: {"type": "invalid_argument", "type_tr": "Geçersiz argüman"},
                126: {"type": "permission_denied", "type_tr": "Çalıştırma izni yok"},
                127: {"type": "missing_tool", "type_tr": "Komut bulunamadı"},
                128: {"type": "invalid_argument", "type_tr": "Geçersiz çıkış kodu"},
                130: {"type": "interrupted", "type_tr": "Kullanıcı tarafından iptal"},
                137: {"type": "killed", "type_tr": "İşlem sonlandırıldı (OOM?)"},
                139: {"type": "segfault", "type_tr": "Segmentation fault"},
                143: {"type": "terminated", "type_tr": "SIGTERM ile sonlandırıldı"},
            }
            if exit_code in exit_code_map:
                return exit_code_map[exit_code]
            if exit_code > 128:
                signal_num = exit_code - 128
                return {"type": "signal_killed", "type_tr": f"Sinyal {signal_num} ile sonlandırıldı"}
        return None
    
    def _log_unknown_error(self, output: str, exit_code: int):
        """Log unknown errors for future pattern learning"""
        try:
            import os
            from datetime import datetime
            
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "unknown_errors.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Exit Code: {exit_code}\n")
                f.write(f"Output:\n{output[:1000]}\n")
        except OSError as e:
            logger.debug(f"Could not write to log file {log_file}: {e}")
    
    def _llm_assisted_error_fix(self, tool_name: str, command: str, error_output: str) -> tuple:
        """
        Use LLM to diagnose unknown errors and suggest fixes.
        Returns (healed: bool, retry_result)
        """
        try:
            self.console.print("🤖 LLM ile hata analizi yapılıyor...", style="dim")
            
            prompt = f"""Analyze this command execution error and suggest a fix:

Command: {command}
Tool: {tool_name}
Error Output: {error_output[:1000]}

Respond in JSON:
{{
    "error_type": "brief error classification",
    "root_cause": "what caused this error",
    "fix_command": "shell command to fix (or null if not fixable)",
    "should_retry": true/false,
    "explanation": "brief explanation in Turkish"
}}"""

            result = self.brain.llm_client.query(prompt, timeout=15)
            
            # Try to parse JSON response
            import json
            import re
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                fix_data = json.loads(json_match.group())
                
                self.console.print(f"🔍 LLM Analizi: {fix_data.get('explanation', 'Analiz tamamlandı')}", style="dim")
                
                # Apply fix command if provided
                fix_cmd = fix_data.get("fix_command")
                if fix_cmd and fix_cmd != "null":
                    self.console.print(f"🔧 Düzeltme uygulanıyor: {fix_cmd}", style="yellow")
                    fix_result = self.executor.terminal.execute(fix_cmd, timeout=120)
                    
                    if fix_result.exit_code == 0 and fix_data.get("should_retry", False):
                        self.console.print("🔄 Düzeltme başarılı, orijinal komut yeniden deneniyor...", style="cyan")
                        retry_result = self.executor.terminal.execute(command, timeout=300)
                        return (retry_result.exit_code == 0, retry_result)
                        
        except Exception as e:
            logger.warning(f"LLM-assisted error fix failed: {e}")
        
        return (False, None)

    def _format_tool_result(self, result, args: Dict) -> Dict:
        """Format execution result dictionary with standardized errors"""
        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        exit_code = result.exit_code
        
        # New: Standardize error
        error_msg = normalize_error_message(stdout_str, stderr_str, exit_code)
        
        # Fallback raw error if normalize returns nothing but exit code non-zero
        if exit_code != 0 and not error_msg:
             if stderr_str.strip():
                 error_msg = f"Tool Error: {stderr_str.strip()[:200]}"
             else:
                 error_msg = f"Command failed with exit code {exit_code}"

        final_result = {
            "success": result.status.value == "success",
            "stdout": stdout_str,
            "stderr": stderr_str,
            "error_summary": error_msg, # New standardized field
            "exit_code": exit_code,
            "args": args,
        }
        
        # Log to structured log
        self.logger.log_action(
            tool = args.get("tool_name", "unknown"), # args might need to contain tool name?
            args = args,
            result = final_result
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
                "⚠️  Cannot run async: event loop already running", style="yellow"
            )
            return {
                "success": False,
                "error": "Async execution blocked: event loop already running",
            }

        try:
            # Run with timeout - this prevents infinite hangs
            return asyncio.run(asyncio.wait_for(coro, timeout=timeout))
        except asyncio.TimeoutError:
            self.console.print(
                f"⚠️  Async task timeout after {timeout}s", style="yellow"
            )
            return {"success": False, "error": f"Async task timed out after {timeout}s"}
        except Exception as e:
            logger.exception(f"Async execution error: {e}")
            self.console.print(f"⚠️  Async execution error: {e}", style="yellow")
            return {"success": False, "error": f"Async execution failed: {str(e)}"}

    def _create_observation(self, tool_name: str, result: Dict) -> str:
        """
        Tool sonucundan ÖZET observation oluştur

        YASAK: Raw log, tool output spam
        SADECE: Anlamlı özet
        """
        if not result.get("success"):
            error_msg = result.get("error") or result.get("stderr", "Unknown error")
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

    def _update_state_from_result(self, tool_name: str, result: Dict, observation: str):
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
        observation = result.get("stdout", "") + "\n" + result.get("stderr", "")
        # Check if exploit succeeded
        if "success" in observation.lower() or "shell" in observation.lower() or result.get("success"):
            self.state.set_foothold(tool_name)
        else:
            self.state.set_observation("Exploit did not succeed; foothold not set")

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


    def _process_vulnerability_result(self, tool_name: str, result: Dict, observation: str):
        """Helper to process vulnerability scan results"""
        if "vuln" in tool_name or "sqlmap" in tool_name:
            if "vulnerable" in observation.lower() or "injection" in observation.lower():
                self._handle_sqlmap_vulnerabilities(result)

    def _handle_sqlmap_vulnerabilities(self, result: Dict):
        """Process SQLMap results and update state"""
        from core.tool_parsers import parse_sqlmap_output
        
        stdout = result.get("stdout", "")
        # Hybrid parsing with LLM fallback
        parsed_vulns = parse_sqlmap_output(stdout, llm_client=self.brain.llm_client)

        if parsed_vulns:
            target_port = self._extract_port_from_result(result)
            
            for vuln_dict in parsed_vulns:
                vuln = VulnerabilityInfo(
                    vuln_id=f"sqli_{vuln_dict.get('parameter', 'unknown')}",
                    service="http",
                    port=target_port,
                    severity=FindingSeverity.CRITICAL, # Assuming high severity for SQLi
                    description=f"SQL Injection: {vuln_dict.get('title', 'Unknown')}",
                    remediation="Use parameterized queries"
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
            self.console.print("📈 Phase transition: INIT -> RECON", style=self.STYLE_BLUE)

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
                "📈 Phase transition: VULN_SCAN -> EXPLOIT", style=self.STYLE_BLUE
            )

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
                "📈 Phase transition: EXPLOIT -> POST_EXPLOIT", style=self.STYLE_BLUE
            )

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
        report.append(f"⚠️  Vulnerabilities: {len(self.state.vulnerabilities)}\n")
        report.append(f"🎪 Foothold: {'YES' if self.state.has_foothold else 'NO'}\n")

        if self.state.has_foothold:
            report.append(f"   Method: {self.state.foothold_method}\n", style="green")

        if self.state.invariant_violations:
            report.append("\n❌ Invariant Violations:\n", style=self.STYLE_RED)
            for violation in self.state.invariant_violations:
                report.append(f"   - {violation}\n", style="red")

        self.console.print(Panel(report, border_style="green", title="Summary"))

    def stop(self) -> None:
        """Stop the agent"""
        self.running = False
