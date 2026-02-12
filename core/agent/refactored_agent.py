# core/refactored_agent.py
# DRAKBEN SELF-REFINING EVOLVING AGENT
# PROFILE-BASED EVOLUTION + POLICY CONFLICT RESOLUTION + META-LEARNING

import json
import logging
import threading
import time
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.agent.brain import DrakbenBrain
from core.agent.error_diagnostics import ErrorDiagnosticsMixin
from core.agent.planner import Planner, PlanStep, StepStatus
from core.agent.ra_state_updates import RAStateUpdatesMixin
from core.agent.ra_tool_executors import RAToolExecutorsMixin
from core.agent.ra_tool_recovery import RAToolRecoveryMixin
from core.agent.recovery.healer import SelfHealer
from core.agent.state import AgentState, AttackPhase, reset_state
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
from core.ui.transparency import get_transparency

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)

# Error message constants (SonarCloud compliance)
_ERR_UNKNOWN = "Unknown error"


class RefactoredDrakbenAgent(
    ErrorDiagnosticsMixin,
    RAToolExecutorsMixin,
    RAToolRecoveryMixin,
    RAStateUpdatesMixin,
):
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

    # Track self-healing attempts to prevent infinite loops
    MAX_SELF_HEAL_PER_TOOL = 2  # Maximum self-heal attempts per tool per session

    def __init__(self, config_manager: ConfigManager) -> None:
        self.config: ConfigManager = config_manager
        self.console = Console()
        self.transparency = get_transparency(self.console)
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
        self._self_heal_attempts: dict[str, int] = {}  # Instance-level heal tracking

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
            self._check_tool_availability()
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
            self.console.print(f"⚠️  Database error: {e}", style="yellow")
            self.console.print(
                "⚠️  Switching to fallback mode (limited functionality)",
                style="yellow",
            )
            self._fallback_mode = True

    def _check_tool_availability(self) -> None:
        """Check which pentest tools are installed and warn user about missing ones."""
        import shutil

        required_tools = {
            "nmap": "Port scanning (critical)",
            "nikto": "Web vulnerability scanning",
            "sqlmap": "SQL injection testing",
            "searchsploit": "Exploit search",
            "hydra": "Credential brute-forcing",
            "metasploit-framework": "Exploitation framework",
        }
        # Metasploit is detected via msfconsole binary
        binary_map = {
            "metasploit-framework": "msfconsole",
        }

        found: list[str] = []
        missing: list[str] = []

        for tool, desc in required_tools.items():
            binary = binary_map.get(tool, tool)
            if shutil.which(binary):
                found.append(tool)
            else:
                missing.append(f"{tool} ({desc})")

        if found:
            self.console.print(
                f"✅ Tools available: {', '.join(found)}",
                style="green",
            )

        if missing:
            self.console.print(
                f"⚠️  Missing tools: {', '.join(missing)}",
                style="yellow",
            )
            self.console.print(
                "   [dim]Install with: apt install <tool> or use /install command[/dim]",
            )

    def _setup_scan_mode(self, mode: str, target: str) -> None:
        """Setup scan mode and display initialization message."""
        self._scan_mode: str = mode.lower() if mode else "auto"
        mode_label: str = {
            "stealth": "🥷 STEALTH (Sessiz)",
            "aggressive": "⚡ AGGRESSIVE (Hızlı)",
            "auto": "🤖 AUTO",
        }.get(self._scan_mode, "🤖 AUTO")
        self.console.print(
            f"🔄 Initializing agent for target: {target} [{mode_label}]",
            style=self.STYLE_BLUE,
        )

    def _reset_and_evolve_state(self, target: str) -> None:
        """Reset state and evolve tool priorities."""
        self.state = reset_state(target)
        self.state.phase = AttackPhase.INIT
        try:
            self.tool_selector.evolve_strategies(self.evolution)
        except Exception as e:
            self.console.print(f"⚠️  Tool evolution skipped: {e}", style="yellow")

    def _classify_target(self, target: str) -> str:
        """Classify target and set signature."""
        target_type: str = self.refining_engine.classify_target(target)
        self.target_signature = self.refining_engine.get_target_signature(target)
        self.console.print(f"🎯 Target Classification: {target_type}", style="cyan")
        self.console.print(f"🔑 Target Signature: {self.target_signature}", style="dim")
        return target_type

    def _select_and_filter_profile(self, target: str) -> bool:
        """Select strategy/profile and apply mode-based filtering. Returns False if failed."""
        try:
            self.current_strategy, self.current_profile = (
                self.refining_engine.select_strategy_and_profile(target)
            )
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
            "🥷 Stealth mode: Searching for low-aggression profile...",
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
            try:
                agg = float(self.current_profile.aggressiveness)
            except (TypeError, ValueError):
                agg = 0.0
            self.console.print(
                f"🥷 Switched to stealth profile (aggression: {agg:.2f})",
                style="green",
            )

    def _switch_to_aggressive_profile(self) -> None:
        """Switch to high-aggression profile for aggressive mode."""
        self.console.print(
            "⚡ Aggressive mode: Searching for high-aggression profile...",
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
            try:
                agg = float(self.current_profile.aggressiveness)
            except (TypeError, ValueError):
                agg = 0.0
            self.console.print(
                f"⚡ Switched to aggressive profile (aggression: {agg:.2f})",
                style="yellow",
            )

    def _display_selected_profile(self) -> None:
        """Display selected strategy and profile information."""
        if not self.current_strategy or not self.current_profile:
            self.console.print("⚠️ No strategy/profile active.", style="yellow")
            return

        self.console.print(
            f"🧠 Selected Strategy: {self.current_strategy.name}",
            style=self.STYLE_MAGENTA,
        )
        try:
            sr = float(self.current_profile.success_rate)
            agg = float(self.current_profile.aggressiveness)
        except (TypeError, ValueError):
            sr, agg = 0.0, 0.0
        self.console.print(
            f"🎭 Selected Profile: {self.current_profile.profile_id[:12]}... "
            f"(gen: {self.current_profile.mutation_generation}, "
            f"success_rate: {sr:.1%}, "
            f"aggression: {agg:.2f})",
            style=self.STYLE_CYAN,
        )
        self.console.print(
            f"   📋 Step Order: {self.current_profile.step_order}",
            style="dim",
        )
        self.console.print(
            f"   ⚙️  Parameters: {json.dumps(self.current_profile.parameters)}",
            style="dim",
        )

    def _create_or_load_plan(self, target: str) -> None:
        """Create new plan or load existing plan."""
        existing_plan: PlanRecord | None = self.evolution.get_active_plan(
            f"pentest_{target}",
        )
        if existing_plan:
            self.console.print(
                f"🔁 Resuming plan: {existing_plan.plan_id}",
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
                f"📋 Created plan from profile: {plan_id}",
                style=self.STYLE_GREEN,
            )

    def _show_evolution_info(self, target_type: str) -> None:
        """Show evolution status and applicable policies."""
        try:
            status = self.refining_engine.get_evolution_status()
            self.console.print(
                f"🧬 Evolution Status: {status['active_policies']} policies, "
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
                    f"📜 Active Policies: {len(policies)}",
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
                f"❌ Critical error during initialization: {e}",
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

        # Show LLM connection status so user knows what to expect
        llm_client = getattr(self.brain, "llm_client", None)
        if llm_client:
            model = getattr(llm_client, "model", "unknown")
            provider = getattr(llm_client, "provider", "unknown")
            self.console.print(
                f"   [bold green]🤖 LLM: {provider} / {model}[/bold green]",
            )
        else:
            self.console.print(
                "   [yellow]⚠️  LLM: Offline mode (rule-based analysis)[/yellow]",
            )
            self.console.print(
                "   [dim]Tip: /llm komutuyla AI bağlantısı kurun[/dim]",
            )

        self.console.print(
            "   [dim]Tip: Press Ctrl+C to stop[/dim]\n",
        )

        if not self.state:
            self.console.print("❌ FATAL: State not initialized.", style=self.STYLE_RED)
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

        # Status dashboard for transparency
        phase_name = self.state.phase.value.upper()
        n_services = len(self.state.open_services)
        n_vulns = len(self.state.vulnerabilities)
        foothold = "✅" if self.state.has_foothold else "—"
        self.console.print(
            f"   📍 Phase: {phase_name} | Services: {n_services} | Vulns: {n_vulns} | Foothold: {foothold}",
            style="dim",
        )

        # 1. Stagnation Check
        if self._check_stagnation():
            return False

        # 2. Get Next Step
        step: PlanStep | None = self.planner.get_next_step()
        if not step:
            should_continue = self._handle_plan_completion()
            if not should_continue:
                return False
            # Replan happened — increment iteration and try again next loop
            if self.state:
                self.state.increment_iteration()
            return True

        self.console.print(
            f"[*] Step: {step.step_id} | Action: {step.action} | Tool: {step.tool}",
            style="cyan",
        )

        # Show WHY this tool was chosen (transparency)
        target = self.state.target if self.state else "global"
        penalty: float = self.evolution.get_tool_penalty(step.tool, target)
        step_reason = self._build_tool_reason(step)
        profile_info = "default"
        if self.current_profile:
            try:
                pid = str(self.current_profile.profile_id)[:12]
                agg = float(self.current_profile.aggressiveness)
                profile_info = f"{pid}... (aggression: {agg:.2f})"
            except (TypeError, ValueError):
                profile_info = str(self.current_profile.profile_id)[:20]
        self.transparency.show_tool_reasoning(
            tool_name=step.tool,
            action=step.action,
            reason=step_reason,
            penalty=penalty,
            profile_info=profile_info,
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

        # ── APPROVAL CHECK for dangerous operations ──
        if not self._check_dangerous_operation(step):
            # User denied — skip this step, continue with next
            if self.state is not None:
                self.state.increment_iteration()
            return True

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
            # LLM Analysis of output (transparency)
            self._analyze_and_show_output(step.tool, execution_result)
        elif not self._handle_step_failure(step, execution_result):
            return False

        # 7. Update State
        observation: str = f"{step.tool}: {'success' if success else 'failed'}"
        self._update_state_from_result(step.tool, execution_result, observation)

        # 8. Validation & Halt Limit
        if not self._validate_loop_state():
            return False

        if self.state is None:

            raise AssertionError(self.MSG_STATE_NOT_NONE)
        self.state.increment_iteration()
        return True

    def _build_tool_reason(self, step: PlanStep) -> str:
        """Build a human-readable reason for why this tool was selected."""
        reasons: list[str] = []

        # Phase-based reasoning
        if self.state:
            phase = self.state.phase.value
            if "port_scan" in step.tool:
                reasons.append(f"Phase is {phase} — need to discover open ports first")
            elif "service" in step.tool or "nikto" in step.tool:
                n_ports = len(self.state.open_services)
                reasons.append(f"{n_ports} ports found — identifying services/vulnerabilities")
            elif "vuln" in step.tool or "sqlmap" in step.tool:
                reasons.append("Services identified — scanning for vulnerabilities")
            elif "exploit" in step.tool:
                n_vulns = len(self.state.vulnerabilities)
                reasons.append(f"{n_vulns} vulnerabilities found — attempting exploitation")
            else:
                reasons.append(f"Step from profile plan for {phase} phase")

        # Profile-based reasoning
        if self.current_profile:
            reasons.append(
                f"Profile step_order: {self.current_profile.step_order[:60]}...",
            )

        # Expected outcome
        if hasattr(step, "expected_outcome") and step.expected_outcome:
            reasons.append(f"Expected: {step.expected_outcome}")

        return " | ".join(reasons) if reasons else "Automatic selection from plan"

    def _analyze_and_show_output(self, tool_name: str, execution_result: dict) -> None:
        """Ask the LLM to analyze tool output and show the analysis to the user."""
        stdout = execution_result.get("stdout", "")
        if not stdout or not stdout.strip():
            return

        llm_client = getattr(self.brain, "llm_client", None)

        # LLM-powered analysis
        if llm_client:
            self._analyze_with_llm_transparency(tool_name, stdout, llm_client)
            return

        # Offline: rule-based analysis so user still sees SOMETHING
        self._analyze_offline(tool_name, stdout)

    # ── Dangerous operation categories requiring user approval ──
    _DANGEROUS_ACTIONS: set[str] = {
        "exploit", "get_shell", "brute_force", "credential_test",
        "data_exfil", "sqlmap_exploit", "execute_exploit",
    }
    _DANGEROUS_TOOLS: set[str] = {
        "sqlmap_scan", "hydra", "metasploit_exploit", "john",
        "hashcat", "generate_payload", "data_exfil",
    }

    def _check_dangerous_operation(self, step: PlanStep) -> bool:
        """Check if a step requires user approval before execution.

        Exploit, shell access, brute-force, and data exfiltration steps
        are considered dangerous. The user is prompted with a Y/n question.
        If the scan is running non-interactively the step is auto-approved
        (same behaviour as OpenInterpreter's auto_run=True).

        Returns:
            True if approved (proceed), False if denied (skip).
        """
        is_dangerous = (
            step.action in self._DANGEROUS_ACTIONS
            or step.tool in self._DANGEROUS_TOOLS
        )
        if not is_dangerous:
            return True  # safe — auto-approve

        risk_level = "HIGH" if step.action in ("exploit", "get_shell", "data_exfil") else "MEDIUM"

        # Auto-approve if configured (equivalent to auto_run=True)
        auto_approve = getattr(self.config, "auto_approve_dangerous", False)
        if auto_approve:
            self.transparency.show_approval_request(
                step.tool, step.action, risk_level, approved=True,
            )
            return True

        # Interactive approval
        self.console.print()
        self.console.print(
            Panel(
                f"[bold red]\u26a0\ufe0f  DANGEROUS OPERATION[/]\n\n"
                f"Tool: [bold cyan]{step.tool}[/]\n"
                f"Action: {step.action}\n"
                f"Target: {step.target}\n"
                f"Risk: [bold red]{risk_level}[/]",
                title="\ud83d\udee1\ufe0f Approval Required",
                border_style="bright_red",
            ),
        )

        try:
            answer = input("\n  Devam edilsin mi? / Proceed? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        approved = answer in ("", "y", "yes", "e", "evet")
        self.transparency.show_approval_request(
            step.tool, step.action, risk_level, approved=approved,
        )

        if not approved:
            self.console.print("   \u26d4 Skipped by user", style="dim")
            self.planner.mark_step_failed(step.step_id, "User denied approval")

        return approved

    def _analyze_with_llm_transparency(self, tool_name: str, stdout: str, llm_client: Any) -> None:
        """LLM-powered output analysis that feeds suggestions back into the planner.

        This is the core "LLM-in-the-loop" mechanism:
        1. Send tool output to LLM for analysis
        2. Parse structured response (findings, severity, suggested next steps)
        3. Inject any suggested next steps into the live plan via planner
        4. Show everything transparently to the user
        """
        try:
            target = self.state.target if self.state else "N/A"
            phase = self.state.phase.value if self.state else "unknown"
            n_services = len(self.state.open_services) if self.state else 0
            n_vulns = len(self.state.vulnerabilities) if self.state else 0

            prompt = (
                f"You are DRAKBEN's analysis engine. Analyze this {tool_name} output "
                f"for target {target} (phase: {phase}, {n_services} services, {n_vulns} vulns).\n\n"
                f"OUTPUT:\n{stdout[:4000]}\n\n"
                f"Respond ONLY in JSON:\n"
                f'{{"findings": ["finding1", ...], '
                f'"summary": "2-3 sentence technical analysis", '
                f'"severity": "info|low|medium|high|critical", '
                f'"next_steps": ['
                f'  {{"action": "action_name", "tool": "tool_name", "reason": "why"}}'
                f']}}\n\n'
                f"next_steps should recommend concrete follow-up scans based on what "
                f"was discovered (e.g., web port open -> nikto, SMB -> enum4linux). "
                f"Return empty list if no further action needed."
            )

            t0 = time.time()
            response = llm_client.query(prompt, timeout=25)
            duration = time.time() - t0

            # Show the LLM thinking
            self.transparency.show_llm_thinking(
                prompt_summary=f"Analyze {tool_name} output ({len(stdout)} chars)",
                response=response[:500],
                duration=duration,
            )

            # Parse structured response
            analysis = self._parse_llm_json(response)
            self.transparency.show_output_analysis(tool_name, analysis)

            # ── KEY: Feed LLM suggestions back into the plan ──
            next_steps = analysis.get("next_steps") or []
            # Support legacy "next_action" single string field too
            if not next_steps and analysis.get("next_action"):
                next_steps = [{"action": analysis["next_action"], "tool": analysis["next_action"]}]

            if next_steps and self.state:
                n_injected = self.planner.inject_dynamic_steps(
                    new_actions=next_steps,
                    target=self.state.target or target,
                    source="llm",
                )
                if n_injected > 0:
                    self.transparency.show_plan_injection(next_steps[:n_injected], source="llm")
                    self.console.print(
                        f"   \ud83e\udde0 LLM injected {n_injected} new step(s) into plan",
                        style="bold magenta",
                    )

        except Exception as e:
            logger.debug("LLM analysis failed, falling back to offline: %s", e)
            self._analyze_offline(tool_name, stdout)

    @staticmethod
    def _parse_llm_json(response: str) -> dict[str, Any]:
        """Extract JSON from LLM response, tolerating markdown fences."""
        import re as _re
        # Try ```json ... ``` block first (supports nested braces via DOTALL)
        m = _re.search(r"```(?:json)?\s*(\{.*\})\s*```", response, _re.DOTALL)
        text = m.group(1) if m else response
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find any JSON object in raw text
            m2 = _re.search(r"(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", response, _re.DOTALL)
            if m2:
                try:
                    return json.loads(m2.group(1))
                except json.JSONDecodeError:
                    pass
            return {"summary": response[:500], "findings": [], "severity": "info"}

    def _analyze_offline(self, tool_name: str, stdout: str) -> None:
        """Rule-based output analysis when LLM is unavailable."""
        findings: list[str] = []
        output_lower = stdout.lower()

        # Port/service detection
        import re
        port_lines = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", stdout)
        for port, svc in port_lines:
            findings.append(f"Port {port}/tcp open — {svc}")

        # Vulnerability markers
        vuln_findings, severity = self._extract_vuln_findings(stdout, output_lower)
        findings.extend(vuln_findings)

        # Service-specific suggestions → injectable steps
        next_action, offline_next_steps = self._determine_offline_next_steps(port_lines)

        if not findings:
            findings.append(f"{tool_name} tamamland\u0131 \u2014 {len(stdout)} karakter \u00e7\u0131kt\u0131")

        summary = f"{len(findings)} bulgu tespit edildi (offline analiz)"
        analysis = {
            "summary": summary,
            "findings": findings[:10],
            "severity": severity,
            "next_action": next_action,
        }
        self.transparency.show_output_analysis(tool_name, analysis)

        # Offline mode also injects steps into the plan (same as LLM path)
        self._inject_offline_steps(offline_next_steps)

    def _extract_vuln_findings(self, stdout: str, output_lower: str) -> tuple[list[str], str]:
        """Scan output for vulnerability markers and extract matching lines."""
        findings: list[str] = []
        severity = "info"
        vuln_markers = ["vulnerable", "cve-", "exploit", "injection", "xss", "rce"]
        for marker in vuln_markers:
            if marker in output_lower:
                severity = "high" if marker in ("exploit", "rce") else "medium"
                for line in stdout.splitlines():
                    if marker in line.lower() and len(line.strip()) > 5:
                        findings.append(line.strip()[:150])
                        break
        return findings, severity

    def _determine_offline_next_steps(
        self, port_lines: list[tuple[str, str]],
    ) -> tuple[str | None, list[dict[str, str]]]:
        """Determine next actions based on discovered ports."""
        if not port_lines:
            return None, []
        next_action: str | None = None
        steps: list[dict[str, str]] = []
        ports_found = {int(p) for p, _ in port_lines}
        if 80 in ports_found or 443 in ports_found:
            next_action = "nikto_web_scan"
            steps.append({"action": "web_vuln_scan", "tool": "nikto_web_scan", "reason": "HTTP port found"})
        elif 3306 in ports_found:
            next_action = "mysql_enum"
            steps.append({"action": "db_enum", "tool": "db_enum", "reason": "MySQL port 3306 open"})
        elif 445 in ports_found:
            next_action = "enum4linux"
            steps.append({"action": "smb_enum", "tool": "enum4linux", "reason": "SMB port 445 open"})
        return next_action, steps

    def _inject_offline_steps(self, offline_next_steps: list[dict[str, str]]) -> None:
        """Inject offline-discovered steps into the plan."""
        if not offline_next_steps or not self.state:
            return
        n_injected = self.planner.inject_dynamic_steps(
            new_actions=offline_next_steps,
            target=self.state.target or "",
            source="offline",
        )
        if n_injected > 0:
            self.transparency.show_plan_injection(offline_next_steps[:n_injected], source="offline")
            self.console.print(
                f"   \ud83d\udcdd Offline analysis injected {n_injected} step(s) into plan",
                style="yellow",
            )

    def _check_stagnation(self) -> bool:
        """Check for stagnation and triggering replan if needed. Returns True if halt required."""
        if self.evolution.detect_stagnation():
            self.console.print(
                "⚠️  STAGNATION DETECTED - forcing replan",
                style=self.STYLE_YELLOW,
            )
            current_step: PlanStep | None = self.planner.get_next_step()
            if current_step:
                self.planner.replan(current_step.step_id)
            self.stagnation_counter += 1

            if self.stagnation_counter >= 6:
                self.console.print(
                    "🛑 HALT: Too many stagnations",
                    style=self.STYLE_RED,
                )
                return True
        return False

    def _handle_plan_completion(self) -> bool:
        """Handle case where no steps are left. Returns True if agent should continue."""
        if self.planner.is_plan_complete():
            self.console.print("✅ Plan complete!", style=self.STYLE_GREEN)
            if self.state:
                self.state.phase = AttackPhase.COMPLETE
            self.running = False
            return False

        # Not complete but no executable step — try replan before giving up
        self.console.print("⚠️  No executable step found — attempting replan...", style="yellow")

        # Try replanning from the first pending/failed step
        replan_done = False
        for step in self.planner.steps:
            if step.status in (StepStatus.PENDING, StepStatus.FAILED):
                replan_done = self.planner.replan(step.step_id)
                break

        if replan_done:
            self.console.print("🔄 Replan successful — continuing scan", style="green")
            return True  # Continue scanning

        self.stagnation_counter += 1
        if self.stagnation_counter >= 6:
            self.console.print("🛑 Cannot continue — no viable steps remaining", style="red")
            self.running = False
            return False

        self.console.print(
            f"⏳ Waiting for dependencies to resolve (attempt {self.stagnation_counter}/6)",
            style="dim",
        )
        return True  # Let the loop continue to try again

    def _check_tool_blocked(self, step: PlanStep) -> bool:
        """Check if tool is blocked by evolution penalty (Per-Target)."""
        target = self.state.target if self.state else "global"
        penalty: float = self.evolution.get_tool_penalty(step.tool, target)
        if self.evolution.is_tool_blocked(step.tool, target):
            self.console.print(
                f"🚫 Tool {step.tool} is BLOCKED for {target} (penalty={penalty:.1f})",
                style=self.STYLE_RED,
            )
            # Trigger replan
            self.planner.replan(step.step_id)
            return True

        self.console.print(
            f"📊 Tool {step.tool} penalty for {target}: {penalty:.1f} / {self.evolution.BLOCK_THRESHOLD}",
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
        self.console.print("✅ Step succeeded", style="green")
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
        manager, and whether it succeeded — no silent force installs.
        """
        try:
            from core.intelligence.universal_adapter import get_universal_adapter
            adapter = get_universal_adapter()
            if not adapter:
                return False

            # Step 1: Tell the user what we're about to do
            self.console.print(
                f"\n   \ud83d\udce6 [bold yellow]Tool '{tool_name}' not found \u2014 attempting install...[/]",
            )

            # Step 2: Check if it's in the registry (known tool)
            from core.intelligence.universal_adapter import TOOL_REGISTRY
            tool_def = TOOL_REGISTRY.get(tool_name)
            if tool_def:
                pm = adapter.resolver.package_manager
                method = pm.value if pm else "auto"
                self.console.print(
                    f"   \ud83d\udce6 Install method: [cyan]{method}[/] ({tool_def.description})",
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
                    f"   \ud83d\udcac Install command: {proposal.get('install_cmd', '?')}",
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
        except Exception as e:
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
            import re as _re
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

        except Exception as e:
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

        # Priority 1: Tool missing → install
        if error_type == "tool_missing":
            self.console.print(
                f"\u26a0\ufe0f Tool '{step.tool}' missing, attempting install...",
                style=self.STYLE_YELLOW,
            )
            if self._attempt_tool_recovery(step.tool):
                self.planner.replan(step.step_id)
                return True
            self.console.print(f"\ud83d\uded1 CRITICAL: Tool '{step.tool}' irreparably missing.", style=self.STYLE_RED)
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
                    f"   \ud83e\udde0 LLM suggested {n_injected} recovery step(s)",
                    style="bold yellow",
                )
                return True

        # Priority 3: Record failure + pattern-based replan
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
                f"📚 Learned: avoid {step.tool} for {error_type} errors",
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
            strategy_name = self.current_strategy.name if self.current_strategy else "unknown"
            self.console.print(
                f"⚠️  Strategy '{strategy_name}' underperforming — switching to alternative...",
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
        self.console.print("🔄 Triggering replan...", style="yellow")
        replan_success: bool = self.planner.replan(step.step_id)

        if not replan_success:
            self.console.print(
                "📝 Replan failed - will select different profile next time",
                style="yellow",
            )

        # === SELF-CODING: If replan failed, try to create new tool ===
        if not replan_success and self.tools_created_this_session < 3:
            self.console.print(
                "🧠 No alternative tool found. Attempting to CREATE one...",
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
                    f"✨ Created new tool: {new_tool_name}",
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
                    f"⚠️  Could not create tool: {create_result.get('error')}",
                    style="yellow",
                )

    def _validate_loop_state(self) -> bool:
        """Validate state invariants and halt conditions."""
        if not self.state:
            return False

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

    def _get_deterministic_fallback(self) -> dict | None:
        """Get deterministic decision as fallback."""
        if not self.state:
            return None
        deterministic_decision = self.tool_selector.recommend_next_action(self.state)
        if deterministic_decision:
            _, tool_name, args = deterministic_decision
            self.console.print(f"✅ Deterministik karar: {tool_name}", style="dim")
            return {"tool": tool_name, "args": args}
        return None

    def _execute_tool_with_progress(self, tool_name: str, args: dict) -> dict:
        """Execute tool with progress indicator and timeout handling."""
        result_container: dict = {}
        execution_done = threading.Event()

        def run_execution():
            try:
                result_container["result"] = self._execute_tool(tool_name, args)
            except Exception as exc:
                result_container["result"] = {
                    "success": False,
                    "error": f"Thread exception: {exc}",
                    "args": args,
                }
            finally:
                execution_done.set()

        # Start execution in thread
        exec_thread = threading.Thread(target=run_execution, daemon=True)
        exec_thread.start()

        # Dynamic timeout based on tool type
        slow_tools = {"nmap_port_scan", "nmap_service_scan", "nmap_vuln_scan", "sqlmap_scan", "nikto_web_scan"}
        max_display_wait = 600 if tool_name in slow_tools else 180  # 10min for scanners, 3min for others
        feedback_interval = 30 if tool_name in slow_tools else 15
        wait_start = time.time()
        last_feedback = wait_start

        while not execution_done.is_set():
            elapsed = time.time() - wait_start

            # Periodic feedback to user
            if time.time() - last_feedback >= feedback_interval:
                self.console.print(
                    f"   [~] Running... ({int(elapsed)}s)",
                    style="dim",
                )
                last_feedback = time.time()

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
                    logger.warning(
                        "Tool %s timed out after %ss — daemon thread may still be running",
                        tool_name, int(elapsed),
                    )
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
        """Execute tool via Strategy Pattern dispatcher.

        Uses ToolDispatcher for O(1) dispatch instead of if/elif chains.
        Custom tool types can be registered at runtime.
        """
        if not hasattr(self, "_dispatcher"):
            from core.agent.tool_dispatch import ToolDispatcher
            self._dispatcher = ToolDispatcher(self)

        return self._dispatcher.dispatch(tool_name, args)

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

        # Security: Validate path is within project directory
        from pathlib import Path
        try:
            target_path = Path(target).resolve()
            project_root = Path.cwd().resolve()
            if not target_path.is_relative_to(project_root):
                return {
                    "success": False,
                    "error": "Security: File path outside project directory",
                }
        except (ValueError, OSError):
            return {"success": False, "error": "Invalid file path"}

        # Read file first
        try:
            with open(target_path) as f:
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
            # C-3 FIX: Verify syntax AND security before writing
            import ast

            from core.intelligence.coder import ASTSecurityChecker

            try:
                ast.parse(new_content)
            except SyntaxError:
                return {
                    "success": False,
                    "error": "Generated code had syntax errors. Change rejected.",
                }

            # Security check — block dangerous patterns
            checker = ASTSecurityChecker()
            violations = checker.check(new_content)
            if violations:
                return {
                    "success": False,
                    "error": f"Security check failed: {violations[:3]}",
                }

            try:
                with open(target_path, "w") as f:
                    f.write(new_content)
                return {
                    "success": True,
                    "output": f"File {target} modified successfully.",
                }
            except OSError as e:
                return {"success": False, "error": f"Write failed: {e}"}

        return {"success": False, "error": "No code generated"}

    def _enrich_tool_args(self, tool_name: str, tool_spec: "ToolSpec", args: dict) -> dict:
        """Auto-fill missing command template params from agent state.

        Resolves the common issue where plan steps have empty params but the
        command template requires {ports}, {port}, {url}, etc.
        """
        args = dict(args)  # Don't mutate original
        template = tool_spec.command_template or ""
        self._fill_ports_arg(template, args)
        self._fill_port_arg(template, args)
        self._fill_url_arg(template, args)
        return args

    def _fill_ports_arg(self, template: str, args: dict) -> None:
        """Auto-fill {ports} — comma-separated list of discovered open ports."""
        if "{ports}" not in template or "ports" in args:
            return
        if self.state and self.state.open_services:
            args["ports"] = ",".join(str(p) for p in sorted(self.state.open_services.keys()))
        else:
            args["ports"] = "1-1000"  # Fallback: scan common range

    def _fill_port_arg(self, template: str, args: dict) -> None:
        """Auto-fill {port} — single port (first open, or 80 fallback)."""
        if "{port}" not in template or "port" in args:
            return
        if self.state and self.state.open_services:
            for preferred in [80, 443, 8080, 8443]:
                if preferred in self.state.open_services:
                    args["port"] = str(preferred)
                    return
            args["port"] = str(next(iter(sorted(self.state.open_services.keys()))))
        else:
            args["port"] = "80"

    def _fill_url_arg(self, template: str, args: dict) -> None:
        """Auto-fill {url} — full URL for web scanners."""
        if "{url}" not in template or "url" in args:
            return
        target = self.state.target if self.state else "localhost"
        port = args.get("port", "80")
        scheme = "https" if port in ("443", "8443") else "http"
        args["url"] = f"{scheme}://{target}:{port}"

    def _run_system_tool(self, tool_name: str, tool_spec: "ToolSpec", args: dict) -> dict:
        """Run a standard system tool."""
        # Auto-fill missing template parameters from agent state
        args = self._enrich_tool_args(tool_name, tool_spec, args)

        target = self.state.target if self.state else "localhost"

        # Build command from template
        try:
            command = tool_spec.command_template.format(
                target=target,
                **args,
            )
        except KeyError as e:
            return {"success": False, "error": f"Missing argument: {e}", "args": args}

        # ====== KOMUTU KULLANICIYA GÖSTER ======
        self.console.print(
            Panel(
                f"[bold cyan]{command}[/bold cyan]",
                title=f"💻 {tool_name}",
                border_style="cyan",
                padding=(0, 1),
            ),
        )

        # Execute via execution engine
        result: ExecutionResult = self.executor.terminal.execute(command, timeout=300)

        # ====== OUTPUT'U KULLANICIYA GÖSTER ======
        if result.stdout and result.stdout.strip():
            # Truncate very long output
            output_display = result.stdout[:2000]
            if len(result.stdout) > 2000:
                output_display += f"\n... ({len(result.stdout) - 2000} karakter daha)"
            self.console.print(
                Panel(
                    output_display,
                    title="📄 Output",
                    border_style="green" if result.exit_code == 0 else "red",
                    padding=(0, 1),
                ),
            )

        if result.stderr and result.stderr.strip() and result.exit_code != 0:
            self.console.print(
                Panel(
                    result.stderr[:1000],
                    title="⚠️ Stderr",
                    border_style="yellow",
                    padding=(0, 1),
                ),
            )

        # Execution time feedback
        self.console.print(
            f"   [dim]⏱️ Süre: {result.duration:.1f}s | Exit: {result.exit_code}[/dim]",
        )

        # Track tool failures globally
        if result.exit_code != 0:
            return self._handle_tool_failure(tool_name, command, result, args)

        return self._format_tool_result(result, args, tool_name=tool_name)

    def _format_tool_result(self, result: Any, args: dict, tool_name: str = "unknown") -> dict:
        """Format execution result dictionary with standardized errors."""
        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        exit_code = result.exit_code

        # New: Standardize error
        error_msg: str = normalize_error_message(stdout_str, stderr_str, exit_code)

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
            "error_summary": error_msg,  # New standardized field
            "exit_code": exit_code,
            "args": args,
        }

        # Log to structured log
        self.logger.log_action(
            tool=tool_name,
            args=args,
            result=final_result,
        )

        return final_result

    def _show_final_report(self) -> None:
        """Show final execution report."""
        if not self.state:
            self.console.print("\n[yellow]No state available for report.[/yellow]")
            return

        self.console.print("\n" + "=" * 60, style="bold")
        self.console.print("📊 FINAL REPORT", style=self.STYLE_GREEN)
        self.console.print("=" * 60, style="bold")

        report = Text()
        report.append(f"🎯 Target: {self.state.target}\n", style="bold")
        report.append(
            f"🔄 Iterations: {self.state.iteration_count}/{self.state.max_iterations}\n",
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
        """Stop the agent."""
        self.running = False

