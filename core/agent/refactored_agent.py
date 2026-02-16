# core/refactored_agent.py
# DRAKBEN SELF-REFINING EVOLVING AGENT
# PROFILE-BASED EVOLUTION + POLICY CONFLICT RESOLUTION + META-LEARNING

import logging
import sqlite3

from rich.console import Console
from rich.panel import Panel

from core.agent.brain import DrakbenBrain
from core.agent.error_diagnostics import ErrorDiagnosticsMixin
from core.agent.planner import Planner, PlanStep, StepStatus
from core.agent.ra_failure_recovery import RAFailureRecoveryMixin
from core.agent.ra_output_analysis import RAOutputAnalysisMixin
from core.agent.ra_profile_selection import RAProfileSelectionMixin
from core.agent.ra_reflection import RAReflectionMixin
from core.agent.ra_state_updates import RAStateUpdatesMixin
from core.agent.ra_tool_executors import RAToolExecutorsMixin
from core.agent.ra_tool_recovery import RAToolRecoveryMixin
from core.agent.ra_tool_runner import RAToolRunnerMixin
from core.agent.recovery.healer import SelfHealer
from core.agent.state import AgentState, AttackPhase, reset_state
from core.config import ConfigManager
from core.execution.execution_engine import ExecutionEngine
from core.execution.tool_selector import ToolSelector
from core.intelligence.coder import AICoder
from core.intelligence.evolution_memory import (
    EvolutionMemory,
    PlanRecord,
    get_evolution_memory,
)
from core.intelligence.self_refining_engine import (
    SelfRefiningEngine,
    Strategy,
    StrategyProfile,
)
from core.storage.structured_logger import DrakbenLogger
from core.ui.transparency import get_transparency

# Intelligence v2 imports (optional — graceful degradation)
_SelfReflectionEngine = None
_ReActLoop = None
try:
    from core.intelligence.react_loop import ReActLoop as _ReActLoop  # type: ignore[assignment]
    from core.intelligence.self_reflection import (  # type: ignore[assignment]
        SelfReflectionEngine as _SelfReflectionEngine,
    )
except ImportError:
    pass

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)

# Error message constants (SonarCloud compliance)
_ERR_UNKNOWN = "Unknown error"


class RefactoredDrakbenAgent(
    ErrorDiagnosticsMixin,
    RAOutputAnalysisMixin,
    RAReflectionMixin,
    RAProfileSelectionMixin,
    RAToolRunnerMixin,
    RAFailureRecoveryMixin,
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

        # Intelligence v2: Self-Reflection Engine
        self.reflector = None
        if _SelfReflectionEngine is not None:
            try:
                self.reflector = _SelfReflectionEngine(
                    llm_client=config_manager.llm_client,
                    reflect_interval=5,
                )
                logger.info("Self-Reflection Engine initialized (every 5 steps)")
            except Exception as e:
                logger.debug("SelfReflectionEngine init failed: %s", e)

        # Intelligence v2: ReAct Loop (available as alternative to plan-based loop)
        self.react_loop = None
        if _ReActLoop is not None:
            try:
                self.react_loop = _ReActLoop(
                    brain=self.brain,
                    executor=self.executor,
                    tool_selector=self.tool_selector,
                    evolution=self.evolution,
                    max_steps=25,
                )
                logger.info("ReAct Loop initialized (available via /react command)")
            except Exception as e:
                logger.debug("ReActLoop init failed: %s", e)

        # Additional Modules for Full System Test
        try:
            from modules.ad_attacks import ActiveDirectoryAttacker

            self.ad_attacker = ActiveDirectoryAttacker()
        except ImportError:
            logger.warning(
                "ActiveDirectoryAttacker could not be initialized (missing imports).",
            )
            self.ad_attacker = None  # type: ignore[assignment]

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

        # 1.5 Self-Reflection Check (Intelligence v2)
        if self.reflector and self.reflector.should_reflect(iteration):
            self._run_self_reflection(iteration)

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
            if self.state is not None:
                self.state.increment_iteration()
            return True

        # Show what we're about to do with context
        self._show_step_info(step)

        # ── Intelligence v3: Adversarial Adapter — apply evasion args ──
        self._apply_evasion_args(step)

        # ── Intelligence v3: Exploit Predictor — predict before attempting ──
        self._predict_exploit_outcome(step)

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
            self._analyze_and_show_output(step.tool, execution_result)
        elif not self._handle_step_failure(step, execution_result):
            return False

        # Update State
        observation: str = f"{step.tool}: {'success' if success else 'failed'}"
        self._update_state_from_result(step.tool, execution_result, observation)

        # Validation & Halt Limit
        if not self._validate_loop_state():
            return False

        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        self.state.increment_iteration()
        return True

    def _show_step_info(self, step: PlanStep) -> None:
        """Display step info to console before execution."""
        self.console.print(f"\n[>] [bold yellow]Executing: {step.tool}[/bold yellow]", style="yellow")
        if step.params:
            params_display = ", ".join(f"{k}={v}" for k, v in list(step.params.items())[:3])
            self.console.print(f"   Params: {params_display}", style="dim")

    def _apply_evasion_args(self, step: PlanStep) -> None:
        """Apply adversarial evasion arguments to step params."""
        adversarial = getattr(self.brain, "adversarial", None) if self.brain else None
        if not adversarial or step.params is None:
            return
        try:
            modifier = adversarial.get_tool_args_modifier(step.tool)
            if not modifier:
                return
            extra_args = modifier.get("extra_args", {})
            if extra_args:
                step.params.update(extra_args)
                self.console.print(
                    f"   🛡\ufe0f Evasion active: +{len(extra_args)} stealth args",
                    style="bold red",
                )
            delay = modifier.get("delay", 0)
            if delay > 0:
                self.console.print(
                    f"   ⏱\ufe0f Stealth delay: {delay}s between requests",
                    style="dim red",
                )
        except (AttributeError, KeyError, TypeError):
            logger.debug("Stealth modifier display failed", exc_info=True)

    def _predict_exploit_outcome(self, step: PlanStep) -> None:
        """Run exploit predictor for exploit steps."""
        if step.action not in ("exploit", "execute_exploit", "sqlmap_exploit"):
            return
        predictor = getattr(self.brain, "exploit_predictor", None) if self.brain else None
        if not predictor:
            return
        try:
            exploit_name = step.params.get("exploit", step.tool) if step.params else step.tool
            svc = step.params.get("service", "") if step.params else ""
            ver = step.params.get("version", "") if step.params else ""
            target = self.state.target if self.state else ""
            prediction = predictor.predict(
                exploit_name=exploit_name,
                service=svc,
                version=ver,
                target=target,
            )
            self.console.print(
                f"   🎯 Exploit prediction: {prediction.probability:.0%} success ({prediction.reasoning})",
                style="bold cyan",
            )
            if prediction.alternatives:
                alt_str = ", ".join(prediction.alternatives[:3])
                self.console.print(f"   💡 Alternatives: {alt_str}", style="dim cyan")
        except (AttributeError, TypeError, ValueError):
            logger.debug("Exploit prediction failed", exc_info=True)

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

    # ── Dangerous operation categories requiring user approval ──
    _DANGEROUS_ACTIONS: set[str] = {
        "exploit",
        "get_shell",
        "brute_force",
        "credential_test",
        "data_exfil",
        "sqlmap_exploit",
        "execute_exploit",
    }
    _DANGEROUS_TOOLS: set[str] = {
        "sqlmap_scan",
        "hydra",
        "metasploit_exploit",
        "john",
        "hashcat",
        "generate_payload",
        "data_exfil",
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
        is_dangerous = step.action in self._DANGEROUS_ACTIONS or step.tool in self._DANGEROUS_TOOLS
        if not is_dangerous:
            return True  # safe — auto-approve

        risk_level = "HIGH" if step.action in ("exploit", "get_shell", "data_exfil") else "MEDIUM"

        # Auto-approve if configured (equivalent to auto_run=True)
        auto_approve = getattr(self.config, "auto_approve_dangerous", False)
        if auto_approve:
            self.transparency.show_approval_request(
                step.tool,
                step.action,
                risk_level,
                approved=True,
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
            step.tool,
            step.action,
            risk_level,
            approved=approved,
        )

        if not approved:
            self.console.print("   \u26d4 Skipped by user", style="dim")
            self.planner.mark_step_failed(step.step_id, "User denied approval")

        return approved

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

    def stop(self) -> None:
        """Stop the agent."""
        self.running = False
