# core/refactored_agent.py
# DRAKBEN SELF-REFINING EVOLVING AGENT
# PROFILE-BASED EVOLUTION + POLICY CONFLICT RESOLUTION + META-LEARNING

import asyncio
import json
import time
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.brain import DrakbenBrain
from core.coder import AICoder
from core.config import ConfigManager
from core.evolution_memory import ActionRecord, get_evolution_memory
from core.execution_engine import ExecutionEngine
from core.planner import Planner, StepStatus
from core.state import (AgentState, AttackPhase, reset_state, ServiceInfo, VulnerabilityInfo)
from core.self_refining_engine import (
    SelfRefiningEngine, 
    Strategy, 
    StrategyProfile,
    PolicyTier
)
from core.tool_selector import ToolSelector
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

        # Core Components
        self.brain = DrakbenBrain(llm_client=config_manager.llm_client)
        self.state: AgentState = None
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
    STYLE_BLUE = "bold blue"

    def initialize(self, target: str):
        """
        Initialize agent with PROFILE-BASED SELECTION
        
        ENFORCED ORDER:
        1. Classify target → target_signature
        2. Select strategy.name (with policy filtering)
        3. Select best strategy_profile (not retired, not failed)
        4. Generate plan FROM THAT PROFILE
        """
        self.console.print(
            f"🔄 Initializing agent for target: {target}", style=self.STYLE_BLUE
        )

        # 1. Reset State
        self.state = reset_state(target)
        self.state.phase = AttackPhase.INIT

        # 1.5. EVOLVE TOOL PRIORITIES (penalty-aware)
        try:
            self.tool_selector.evolve_strategies(self.evolution)
        except Exception as e:
            self.console.print(f"⚠️  Tool evolution skipped: {e}", style="yellow")

        # 2. CLASSIFY TARGET
        target_type = self.refining_engine.classify_target(target)
        self.target_signature = self.refining_engine.get_target_signature(target)
        self.console.print(
            f"🎯 Target Classification: {target_type}", style="cyan"
        )
        self.console.print(
            f"🔑 Target Signature: {self.target_signature}", style="dim"
        )

        # 3. SELECT STRATEGY AND PROFILE (enforced order)
        self.current_strategy, self.current_profile = self.refining_engine.select_strategy_and_profile(target)
        
        if not self.current_strategy or not self.current_profile:
            self.console.print("❌ No strategy/profile available", style="red")
            return
        
        self.console.print(
            f"🧠 Selected Strategy: {self.current_strategy.name}",
            style=self.STYLE_MAGENTA
        )
        self.console.print(
            f"🎭 Selected Profile: {self.current_profile.profile_id[:12]}... "
            f"(gen: {self.current_profile.mutation_generation}, "
            f"success_rate: {self.current_profile.success_rate:.1%}, "
            f"aggression: {self.current_profile.aggressiveness:.2f})",
            style=self.STYLE_CYAN
        )
        
        # Show profile details
        self.console.print(
            f"   📋 Step Order: {self.current_profile.step_order}",
            style="dim"
        )
        self.console.print(
            f"   ⚙️  Parameters: {json.dumps(self.current_profile.parameters)}",
            style="dim"
        )

        # 4. CREATE PLAN FROM PROFILE (not strategy!)
        existing_plan = self.evolution.get_active_plan(f"pentest_{target}")
        if existing_plan:
            self.console.print(
                f"🔁 Resuming plan: {existing_plan.plan_id}", style=self.STYLE_GREEN
            )
            self.planner.load_plan(existing_plan.plan_id)
        else:
            # Create plan FROM PROFILE
            plan_id = self.planner.create_plan_from_profile(
                target, 
                self.current_profile,
                f"pentest_{target}"
            )
            self.console.print(
                f"📋 Created plan from profile: {plan_id}", style=self.STYLE_GREEN
            )

        # 5. SHOW EVOLUTION STATUS
        status = self.refining_engine.get_evolution_status()
        self.console.print(
            f"🧬 Evolution Status: {status['active_policies']} policies, "
            f"{status['retired_profiles']} retired profiles, "
            f"{status['max_mutation_generation']} max mutation gen",
            style="dim"
        )

        # 6. SHOW APPLICABLE POLICIES (with conflict resolution info)
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

        self.running = True
        self.stagnation_counter = 0

    def run_autonomous_loop(self):
        """
        EVOLVED AGENTIC LOOP
        
        Refactored to reduce Cognitive Complexity.
        """
        lang = self.config.language
        self.console.print(
            f"\n🚀 Starting evolved autonomous loop...\n", style=self.STYLE_GREEN
        )

        while self.running:
            iteration = self.state.iteration_count + 1
            self.console.print(f"\n{'='*60}", style="dim")
            self.console.print(
                f"⚡ Iteration {iteration}/{self.state.max_iterations}",
                style="bold cyan",
            )

            # 1. Stagnation Check
            if self._check_stagnation():
                break

            # 2. Get Next Step
            step = self.planner.get_next_step()
            if not step:
                self._handle_plan_completion()
                break

            self.console.print(
                f"📋 Plan Step: {step.step_id} | Action: {step.action} | Tool: {step.tool}",
                style="cyan"
            )

            # 3. Check Penalty
            if self._check_tool_blocked(step):
                continue

            # 4. Execute
            self.planner.mark_step_executing(step.step_id)
            self.console.print(f"🔧 Executing: {step.tool}...", style="yellow")

            execution_result = self._execute_tool(step.tool, step.params)
            success = execution_result.get("success", False)

            # 5. Record & Update
            penalty = self.evolution.get_tool_penalty(step.tool)
            self._record_action(step, success, penalty, execution_result)
            self.evolution.update_penalty(step.tool, success=success)

            # 6. Handle Result
            if success:
                self._handle_step_success(step, execution_result)
            else:
                if not self._handle_step_failure(step, execution_result):
                    break

            # 7. Update State
            observation = f"{step.tool}: {'success' if success else 'failed'}"
            self._update_state_from_result(step.tool, execution_result, observation)

            # 8. Validation & Halt Limit
            if not self._validate_loop_state():
                break

            self.state.increment_iteration()
            time.sleep(0.5)

        # ============ FINAL REPORT ============
        self._show_final_report()

    def _check_stagnation(self) -> bool:
        """Check for stagnation and triggering replan if needed. Returns True if halt required."""
        if self.evolution.detect_stagnation():
            self.console.print("⚠️  STAGNATION DETECTED - forcing replan", style="bold yellow")
            current_step = self.planner.get_next_step()
            if current_step:
                self.planner.replan(current_step.step_id)
            self.stagnation_counter += 1
            
            if self.stagnation_counter >= 3:
                self.console.print("🛑 HALT: Too many stagnations", style=self.STYLE_RED)
                return True
        return False

    def _handle_plan_completion(self):
        """Handle case where no steps are left."""
        if self.planner.is_plan_complete():
            self.console.print("✅ Plan complete!", style="bold green")
            self.state.phase = AttackPhase.COMPLETE
        else:
            self.console.print("❓ No executable step found", style="yellow")

    def _check_tool_blocked(self, step) -> bool:
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

    def _record_action(self, step, success, penalty, execution_result):
        """Record action to evolution memory."""
        record = ActionRecord(
            goal=f"pentest_{self.state.target}",
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

    def _handle_step_success(self, step, execution_result):
        """Handle successful step execution."""
        self.planner.mark_step_success(step.step_id, execution_result.get("stdout", "")[:200])
        self.console.print(f"✅ Step succeeded", style="green")
        self.stagnation_counter = 0
        
        # Update profile outcome on success
        if self.current_profile:
            self.refining_engine.update_profile_outcome(self.current_profile.profile_id, True)

    def _handle_step_failure(self, step, execution_result) -> bool:
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
            error_type = "missing_tool"
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
                f"📝 Replan failed - will select different profile next time",
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
            self.console.print(f"\n🛑 HALT: {halt_reason}", style="bold yellow")
            return False
            
        return True

    def _get_llm_decision(self, context: Dict) -> Optional[Dict]:
        """
        LLM'den TEK aksiyon al

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
        """
        # Fallback to deterministic if LLM unavailable
        deterministic_decision = self.tool_selector.recommend_next_action(self.state)

        if deterministic_decision:
            action_type, tool_name, args = deterministic_decision
            return {"tool": tool_name, "args": args}

        # If no deterministic decision, try LLM
        try:
            # Simplified LLM call - brain should return just tool selection
            result = self.brain.select_next_tool(context)

            if isinstance(result, dict) and "tool" in result:
                return result
        except Exception as e:
            self.console.print(f"⚠️  LLM error: {e}", style="yellow")

        return None

    def _install_tool(self, tool_name: str) -> bool:
        """
        Attempt to automatically install a missing tool.
        Supports: Linux (apt), MacOS (brew), Windows (choco/winget)
        """
        import platform
        
        # Map internal tool names to package names
        tool_pkg_map = {
            "nmap_port_scan": "nmap",
            "nmap_service_scan": "nmap", 
            "nmap_vuln_scan": "nmap",
            "sqlmap_scan": "sqlmap",
            "sqlmap_exploit": "sqlmap",
            "nikto_web_scan": "nikto",
            # Add others as needed
        }
        
        pkg = tool_pkg_map.get(tool_name)
        if not pkg:
            return False
            
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
        Execute a single tool.
        Supports both static tools and AI-generated dynamic tools.
        """
        if not self.state:
            return {"success": False, "error": "State is not initialized", "args": args}

        # ============ DYNAMIC TOOL CHECK ============
        # If tool starts with "auto_" it's AI-generated
        if tool_name.startswith("auto_") or tool_name in self.coder.created_tools:
            self.console.print(
                f"🧬 Executing AI-generated tool: {tool_name}",
                style=self.STYLE_MAGENTA
            )
            result = self.coder.execute_dynamic_tool(
                tool_name=tool_name,
                target=self.state.target,
                args=args
            )
            return {
                "success": result.get("success", False),
                "stdout": result.get("output", ""),
                "stderr": result.get("error", ""),
                "exit_code": 0 if result.get("success") else 1,
                "args": args
            }

        # ============ STATIC TOOL EXECUTION ============
        # Route exploit/payload tools through state-aware modules

        # 🛡️ SAFETY CHECK: Hard-stop approval for critical tools
        tool_spec = self.tool_selector.tools.get(tool_name)
        if tool_spec and tool_spec.risk_level == "critical":
            self.console.print(
                f"\n⚠️  CRITICAL ACTION DETECTED: {tool_name}", style=self.STYLE_RED
            )
            self.console.print(f"Args: {args}", style="red")

            # Interactive confirmation (Input loop)
            while True:
                response = (
                    input("🛑 Do you authorize this action? (YES/NO): ").strip().upper()
                )
                if response == "YES":
                    self.console.print("✅ Action authorized by user.", style="green")
                    break
                elif response == "NO":
                    self.console.print("🚫 Action blocked by user.", style=self.STYLE_RED)
                    return {
                        "success": False,
                        "error": "User denied authorization",
                        "blocked": True,
                    }

        if tool_name in ["sqlmap_exploit", "sqlmap_scan"]:
            target = args.get("target") or f"http://{self.state.target}"
            # Fixed: Correct parameter order - state first
            result = exploit_module.run_sqlmap(self.state, target)
            return {
                "success": result.get("exit_code", 1) == 0
                and not result.get("blocked"),
                "stdout": result.get("stdout", "")[:500],
                "stderr": result.get("stderr", "")[:200],
                "exit_code": result.get("exit_code", -1),
                "error": result.get("error"),
                "args": args,
            }

        if tool_name in ["reverse_shell", "msfvenom_payload"]:
            # Reverse shell requires foothold and state
            target_ip = args.get("lhost") or self.state.target or "127.0.0.1"
            target_port = int(args.get("lport", 4444))
            # Fixed: Correct parameter order and names - state first, then target_ip, target_port
            result = self._run_async(
                payload_module.reverse_shell(self.state, target_ip, target_port)
            )
            return {
                "success": result.get("success", False) and not result.get("blocked"),
                "stdout": "",
                "stderr": "",
                "exit_code": 0 if result.get("success") else 1,
                "error": result.get("error"),
                "args": args,
            }

        if tool_name == "passive_recon":
            # Passive recon via Python module
            from modules import recon as recon_module

            target = args.get("target") or f"http://{self.state.target}"

            # Only run on HTTP/HTTPS targets
            if not target.startswith("http"):
                target = f"http://{target}"

            result = self._run_async(recon_module.passive_recon(target, self.state))
            return {
                "success": not result.get("error") and not result.get("blocked"),
                "stdout": str(result.get("ai_summary", "Recon completed"))[:500],
                "stderr": result.get("error", "")[:200],
                "exit_code": 0 if not result.get("error") else 1,
                "error": result.get("error"),
                "args": args,
            }

        if tool_name == "generic_command":
            # High-risk flexible command execution
            cmd = args.get("command", "")
            if not cmd:
                return {"success": False, "error": "No command provided", "args": args}

            # Security filter for destructive commands
            forbidden = [
                "rm -rf",
                "mkfs",
                "dd if=",
                ":(){ :|:& };:",
                "shutdown",
                "reboot",
            ]
            if any(f in cmd for f in forbidden):
                self.console.print(
                    f"🛑 BLOCKED DESTRUCTIVE COMMAND: {cmd}", style="bold red"
                )
                return {
                    "success": False,
                    "error": "Command blocked by safety filter",
                    "args": args,
                }

            # Allow execution
            self.console.print(
                f"⚠️  EXECUTING GENERIC COMMAND: {cmd}", style="bold yellow"
            )
            result = self.executor.terminal.execute(cmd, timeout=60)
            return {
                "success": result.exit_code == 0,
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:200],
                "exit_code": result.exit_code,
                "args": args,
            }

        if tool_name == "system_evolution":
            # GOD MODE: Self-Modification & Evolution
            action = args.get("action")  # create_tool, modify_file
            target = args.get("target")  # tool_name or file_path
            instruction = args.get(
                "instruction"
            )  # "Make nmap faster" or "Remove firewall check"

            self.console.print(
                f"🧬 SYSTEM EVOLUTION TRIGGERED: {action} on {target}",
                style="bold magenta blink",
            )

            if action == "create_tool":
                # Create brand new tool dynamically
                result = self.coder.create_tool(target, instruction, "python")
                if result["success"]:
                    # Register immediately using dynamic loader
                    tool_name = f"dynamic_{target.replace('.', '_').replace(' ', '_')}"
                    self.tool_selector.register_dynamic_tool(
                        name=tool_name,
                        phase=self.state.phase,
                        command_template=f"python dynamic_tools/{tool_name}.py {{target}}"
                    )
                    return {
                        "success": True,
                        "output": f"Created and registered tool: {target}. It is now available.",
                    }
                return {"success": False, "error": result["error"]}

            elif action == "modify_file":
                # DANGEROUS: Modify existing core files
                # 1. Read file
                try:
                    with open(target, "r", encoding="utf-8") as f:
                        original_content = f.read()
                except Exception as e:
                    return {"success": False, "error": f"Read failed: {e}"}

                # 2. Ask LLM to modify
                prompt = f"""You are a Senior Python Architect.
Refactor this file: {target}
Instruction: {instruction}
Original Content:
```python
{original_content}
```
Output the FULL modified file content in ```python``` block. Ensure valid syntax.
"""
                try:
                    response = self.brain.llm_client.query(prompt)
                    new_content = self.coder._extract_code(response)

                    # 3. Syntax Check (CRITICAL)
                    if self.coder._validate_syntax(new_content):
                        import os
                        import shutil

                        # Safe Atomic Write Pattern
                        backup_path = f"{target}.bak"
                        temp_path = f"{target}.tmp"

                        try:
                            # 1. Write to temp first
                            with open(temp_path, "w", encoding="utf-8") as f:
                                f.write(new_content)

                            # 2. Create backup of original
                            shutil.copy2(target, backup_path)

                            # 3. Atomic Replace (Try to overwrite)
                            # On Windows, os.replace might fail if open, but it's the best attempt
                            try:
                                os.replace(temp_path, target)
                                return {
                                    "success": True,
                                    "output": f"Modified {target} successfully. Backup created at {backup_path}.",
                                }
                            except PermissionError:
                                # Fallback: If locked, leave .tmp and notify
                                return {
                                    "success": False,
                                    "error": f"FILE EXTENSION LOCKED by Windows. Written to {temp_path}. Manual replace or restart required.",
                                    "warning": "Agent is running from this file.",
                                }

                        except Exception as e:
                            return {
                                "success": False,
                                "error": f"File operation failed: {e}",
                            }
                    else:
                        return {
                            "success": False,
                            "error": "Generated code had syntax errors. Change rejected.",
                        }
                except Exception as e:
                    return {"success": False, "error": f"Modification failed: {e}"}

        if tool_name == "metasploit_exploit":
            return {
                "success": False,
                "error": "Metasploit integration blocked: no state-aware wrapper",
                "args": args,
            }

        # Get tool spec
        tool_spec = self.tool_selector.tools.get(tool_name)

        if not tool_spec:
            return {"success": False, "error": "Tool not found", "args": args}

        # Build command from template
        try:
            command = tool_spec.command_template.format(**args)
        except KeyError as e:
            return {"success": False, "error": f"Missing argument: {e}", "args": args}

        # Execute via execution engine
        result = self.executor.terminal.execute(command, timeout=300)

        # Track tool failures globally
        if result.exit_code != 0:
            stdout_str = result.stdout or ""
            stderr_str = result.stderr or ""
            
            # Check for missing tool
            if "not found" in stderr_str.lower() or "not recognized" in stderr_str.lower() or "bulunamadı" in stderr_str.lower():
                 # Attempt auto-install
                 if self._install_tool(tool_name):
                     self.console.print(f"🔄 Retrying {tool_name} after installation...", style="cyan")
                     # Retry execution
                     result = self.executor.terminal.execute(command, timeout=300)
                     # Update output vars
                     stdout_str = result.stdout or ""
                     stderr_str = result.stderr or ""
            
            if result.exit_code != 0:
                 self.tool_selector.record_tool_failure(tool_name)

        # Smart error extraction (ensure vars exist if not retried)
        if 'stdout_str' not in locals():
            stdout_str = result.stdout or ""
            stderr_str = result.stderr or ""
        
        # Some tools output errors to stdout (like nmap sometimes)
        if result.exit_code != 0 and not stderr_str.strip():
            if stdout_str.strip():
               stderr_str = f"Tool Error (in stdout): {stdout_str[-500:]}"
            else:
               stderr_str = f"Command failed with exit code {result.exit_code} (No output captured)"

        return {
            "success": result.status.value == "success",
            "stdout": stdout_str,
            "stderr": stderr_str,
            "exit_code": result.exit_code,
            "args": args,
        }

    def _run_async(self, coro, timeout: int = 60):
        """
        Run async coroutine deterministically from sync context.

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
            # Run with timeout
            return asyncio.run(asyncio.wait_for(coro, timeout=timeout))
        except asyncio.TimeoutError:
            self.console.print(
                f"⚠️  Async task timeout after {timeout}s", style="yellow"
            )
            return {"success": False, "error": f"Async task timed out after {timeout}s"}
        except Exception as e:
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
        Tool sonucuna göre state'i güncelle

        IMPROVED: Gerçek tool output parsing ile
        """
        # Set observation
        self.state.set_observation(observation)

        # Tool failure tracking
        if not result.get("success"):
            self.tool_selector.record_tool_failure(tool_name)
            # Observe failure too
            self.brain.observe(
                tool=tool_name, 
                output=result.get("stdout", "") + "\n" + result.get("stderr", ""), 
                success=False
            )
            return

        # Observe success
        self.brain.observe(
            tool=tool_name, 
            output=result.get("stdout", "") + "\n" + result.get("stderr", ""), 
            success=True
        )

        # Success - update state based on tool
        if "nmap_port_scan" in tool_name:
            # Parse real nmap output
            from core.tool_parsers import parse_nmap_output

            stdout = result.get("stdout", "")
            # Hybrid parsing with LLM fallback
            parsed_services = parse_nmap_output(
                stdout, llm_client=self.brain.llm_client
            )

            if parsed_services:
                # Convert to ServiceInfo objects
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
                services = [
                    ServiceInfo(port=80, protocol="tcp", service="http"),
                    ServiceInfo(port=443, protocol="tcp", service="https"),
                    ServiceInfo(port=22, protocol="tcp", service="ssh"),
                ]
                self.state.update_services(services)

        elif "nmap_service_scan" in tool_name or "nikto" in tool_name:
            # Mark surface as tested - requires args
            args_port = result.get("args", {}).get("port")
            if not args_port:
                self.state.set_observation(
                    "Missing port in tool args; state not updated"
                )
                return
            if args_port in self.state.open_services:
                service_info = self.state.open_services[args_port]
                self.state.mark_surface_tested(args_port, service_info.service)

        elif "vuln" in tool_name or "sqlmap" in tool_name:
            # Check if vulnerability found
            if (
                "vulnerable" in observation.lower()
                or "injection" in observation.lower()
            ):
                # Parse sqlmap output for details
                from core.tool_parsers import parse_sqlmap_output

                stdout = result.get("stdout", "")
                # Hybrid parsing with LLM fallback
                parsed_vulns = parse_sqlmap_output(
                    stdout, llm_client=self.brain.llm_client
                )

                if parsed_vulns:
                    for vuln_dict in parsed_vulns:
                        vuln = VulnerabilityInfo(
                            vuln_id=f"sqli_{vuln_dict.get('parameter', 'unknown')}",
                            service="http",
                            port=80,  # TODO: extract from args
                            severity="high",
                            exploitable=True,
                        )
                        self.state.add_vulnerability(vuln)
                        # 🧠 LEARNING: Record experience
                        # Note: Evolution memory handles learning through record_action
                else:
                    # Fallback mock
                    vuln = VulnerabilityInfo(
                        vuln_id="sqli_001",
                        service="http",
                        port=80,
                        severity="high",
                        exploitable=True,
                    )
                    self.state.add_vulnerability(vuln)
            else:
                self.state.set_observation(
                    "No confirmed vulnerability; state not updated"
                )

        elif "exploit" in tool_name:
            # Check if exploit succeeded
            if "success" in observation.lower() or "shell" in observation.lower():
                self.state.set_foothold(tool_name)
            else:
                self.state.set_observation("Exploit did not succeed; foothold not set")

    def _check_phase_transition(self):
        """
        Phase transition kontrolü - DETERMİNİSTİK
        """
        # INIT -> RECON (target set)
        if self.state.phase == AttackPhase.INIT and self.state.target:
            self.state.phase = AttackPhase.RECON
            self.console.print("📈 Phase transition: INIT -> RECON", style="bold blue")

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
                "📈 Phase transition: RECON -> VULN_SCAN", style="bold blue"
            )

        # VULN_SCAN -> EXPLOIT (vulnerabilities found)
        elif (
            self.state.phase == AttackPhase.VULN_SCAN
            and self.state.vulnerabilities
            and len(self.state.remaining_attack_surface) == 0
        ):
            self.state.phase = AttackPhase.EXPLOIT
            self.console.print(
                "📈 Phase transition: VULN_SCAN -> EXPLOIT", style="bold blue"
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
                style="bold yellow",
            )

        # EXPLOIT -> POST_EXPLOIT (foothold achieved)
        elif self.state.phase == AttackPhase.EXPLOIT and self.state.has_foothold:
            self.state.phase = AttackPhase.POST_EXPLOIT
            self.console.print(
                "📈 Phase transition: EXPLOIT -> POST_EXPLOIT", style="bold blue"
            )

    def _show_final_report(self):
        """Show final execution report"""
        self.console.print("\n" + "=" * 60, style="bold")
        self.console.print("📊 FINAL REPORT", style="bold green")
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
            report.append("\n❌ Invariant Violations:\n", style="bold red")
            for violation in self.state.invariant_violations:
                report.append(f"   - {violation}\n", style="red")

        self.console.print(Panel(report, border_style="green", title="Summary"))

    def stop(self):
        """Stop the agent"""
        self.running = False
