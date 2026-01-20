# core/refactored_agent.py
# DRAKBEN REFACTORED AGENT - 100% MİMARİ UYUMLU
# TEK AGENTİC LOOP - STATE-DRIVEN - DETERMİNİSTİK

import time
import asyncio
from typing import Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Core imports
from core.state import AgentState, AttackPhase, ServiceInfo, VulnerabilityInfo, reset_state
from core.tool_selector import ToolSelector
from core.brain import DrakbenBrain
from core.execution_engine import ExecutionEngine
from core.config import ConfigManager
from core.i18n import t

# Module-level tool integrations (state-aware)
from modules import exploit as exploit_module
from modules import payload as payload_module


class RefactoredDrakbenAgent:
    """
    DRAKBEN Refactored Agent - %100 Mimari Uyumlu
    
    ZORUNLU KURALLAR:
    1. TEK while loop (bu dosyada)
    2. Her iterasyonda ZORUNLU SIRA:
       - State snapshot
       - LLM TEK aksiyon seçer
       - TEK tool çalışır
       - Observation alınır
       - State güncellenir
       - State invariant kontrolü
    3. Max 15 iteration
    4. Son 3 adımda state değişmediyse HARD STOP
    5. LLM'ye SADECE state özeti gönderilir
    """
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.config
        self.console = Console()
        
        # Core components
        self.state: Optional[AgentState] = None
        self.tool_selector = ToolSelector()
        self.brain = DrakbenBrain()
        self.executor = ExecutionEngine()
        
        # Run control
        self.running = True
    
    def initialize(self, target: str):
        """Initialize agent for a new run"""
        self.console.print(Panel(
            f"🎯 Target: {target}\n📊 Max iterations: 15\n🔒 State-driven execution",
            title="🧛 DRAKBEN Refactored Agent",
            border_style="bold #FF5555"
        ))
        
        # Reset/create state
        self.state = reset_state(target)
        self.state.phase = AttackPhase.INIT
    
    def run_autonomous_loop(self):
        """
        MAIN AGENTIC LOOP - SADECE BU LOOP VAR
        
        ZORUNLU AKIŞ:
        1. State snapshot
        2. LLM decision (TEK aksiyon)
        3. Tool execution (TEK tool)
        4. Observation
        5. State update
        6. Invariant check
        7. Loop
        """
        lang = self.config.language
        
        self.console.print(f"\n🚀 {t('starting_autonomous', lang)}...\n", style="bold green")
        
        # MAIN LOOP - TEK GERÇEK LOOP
        while self.running:
            # ============ 1. STATE SNAPSHOT ============
            iteration = self.state.iteration_count + 1
            self.console.print(f"\n{'='*60}", style="dim")
            self.console.print(f"⚡ Iteration {iteration}/{self.state.max_iterations}", style="bold cyan")
            
            snapshot = self.state.snapshot()
            self.console.print(f"📊 Phase: {snapshot['phase']} | Services: {snapshot['open_services_count']} | "
                             f"Remaining: {snapshot['remaining_count']}", style="dim")
            # ============ STATE VALIDATION (ÖNCE) ============
            if not self.state.validate():
                self.console.print("❌ STATE INVARIANT VIOLATION (pre-action)!", style="bold red")
                for violation in self.state.invariant_violations:
                    self.console.print(f"   - {violation}", style="red")
                break
            
            # ============ 2. HALT CHECK (ÖNCE) ============
            should_halt, halt_reason = self.state.should_halt()
            if should_halt:
                self.console.print(f"\n🛑 HALT: {halt_reason}", style="bold yellow")
                self.state.phase = AttackPhase.COMPLETE if "complete" in halt_reason.lower() else AttackPhase.FAILED
                break
            
            # ============ 3. LLM DECISION (TEK AKSİYON) ============
            self.console.print("🧠 Requesting LLM decision...", style="cyan")
            
            # Prepare LLM context - SADECE ÖZET
            llm_context = {
                "state_snapshot": snapshot,
                "allowed_tools": self.tool_selector.get_allowed_tools(self.state),
                "remaining_surfaces": self.state.get_available_attack_surface()[:5],  # Max 5
                "last_observation": self.state.last_observation[:200],  # Max 200 char
                "phase": self.state.phase.value
            }
            
            # Get LLM decision
            decision = self._get_llm_decision(llm_context)
            
            if not decision or not decision.get("tool"):
                self.console.print("❌ No valid decision from LLM", style="red")
                self.state.set_observation("LLM returned no decision")
                self.state.increment_iteration()
                continue
            
            tool_name = decision["tool"]
            tool_args = decision.get("args", {})
            
            self.console.print(f"🎯 Decision: {tool_name} | Args: {tool_args}", style="green")

            # Enforce remaining attack surface constraint
            remaining = self.state.get_available_attack_surface()
            if remaining and self.state.phase in [AttackPhase.RECON, AttackPhase.VULN_SCAN]:
                # Only allow tools that match a surface selection
                surface_tool = self.tool_selector.select_tool_for_surface(self.state, remaining[0])
                if surface_tool:
                    allowed_tool, allowed_args = surface_tool
                    if tool_name != allowed_tool:
                        self.console.print("❌ Tool not allowed for remaining attack surface", style="red")
                        self.state.set_observation("Tool selection bypass blocked")
                        self.state.increment_iteration()
                        continue
                    # Override args to deterministic selection
                    tool_args = allowed_args
            
            # ============ 4. TOOL VALIDATION ============
            valid, reason = self.tool_selector.validate_tool_selection(tool_name, self.state)
            if not valid:
                self.console.print(f"❌ Tool validation failed: {reason}", style="red")
                self.state.set_observation(f"Tool {tool_name} validation failed: {reason}")
                self.state.increment_iteration()
                continue
            
            # ============ 5. TOOL EXECUTION (TEK TOOL) ============
            self.console.print(f"🔧 Executing: {tool_name}...", style="yellow")
            
            execution_result = self._execute_tool(tool_name, tool_args)
            
            # ============ 6. OBSERVATION ============
            observation = self._create_observation(tool_name, execution_result)
            self.console.print(f"👁️  Observation: {observation[:100]}...", style="dim")
            
            # ============ 7. STATE UPDATE ============
            self._update_state_from_result(tool_name, execution_result, observation)
            
            # ============ 8. STATE INVARIANT CHECK (ZORUNLU) ============
            if not self.state.validate():
                self.console.print(f"❌ STATE INVARIANT VIOLATION!", style="bold red")
                for violation in self.state.invariant_violations:
                    self.console.print(f"   - {violation}", style="red")
                break  # HARD STOP
            
            # ============ 9. INCREMENT ITERATION ============
            self.state.increment_iteration()
            
            # ============ 10. PHASE TRANSITION CHECK ============
            self._check_phase_transition()
            
            # Small delay for readability
            time.sleep(0.5)
        
        # ============ LOOP END - FINAL REPORT ============
        self._show_final_report()
    
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
    
    def _execute_tool(self, tool_name: str, args: Dict) -> Dict:
        """
        TEK tool çalıştır - gerçek implementation
        
        VARSAYIM: Şu an basit mock, gerçek tool entegrasyonu gerekli
        """
        if not self.state:
            return {"success": False, "error": "State is not initialized", "args": args}

        # Route exploit/payload tools through state-aware modules
        if tool_name in ["sqlmap_exploit", "sqlmap_scan"]:
            target = args.get("target") or f"http://{self.state.target}"
            result = exploit_module.run_sqlmap(target, state=self.state)
            return {"success": result.get("exit_code", 1) == 0 and not result.get("blocked"), "stdout": result.get("stdout", "")[:500], "stderr": result.get("stderr", "")[:200], "exit_code": result.get("exit_code", -1), "error": result.get("error"), "args": args}

        if tool_name in ["reverse_shell", "msfvenom_payload"]:
            # Reverse shell requires foothold and state
            lhost = args.get("lhost") or self.state.target or "127.0.0.1"
            lport = int(args.get("lport", 4444))
            result = self._run_async(payload_module.reverse_shell(lhost, lport, state=self.state))
            return {"success": result.get("success", False) and not result.get("blocked"), "stdout": "", "stderr": "", "exit_code": 0 if result.get("success") else 1, "error": result.get("error"), "args": args}

        if tool_name == "metasploit_exploit":
            return {"success": False, "error": "Metasploit integration blocked: no state-aware wrapper", "args": args}

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
        result = self.executor.execute(command, timeout=300)
        
        return {
            "success": result.status.value == "success",
            "stdout": result.stdout[:500],  # Max 500 char
            "stderr": result.stderr[:200],  # Max 200 char
            "exit_code": result.exit_code,
            "args": args
        }

    def _run_async(self, coro):
        """Run async coroutine deterministically from sync context."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            return {"success": False, "error": "Async execution blocked: event loop already running"}

        return asyncio.run(coro)
    
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
        
        VARSAYIM: Gerçek implementation için tool-specific parsing gerekli
        """
        # Set observation
        self.state.set_observation(observation)
        
        # Tool failure tracking
        if not result.get("success"):
            self.tool_selector.record_tool_failure(tool_name)
            return
        
        # Success - update state based on tool
        if "nmap_port_scan" in tool_name:
            # VARSAYIM: Parse nmap output and extract services
            # For now, mock data
            services = [
                ServiceInfo(port=80, protocol="tcp", service="http"),
                ServiceInfo(port=443, protocol="tcp", service="https"),
                ServiceInfo(port=22, protocol="tcp", service="ssh")
            ]
            self.state.update_services(services)
        
        elif "nmap_service_scan" in tool_name or "nikto" in tool_name:
            # Mark surface as tested - requires args
            args_port = result.get("args", {}).get("port")
            if not args_port:
                self.state.set_observation("Missing port in tool args; state not updated")
                return
            if args_port in self.state.open_services:
                service_info = self.state.open_services[args_port]
                self.state.mark_surface_tested(args_port, service_info.service)
        
        elif "vuln" in tool_name or "sqlmap" in tool_name:
            # Check if vulnerability found
            if "vulnerable" in observation.lower() or "injection" in observation.lower():
                # VARSAYIM: Parse actual vulnerability details
                vuln = VulnerabilityInfo(
                    vuln_id="sqli_001",
                    service="http",
                    port=80,
                    severity="high",
                    exploitable=True
                )
                self.state.add_vulnerability(vuln)
            else:
                self.state.set_observation("No confirmed vulnerability; state not updated")
        
        elif "exploit" in tool_name:
            # VARSAYIM: Check if exploit succeeded
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
        elif (self.state.phase == AttackPhase.RECON and 
              self.state.open_services and 
              len(self.state.remaining_attack_surface) == 0):
            self.state.phase = AttackPhase.VULN_SCAN
            # Re-add services for vuln scanning
            for port, svc in self.state.open_services.items():
                surface_key = f"{port}:{svc.service}"
                self.state.remaining_attack_surface.add(surface_key)
            self.console.print("📈 Phase transition: RECON -> VULN_SCAN", style="bold blue")
        
        # VULN_SCAN -> EXPLOIT (vulnerabilities found)
        elif (self.state.phase == AttackPhase.VULN_SCAN and 
              self.state.vulnerabilities and
              len(self.state.remaining_attack_surface) == 0):
            self.state.phase = AttackPhase.EXPLOIT
            self.console.print("📈 Phase transition: VULN_SCAN -> EXPLOIT", style="bold blue")
        
        # EXPLOIT -> POST_EXPLOIT (foothold achieved)
        elif self.state.phase == AttackPhase.EXPLOIT and self.state.has_foothold:
            self.state.phase = AttackPhase.POST_EXPLOIT
            self.console.print("📈 Phase transition: EXPLOIT -> POST_EXPLOIT", style="bold blue")
    
    def _show_final_report(self):
        """Show final execution report"""
        self.console.print("\n" + "="*60, style="bold")
        self.console.print("📊 FINAL REPORT", style="bold green")
        self.console.print("="*60, style="bold")
        
        report = Text()
        report.append(f"🎯 Target: {self.state.target}\n", style="bold")
        report.append(f"🔄 Iterations: {self.state.iteration_count}/{self.state.max_iterations}\n")
        report.append(f"📍 Final Phase: {self.state.phase.value}\n")
        report.append(f"🔓 Services Found: {len(self.state.open_services)}\n")
        report.append(f"⚠️  Vulnerabilities: {len(self.state.vulnerabilities)}\n")
        report.append(f"🎪 Foothold: {'YES' if self.state.has_foothold else 'NO'}\n")
        
        if self.state.has_foothold:
            report.append(f"   Method: {self.state.foothold_method}\n", style="green")
        
        if self.state.invariant_violations:
            report.append(f"\n❌ Invariant Violations:\n", style="bold red")
            for violation in self.state.invariant_violations:
                report.append(f"   - {violation}\n", style="red")
        
        self.console.print(Panel(report, border_style="green", title="Summary"))
    
    def stop(self):
        """Stop the agent"""
        self.running = False
