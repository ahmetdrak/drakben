# core/agent.py
# DRAKBEN - GPT-5 Level Autonomous Pentesting Agent
# 25 modules integrated for maximum intelligence

import time
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import all 25 modules
from core.brain import DrakbenBrain
from core.system_intelligence import SystemIntelligence
from core.execution_engine import ExecutionEngine
from core.autonomous_solver import AutonomousSolver
from core.security_toolkit import SecurityToolkit
from core.config import ConfigManager, SessionManager
from core.memory_manager import MemoryManager, get_memory
from core.i18n import t


class DrakbenAgent:
    """
    GPT-5 Level Autonomous Penetration Testing Agent
    
    Features:
    - 25 intelligent modules working together
    - Continuous reasoning and self-correction
    - Auto-healing of errors
    - System-aware execution
    - First-time approval, then autonomous
    """
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.config
        self.console = Console()
        
        # State
        self.running = True
        self.command_count = 0
        self.approved_commands = set()  # Track approved commands
        self.workflow_active = False
        
        # Initialize memory system
        self.memory = get_memory()
        
        # Load approved commands from memory
        self.approved_commands = set(self.memory.get_all_approved_commands())
        
        # Initialize all modules silently
        self.system_intel = SystemIntelligence()
        self.system_context = self.system_intel.get_full_system_context()
        self.brain = DrakbenBrain()
        self.executor = ExecutionEngine()
        self.solver = AutonomousSolver(self.system_context["system"])
        self.security = SecurityToolkit()
        self.session_manager = SessionManager(session_dir=self.config.session_dir)
        
    def initialize(self):
        """Initialize agent and show welcome"""
        lang = self.config.language
        
        # Combined compact panel
        welcome_text = Text()
        welcome_text.append("🩸 ", style="bold #FF5555")
        welcome_text.append("DRAKBEN", style="bold #BD93F9")
        welcome_text.append(" | ", style="#6272A4")
        welcome_text.append("Ready", style="#50FA7B")
        welcome_text.append("\n\n", style="")
        welcome_text.append("💬 ", style="bold #FF79C6")
        welcome_text.append("/help  /target  /scan  /status  /clear  /exit", style="#F8F8F2")
        
        # Show target if set
        if self.config.target:
            welcome_text.append(f"\n\n🎯 Target: ", style="bold #F8F8F2")
            welcome_text.append(self.config.target, style="bold #FF79C6")
        
        self.console.print(Panel(welcome_text, border_style="#FF5555", title="🧛 DRAKBEN", title_align="left"))
        
        # Show compact help
        self._show_compact_menu()
    
    def _show_compact_menu(self):
        """Show compact persistent menu"""
        # Menu removed - ultra minimal interface
    
    def _show_quick_help(self):
        """Show quick help"""
        lang = self.config.language
        
        if lang == "tr":
            help_text = """
💡 Nasıl Kullanılır:
  📌 Doğal dille konuş:
    • "10.0.0.1'i tara"
    • "192.168.1.1'de açık portları bul"
    • "example.com'da SQL injection test et"
    • "10.0.0.1'e shell at"
    • "payload üret 10.0.0.1:4444"
    
  🎮 Komutlar:
    • target <IP>    - Hedef belirle
    • status         - Sistem durumu
    • help           - Detaylı yardım
    • exit           - Çıkış
    
  ⚡ Özellikler:
    • İlk kez onay alır, sonra otomatik çalışır
    • Hataları otomatik düzeltir
    • Eksik araçları otomatik yükler
    • Her adımı raporlar
"""
        else:
            help_text = """
💡 How to Use:
  📌 Talk naturally:
    • "scan 10.0.0.1"
    • "find open ports on 192.168.1.1"
    • "test example.com for SQL injection"
    • "get shell on 10.0.0.1"
    • "generate payload for 10.0.0.1:4444"
    
  🎮 Commands:
    • target <IP>    - Set target
    • status         - System status
    • help           - Show help
    • exit           - Exit
    
  ⚡ Features:
    • First-time approval, then autonomous
    • Auto-heals errors
    • Auto-installs missing tools
    • Reports every step
"""
        
        self.console.print(help_text, style="yellow")
    
    def input_handler(self) -> bool:
        """Handle user input with GPT-5 level intelligence"""
        lang = self.config.language
        
        try:
            # Get user input
            user_input = self.console.input(f"\n[bold cyan]💬 {t('prompt', lang)}[/] ").strip()
            
            if not user_input:
                return True
            
            # Handle special commands (returns False for exit, None for AI processing)
            result = self._handle_special_commands(user_input)
            if result == False:  # Exit command
                return False
            elif result == True:  # System command handled
                return True
            # result == None means send to AI
            
            # Process with AI brain
            self._process_with_brain(user_input)
            
            return True
            
        except KeyboardInterrupt:
            self.console.print(f"\n\n⚠️  {t('interrupted', lang)}", style="yellow")
            return False
        except Exception as e:
            self.console.print(f"\n❌ Error: {e}", style="bold red")
            if self.config.verbose:
                import traceback
                self.console.print(traceback.format_exc(), style="dim red")
            return True
    
    def _handle_special_commands(self, user_input: str) -> bool:
        """Handle special commands - Only slash commands are system commands"""
        cmd = user_input.lower().strip()
        lang = self.config.language
        
        # Help command
        if cmd == "/help":
            self._show_detailed_help()
            return True
        
        # Target command
        if cmd.startswith("/target "):
            target = cmd.replace("/target ", "").strip()
            self.config.target = target
            self.memory.remember_target(target)  # Hafızaya kaydet
            self.console.print(f"🎯 {t('target', lang)}: {target}", style="bold green")
            
            # Check if we know this target
            target_info = self.memory.get_target_info(target)
            if target_info and target_info.get("findings"):
                self.console.print(f"💡 Bu hedefi daha önce taramıştık!", style="cyan")
            return True
        
        # Scan command
        if cmd == "/scan":
            if not self.config.target:
                self.console.print("❌ No target set. Use: /target <IP>", style="red")
            else:
                self.console.print(f"🔍 Scanning {self.config.target}...", style="cyan")
                # Add actual scan logic here
            return True
        
        # Status command
        if cmd == "/status":
            self._show_status()
            return True
        
        # Clear command
        if cmd == "/clear":
            import os
            os.system('cls' if os.name == 'nt' else 'clear')
            # Re-show banner and menu
            from drakben import show_banner
            show_banner()
            self.initialize()
            return True
        
        # Exit command
        if cmd in ["/exit", "/quit"]:
            return False
        
        # Stats command (hidden command)
        if cmd == "/stats":
            self._show_stats()
            return True
        
        # Not a system command - send to AI
        return None
    
    def _process_with_brain(self, user_input: str):
        """Process input with full AI brain intelligence"""
        lang = self.config.language
        
        # Save user input to memory
        self.memory.add_conversation("user", user_input)
        
        # Get full context from memory (includes conversation history, system profile, recent commands)
        full_context = self.memory.get_full_context_for_ai()
        
        # Update system context with memory data
        context = {
            "target": self.config.target or full_context.get("current_target"),
            "is_root": self.system_context["permissions"]["is_root"],
            "can_sudo": self.system_context["permissions"]["can_sudo"],
            "has_internet": self.system_context["network"]["connected"],
            "os": self.system_context["system"]["os"],
            "conversation_history": full_context.get("conversation_history", []),
            "system_profile": full_context.get("system_profile"),
            "recent_commands": full_context.get("recent_commands", []),
            "learned_patterns_count": full_context.get("learned_patterns_count", 0)
        }
        
        # Check if we have a learned pattern for similar intent
        learned_command = self.memory.get_best_command_for_intent(user_input[:50])
        if learned_command:
            context["suggested_command"] = learned_command
        
        # Show processing
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task(f"🧠 {t('thinking', lang)}...", total=None)
            
            # Brain processes the input
            result = self.brain.process(user_input, context)
        
        # Extract decision
        action = result.get("action")
        command = result.get("command")
        steps = result.get("steps", [])
        risks = result.get("risks", [])
        needs_approval = result.get("needs_approval", True)
        
        # Show what brain decided
        self.console.print(f"\n🎯 Intent: [bold cyan]{action}[/]")
        
        if risks:
            self.console.print(f"⚠️  Risks detected:", style="yellow")
            for risk in risks:
                self.console.print(f"  • {risk}", style="dim yellow")
        
        if steps:
            self.console.print(f"\n📋 Plan ({len(steps)} steps):", style="bold")
            for i, step in enumerate(steps, 1):
                self.console.print(f"  {i}. {step}", style="dim")
        
        # Safety check
        if command:
            safety_check = self.security.safe_execute_check(command, self.config.target)
            
            if not safety_check["safe"]:
                self.console.print(f"\n🛑 Command blocked by safety guard!", style="bold red")
                if safety_check["safety_check"]["blocked_reason"]:
                    self.console.print(f"   Reason: {safety_check['safety_check']['blocked_reason']}", style="red")
                return
            
            # Check if approval needed
            command_signature = f"{action}:{command[:50]}"
            
            if needs_approval and command_signature not in self.approved_commands:
                # Check memory for previous approval
                if self.memory.is_approved(command_signature):
                    self.approved_commands.add(command_signature)
                else:
                    # First time - ask approval
                    self.console.print(f"\n💡 Command: [bold yellow]{command}[/]")
                    approval = self.console.input(f"   Approve? (y/n) [bold green](y)[/] ").strip().lower()
                    
                    if approval not in ["y", "yes", "evet", ""]:
                        self.console.print("❌ Operation cancelled", style="yellow")
                        self.memory.add_conversation("assistant", f"Komut iptal edildi: {command}")
                        return
                    
                    # Remember approval - both in memory and session
                    self.approved_commands.add(command_signature)
                    self.memory.approve_command(command_signature)
                    self.console.print("✅ Approved - similar commands will run automatically", style="green")
            
            # Execute with retry and auto-healing
            self._execute_with_intelligence(command, steps, action)
        else:
            # No command to execute - just show info
            if action == "check_tools":
                self._show_tool_status()
            elif action == "need_target":
                self.console.print(f"\n⚠️  {t('need_target', lang)}", style="yellow")
    
    def _execute_with_intelligence(self, command: str, steps: List[str], intent: str = ""):
        """Execute command with full intelligence (retry, auto-heal, fallback)"""
        lang = self.config.language
        import time as time_module
        start_time = time_module.time()
        
        self.console.print(f"\n⚡ Executing...", style="bold cyan")
        
        # Try with retry and auto-healing
        result = self.solver.solve_with_retry(
            command=command,
            executor_func=lambda cmd: self.executor.execute_smart(cmd, optimize=True)
        )
        
        duration = time_module.time() - start_time
        
        if result["success"]:
            # Success!
            exec_result = result["result"]["result"]
            self.console.print(f"✅ Success! (took {exec_result.duration:.2f}s)", style="bold green")
            
            # AUTO-SAVE: Komut sonucunu hafızaya kaydet
            self.memory.log_command(
                command=command,
                stdout=exec_result.stdout[:5000] if exec_result.stdout else "",
                stderr=exec_result.stderr[:2000] if exec_result.stderr else "",
                return_code=exec_result.return_code,
                duration=exec_result.duration,
                success=True,
                context={"intent": intent, "target": self.config.target}
            )
            
            # AUTO-LEARN: Pattern'i öğren
            if intent:
                self.memory.learn_pattern(intent, command, success=True, context={"target": self.config.target})
            
            # Show output
            if exec_result.stdout:
                self.console.print("\n📄 Output:", style="bold")
                output_preview = exec_result.stdout[:500]
                self.console.print(output_preview, style="dim")
                if len(exec_result.stdout) > 500:
                    self.console.print("... (output truncated)", style="dim italic")
            
            # Analyze results
            analysis = result["result"]["analysis"]
            if analysis.get("insights"):
                self.console.print(f"\n💡 Insights:", style="bold yellow")
                for insight in analysis["insights"]:
                    self.console.print(f"  • {insight}", style="yellow")
                
                # AUTO-SAVE: Insights'ları assistant yanıtı olarak kaydet
                insights_text = "Analiz: " + ", ".join(analysis["insights"])
                self.memory.add_conversation("assistant", insights_text)
            
            # Report to security toolkit
            if analysis.get("tool"):
                self.security.reporter.add_scan_result(
                    tool=analysis["tool"],
                    target=self.config.target or "unknown",
                    result=analysis
                )
            
            self.command_count += 1
            
        else:
            # Failed even after retry
            error_info = result.get("error_info")
            attempts = result.get("attempts", 1)
            
            # AUTO-SAVE: Başarısız komutu da kaydet
            stderr_text = ""
            if result.get("result") and result["result"].get("stderr"):
                stderr_text = result["result"]["stderr"][:2000]
            
            self.memory.log_command(
                command=command,
                stdout="",
                stderr=stderr_text,
                return_code=-1,
                duration=duration,
                success=False,
                context={"intent": intent, "attempts": attempts, "target": self.config.target}
            )
            
            # AUTO-LEARN: Başarısız pattern'i de öğren
            if intent:
                self.memory.learn_pattern(intent, command, success=False, context={"error": str(error_info)})
            
            self.console.print(f"❌ Failed after {attempts} attempts", style="bold red")
            
            if error_info:
                self.console.print(f"\n🔍 Error Analysis:", style="bold")
                self.console.print(f"  Category: {error_info.category.value}", style="dim")
                self.console.print(f"  Message: {error_info.message[:200]}", style="dim red")
                
                # AUTO-SAVE: Hata analizini kaydet
                self.memory.add_conversation("assistant", f"Hata: {error_info.category.value} - {error_info.message[:200]}")
                
                if error_info.suggestions:
                    self.console.print(f"\n💡 Suggestions:", style="yellow")
                    for suggestion in error_info.suggestions[:3]:
                        self.console.print(f"  • {suggestion}", style="dim yellow")
                
                # Try to solve autonomously
                if error_info.auto_fixable:
                    self.console.print(f"\n🔧 Attempting auto-heal...", style="cyan")
                    
                    solution = self.solver.solve(
                        command=command,
                        error_output=result["result"]["stderr"],
                        executor_func=lambda cmd: self.executor.execute_smart(cmd)
                    )
                    
                    if solution.get("solved"):
                        self.console.print(f"✅ Auto-healed! Retry the command.", style="green")
                        self.memory.add_conversation("assistant", "Auto-heal başarılı oldu.")
                    elif solution.get("fallback_command"):
                        self.console.print(f"💡 Try fallback: {solution['fallback_command']}", style="yellow")
                        self.memory.add_conversation("assistant", f"Alternatif komut önerisi: {solution['fallback_command']}")
    
    def _show_status(self):
        """Show current system and agent status"""
        self.console.print("\n" + "="*60)
        self.console.print("📊 SYSTEM STATUS", style="bold cyan")
        self.console.print("="*60)
        
        # System info
        sys_info = self.system_intel.fingerprint.get_system_info()
        self.console.print(f"\n💻 System:", style="bold")
        self.console.print(f"  OS: {sys_info.os_name} {sys_info.os_version}")
        self.console.print(f"  Root: {'✅ Yes' if sys_info.is_root else '❌ No'}")
        self.console.print(f"  Internet: {'✅ Connected' if sys_info.has_internet else '❌ Disconnected'}")
        
        # Resources
        resources = self.system_intel.resources.get_resource_summary()
        self.console.print(f"\n{resources}")
        
        # Agent stats
        brain_stats = self.brain.get_stats()
        self.console.print(f"\n🤖 Agent:", style="bold")
        self.console.print(f"  Commands executed: {self.command_count}")
        self.console.print(f"  AI decisions: {brain_stats['decisions_made']}")
        self.console.print(f"  Auto-corrections: {brain_stats['corrections_made']}")
        
        # Solver stats
        solver_stats = self.solver.get_solver_summary()
        self.console.print(f"  Auto-healings: {solver_stats['total_healings']}")
        
        self.console.print("\n" + "="*60 + "\n")
    
    def _show_tool_status(self):
        """Show available pentesting tools"""
        self.console.print("\n🔧 Available Tools:", style="bold cyan")
        
        tools = self.security.toolkit.get_available_tools()
        available = [tool for tool, avail in tools.items() if avail]
        missing = [tool for tool, avail in tools.items() if not avail]
        
        if available:
            self.console.print(f"\n✅ Installed ({len(available)}):", style="green")
            for tool in available[:10]:  # Show first 10
                self.console.print(f"  • {tool}", style="dim green")
            if len(available) > 10:
                self.console.print(f"  ... and {len(available)-10} more", style="dim italic")
        
        if missing:
            self.console.print(f"\n❌ Missing ({len(missing)}):", style="red")
            for tool in missing[:5]:  # Show first 5
                install_cmd = self.system_intel.scanner.suggest_install_command(tool)
                self.console.print(f"  • {tool}: [dim]{install_cmd}[/]", style="dim red")
            if len(missing) > 5:
                self.console.print(f"  ... and {len(missing)-5} more", style="dim italic")
    
    def _show_stats(self):
        """Show detailed statistics including memory"""
        self.console.print("\n" + "="*60)
        self.console.print("📈 STATISTICS", style="bold cyan")
        self.console.print("="*60)
        
        # Memory stats (NEW)
        memory_stats = self.memory.get_session_stats()
        global_stats = self.memory.get_global_stats()
        self.console.print(f"\n🧠 Memory (Session):", style="bold")
        self.console.print(f"  Session ID: {memory_stats['session_id']}")
        self.console.print(f"  Messages: {memory_stats['conversation_count']}")
        self.console.print(f"  Commands: {memory_stats['commands_total']} ({memory_stats['commands_successful']} successful)")
        
        self.console.print(f"\n📚 Memory (Global):", style="bold")
        self.console.print(f"  Total Sessions: {global_stats['total_sessions']}")
        self.console.print(f"  Total Commands: {global_stats['total_commands']}")
        self.console.print(f"  Learned Patterns: {global_stats['learned_patterns']}")
        self.console.print(f"  Known Targets: {global_stats['total_targets']}")
        
        # Execution stats
        exec_summary = self.executor.get_execution_summary()
        self.console.print(f"\n⚡ Execution:", style="bold")
        self.console.print(f"  Total: {exec_summary['total_executions']}")
        self.console.print(f"  Successful: {exec_summary['successful']}")
        self.console.print(f"  Failed: {exec_summary['failed']}")
        self.console.print(f"  Avg duration: {exec_summary['average_duration']:.2f}s")
        
        # Brain stats
        brain_stats = self.brain.get_stats()
        self.console.print(f"\n🤖 AI Brain:", style="bold")
        for key, value in brain_stats.items():
            self.console.print(f"  {key}: {value}")
        
        # Solver stats
        solver_stats = self.solver.get_solver_summary()
        self.console.print(f"\n🔧 Auto-Solver:", style="bold")
        self.console.print(f"  Total healings: {solver_stats['total_healings']}")
        if solver_stats['healing_actions']:
            self.console.print(f"  Recent actions:")
            for action in solver_stats['healing_actions'][-3:]:
                self.console.print(f"    • {action['description']} ({action['risk']})")
        
        # Security stats
        security_summary = self.security.get_toolkit_summary()
        self.console.print(f"\n🛡️  Security:", style="bold")
        self.console.print(f"  Scans logged: {security_summary['scan_results']}")
        self.console.print(f"  Vulnerabilities: {security_summary['vulnerabilities']}")
        
        # System info from memory
        sys_info = self.memory.get_temp("system_info")
        if sys_info:
            self.console.print(f"\n💻 System (from memory):", style="bold")
            self.console.print(f"  OS: {sys_info.get('os', 'unknown')}")
            self.console.print(f"  Root: {'✅' if sys_info.get('is_root') else '❌'}")
            self.console.print(f"  Internet: {'✅' if sys_info.get('has_internet') else '❌'}")
        
        self.console.print("\n" + "="*60 + "\n")
    
    def _show_detailed_help(self):
        """Show detailed help"""
        help_text = """
╔═══════════════════════════════════════════════════════════╗
║                    DRAKBEN - Help                         ║
╚═══════════════════════════════════════════════════════════╝

🎯 COMMANDS:
  /help           - Show this help
  /target <IP>    - Set target (example: /target 192.168.1.1)
  /scan           - Scan current target
  /status         - Show system status
  /clear          - Clear screen (keeps menu)
  /exit           - Exit DRAKBEN

📌 NATURAL LANGUAGE:
  Talk naturally! AI will:
  • Create commands for you
  • Fix errors automatically
  • Install missing tools
  • Analyze results

  Examples:
    "scan 10.0.0.1"
    "find SQL injection on example.com"
    "test XSS on target.com"

⚡ FEATURES:
  ✅ Auto error fixing
  ✅ Auto tool installation
  ✅ Smart retry mechanism
  ✅ Security checks
  ✅ Approval system
  ✅ Full logging

🛡️ SECURITY:
  • Dangerous commands blocked
  • All actions logged
  • Risk analysis
  • Approval required

💡 TIP:
  Be clear and specific with your questions!
"""
        
        self.console.print(help_text, style="#F8F8F2")
    
    def run(self):
        """Main agent loop"""
        lang = self.config.language
        
        # AUTO-SAVE: Sistem bilgisini hafızaya kaydet
        self._save_system_info_to_memory()
        
        self.initialize()
        
        while self.running:
            if not self.input_handler():
                break
        
        # Goodbye
        self.console.print(f"\n👋 {t('goodbye', lang)} {t('thanks', lang)}", style="bold green")
        self.console.print(f"📊 Commands executed: {self.command_count}", style="dim")
        
        # AUTO-SAVE: Oturum istatistiklerini göster ve hafızayı kapat
        stats = self.memory.get_session_stats()
        self.console.print(f"💾 Session saved (ID: {stats['session_id']}, {stats['commands_total']} commands)", style="dim")
        self.memory.end_session(notes=f"Commands: {self.command_count}, Target: {self.config.target}")
    
    def _save_system_info_to_memory(self):
        """Sistem bilgisini hafızaya otomatik kaydet"""
        sys_info = {
            "os": self.system_context["system"]["os"],
            "os_version": self.system_context["system"].get("version", "unknown"),
            "hostname": self.system_context["system"].get("hostname", "unknown"),
            "is_root": self.system_context["permissions"]["is_root"],
            "can_sudo": self.system_context["permissions"]["can_sudo"],
            "has_internet": self.system_context["network"]["connected"],
            "python_version": self.system_context["system"].get("python_version", "unknown"),
            "available_tools": list(self.system_context.get("tools", {}).keys())[:20]
        }
        
        # Hafızaya sistem profilini kalıcı kaydet
        self.memory.save_system_profile(sys_info)
        
        # Geçici hafızaya da kaydet (hızlı erişim için)
        self.memory.set_temp("system_info", sys_info, ttl_seconds=3600)
        
        # Sistem context'ini conversation olarak da kaydet
        self.memory.add_conversation(
            "system", 
            f"Sistem: {sys_info['os']} | Root: {sys_info['is_root']} | Internet: {sys_info['has_internet']}",
            metadata=sys_info
        )
