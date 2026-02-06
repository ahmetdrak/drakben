import os
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, LiteralString

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.table import Table

    from core.agent.brain import DrakbenBrain
    from core.agent.refactored_agent import RefactoredDrakbenAgent
    from core.agent.state import AgentState
    from core.execution.execution_engine import ExecutionResult
    from core.execution.tool_selector import ToolSpec

from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text

# prompt_toolkit for protected prompt
try:
    from prompt_toolkit import prompt as pt_prompt
    from prompt_toolkit.formatted_text import HTML

    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

from core.config import ConfigManager, DrakbenConfig
from core.security.kali_detector import KaliDetector


class DrakbenMenu:
    """DRAKBEN Minimal Menu System.

    COMMANDS (Only 7):
    - /help     : Help
    - /target   : Set target
    - /scan     : Scan
    - /clear    : Clear screen (menu remains)
    - /tr       : Turkish
    - /en       : English
    - /exit     : Exit

    Everything else goes to AI.
    """

    # Dracula Theme
    COLORS: dict[str, str] = {
        "red": "#FF5555",
        "green": "#50FA7B",
        "yellow": "#F1FA8C",
        "purple": "#8BE9FD",  # Cyan (Hacker Blue) - Dracula Cyan
        "cyan": "#8BE9FD",
        "pink": "#FFB86C",  # Orange - Replaced Pink
        "fg": "#F8F8F2",
    }

    # Rich style constants (SonarCloud: avoid duplicate literals)
    STYLE_BOLD_WHITE = "bold white"
    STYLE_BOLD_GREEN = "bold green"
    STYLE_BOLD_CYAN = "bold cyan"
    STYLE_BOLD_YELLOW = "bold yellow"
    STYLE_BOLD_RED = "bold red"
    STYLE_DIM_CYAN = "dim cyan"
    STYLE_DIM_RED = "dim red"
    MSG_AGENT_NOT_NONE = "self.agent is not None"

    # Command constants (SonarCloud: avoid duplicate literals)
    CMD_SCAN = "/scan"
    CMD_SHELL = "/shell"
    CMD_STATUS = "/status"
    CMD_CLEAR = "/clear"
    CMD_EXIT = "/exit"
    CMD_REPORT = "/report"
    CMD_CONFIG = "/config"
    CMD_UNTARGET = "/untarget"
    CMD_TOOLS = "/tools"
    CMD_MEMORY = "/memory"

    # Modern minimal banner - inspired by professional tools like sqlmap, sherlock
    BANNER = r"""
 ██████╗ ██████╗  █████╗ ██╗  ██╗██████╗ ███████╗███╗   ██╗
 ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝████╗  ██║
 ██║  ██║██████╔╝███████║█████╔╝ ██████╔╝█████╗  ██╔██╗ ██║
 ██║  ██║██╔══██╗██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║╚██╗██║
 ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝███████╗██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
    """
    VERSION = "2.0.0"

    def __init__(self, config_manager: ConfigManager) -> None:
        self.config_manager: ConfigManager = config_manager
        self.config: DrakbenConfig = config_manager.config
        self.console: Console = Console(color_system="truecolor")
        self.kali = KaliDetector()
        self.agent: RefactoredDrakbenAgent | None = None
        self.brain: DrakbenBrain | None = None
        self.orchestrator = None  # New: PentestOrchestrator
        self.running = True
        self.system_info: dict[str, Any] = {}
        self._commands: dict[str, Callable[[str], Any]] = {
            "/help": self._cmd_help,
            "/target": self._cmd_target,
            self.CMD_SCAN: self._cmd_scan,
            self.CMD_SHELL: self._cmd_shell,
            self.CMD_STATUS: self._cmd_status,
            "/llm": self._cmd_llm_setup,
            self.CMD_CLEAR: self._cmd_clear,
            "/tr": self._cmd_turkish,
            "/en": self._cmd_english,
            self.CMD_EXIT: self._cmd_exit,
            "/research": self._cmd_research,
            self.CMD_REPORT: self._cmd_report,
            self.CMD_CONFIG: self._cmd_config,
            self.CMD_UNTARGET: self._cmd_untarget,
            self.CMD_TOOLS: self._cmd_tools,
            self.CMD_MEMORY: self._cmd_memory,
        }

        # System detection
        self._detect_system()

        # Initialize orchestrator
        self._init_orchestrator()

    def _init_orchestrator(self) -> None:
        """Initialize the pentest orchestrator."""
        try:
            from core.agent.pentest_orchestrator import get_orchestrator

            # Try to get LLM client
            llm_client = None
            try:
                from llm.openrouter_client import OpenRouterClient
                llm_client = OpenRouterClient()
                # Check if API key is configured
                if not getattr(llm_client, "api_key", None):
                    llm_client = None
            except (ImportError, OSError, AttributeError):
                pass

            self.orchestrator = get_orchestrator(llm_client)
            self.orchestrator.context.language = self.config.language
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Orchestrator init failed: {e}")
            self.orchestrator = None

    def _detect_system(self) -> None:
        """Detect system and save info."""
        import platform

        self.system_info = {
            "os": platform.system(),
            "os_version": platform.release(),
            "is_kali": self.kali.is_kali(),
            "python_version": platform.python_version(),
            "available_tools": self.kali.get_available_tools(),
        }

    def show_banner(self) -> None:
        """Show banner - Modern professional style inspired by sqlmap/sherlock."""
        if not self.BANNER.strip():
            return

        lines: list[LiteralString] = self.BANNER.strip("\n").split("\n")
        text = Text()

        # Gradient: Cyan (#8BE9FD) -> Purple (#BD93F9) - Dracula theme
        color_start = (139, 233, 253)  # Cyan RGB
        color_end = (189, 147, 249)    # Purple RGB
        total_lines: int = len(lines)

        for y, line in enumerate(lines):
            # Calculate gradient position (0.0 to 1.0)
            progress = y / max(total_lines - 1, 1)
            # Linear interpolation between colors
            r = int(color_start[0] + (color_end[0] - color_start[0]) * progress)
            g = int(color_start[1] + (color_end[1] - color_start[1]) * progress)
            b = int(color_start[2] + (color_end[2] - color_start[2]) * progress)
            color = f"#{r:02x}{g:02x}{b:02x}"

            text.append(line, style=f"bold {color}")
            text.append("\n")

        self.console.print(text)

        # Compact info line - professional style like sqlmap
        is_tr = self.config.language == "tr"
        os_name = "Kali" if self.system_info.get("is_kali") else self.system_info.get("os", "Unknown")

        info_line = Text()
        info_line.append(" DRAKBEN", style=self.STYLE_BOLD_WHITE)
        info_line.append(f" v{self.VERSION}", style="dim")
        info_line.append(" │ ", style="dim")
        if is_tr:
            info_line.append("Otonom Pentest AI", style="cyan")
        else:
            info_line.append("Autonomous Pentest AI", style="cyan")
        info_line.append(" │ ", style="dim")
        info_line.append(os_name, style="green")

        self.console.print(info_line)
        self.console.print()

    def _get_status_labels(self, is_tr: bool) -> tuple[str, str, str, str]:
        """Get localized status labels."""
        return (
            "HEDEF" if is_tr else "TARGET",
            "SİSTEM" if is_tr else "SYSTEM",
            "MOD" if is_tr else "MODE",
            "KOMUTLAR" if is_tr else "COMMANDS",
        )

    def _get_mode_info(self, is_tr: bool) -> tuple[str, str]:
        """Get stealth mode display info."""
        is_stealth = getattr(self.config, "stealth_mode", False)
        # Avoid nested ternary for SonarQube compliance
        if is_stealth:
            status = "GİZLİ" if is_tr else "STEALTH"
            color = self.STYLE_BOLD_GREEN
        else:
            status = "NORMAL"  # Same in both languages
            color = "dim"
        return status, color

    def show_status_line(self) -> None:
        """Compact professional status line - inspired by modern CLI tools."""
        from rich.text import Text

        is_tr = self.config.language == "tr"

        # Build compact status line
        status = Text()

        # Target section
        target = self.config.target
        if target:
            status.append(" TARGET ", style="black on green")
            status.append(f" {target} ", style=self.STYLE_BOLD_WHITE)
        else:
            no_target = "Hedef yok" if is_tr else "No target"
            status.append(" TARGET ", style="black on red")
            status.append(f" {no_target} ", style="dim")

        status.append(" │ ", style="dim")

        # Mode section
        mode_text, mode_color = self._get_mode_info(is_tr)
        status.append(mode_text, style=mode_color)

        status.append(" │ ", style="dim")

        # LLM section
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            model = info.get("model", "N/A")
            # Shorten model name
            short_model = model.split("/")[-1][:20] if "/" in model else model[:20]
            status.append("LLM ", style="dim")
            status.append(short_model, style="green")
        else:
            llm_off = "LLM kapalı" if is_tr else "LLM off"
            status.append(llm_off, style=self.STYLE_DIM_RED)

        self.console.print(status)

        # Quick commands hint
        help_lbl = "Yardım:" if is_tr else "Help:"
        self.console.print(f"[dim]{help_lbl}[/] [green]/help[/]")
        self.console.print()

    def run(self) -> None:
        """Main loop."""
        # Initial start - show banner and status
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

        lang: str = self.config.language
        self._show_welcome_message(lang)

        # PLUGINS: Register external tools
        self._load_plugins_at_startup(lang)

        # MAIN LOOP
        while self.running:
            if not self._run_main_loop_iteration(lang):
                break

        # Exit
        msg: str = "Görüşürüz!" if lang == "tr" else "Goodbye!"
        self.console.print(f"[dim]{msg}[/]")

    def _run_main_loop_iteration(self, lang: str) -> bool:
        """Run a single iteration of the main loop.

        Returns:
            True to continue, False to exit
        """
        try:
            # Get user input with protected prompt
            user_input: str = self._get_input().strip()

            if not user_input:
                return True

            # Is it a slash command?
            if user_input.startswith("/"):
                self._handle_command(user_input)
            else:
                # Send to AI
                self._process_with_ai(user_input)
            return True

        except KeyboardInterrupt:
            return self._handle_keyboard_interrupt(lang)
        except EOFError:
            return False

    def _handle_keyboard_interrupt(self, lang: str) -> bool:
        """Handle Ctrl+C in main menu.

        Returns:
            True to continue, False to exit
        """
        self.console.print("\n")
        confirm_msg = (
            "Çıkmak istiyor musunuz? (e/h)"
            if lang == "tr"
            else "Do you want to exit? (y/n)"
        )
        try:
            response = Prompt.ask(confirm_msg, choices=["e", "h", "y", "n"], default="h")
            if response.lower() in ["e", "y"]:
                return False
            self.console.print("👍 Menüye dönüldü.\n", style="green")
            return True
        except (KeyboardInterrupt, EOFError):
            # Double Ctrl+C = Force exit
            return False

    def _show_welcome_message(self, lang: str) -> None:
        """Helper to show welcome message."""
        if lang == "tr":
            self.console.print(
                "[dim]Hazır.[/] [green]/help[/] [dim]yazın veya doğal dilde komut verin.[/]\n",
            )
        else:
            self.console.print(
                "[dim]Ready. Type[/] [green]/help[/] [dim]or use natural language.[/]\n",
            )

    def _load_plugins_at_startup(self, lang: str) -> None:
        """Helper to safely load plugins without polluting run() method."""
        try:
            from core.plugin_loader import PluginLoader

            loader = PluginLoader()
            plugins: dict[str, ToolSpec] = loader.load_plugins()

            if plugins:
                msg: str = (
                    f"🔌 {len(plugins)} Plugin Yüklendi"
                    if lang == "tr"
                    else f"🔌 {len(plugins)} Plugins Loaded"
                )
                self.console.print(f"[dim green]{msg}[/dim]")

                # Enterprise Plugin Registration (No Monkey Patching)
                from core.execution.tool_selector import ToolSelector

                ToolSelector.register_global_plugins(plugins)

        except Exception as e:
            self.console.print(f"[{self.STYLE_DIM_RED}]Plugin Load Error: {e}[/]")

    def _get_input(self) -> str:
        """Get user input with protected prompt that can't be deleted."""
        if PROMPT_TOOLKIT_AVAILABLE:
            # prompt_toolkit protects the prompt from being deleted
            if self.config.target:
                prompt_text = HTML(
                    f'<style fg="#8BE9FD" bg="" bold="true">drakben</style>'
                    f'<style fg="#8BE9FD">@{self.config.target}</style>'
                    f'<style fg="#F8F8F2">&gt; </style>',
                )
            else:
                prompt_text = HTML(
                    '<style fg="#8BE9FD" bg="" bold="true">drakben</style>'
                    '<style fg="#F8F8F2">&gt; </style>',
                )
            try:
                return pt_prompt(prompt_text)
            except (EOFError, KeyboardInterrupt):
                return self.CMD_EXIT
        else:
            # Fallback: print prompt then input
            prompt = Text()
            prompt.append("drakben", style=f"bold {self.COLORS['purple']}")
            if self.config.target:
                prompt.append(
                    f"@{self.config.target}",
                    style=f"bold {self.COLORS['cyan']}",
                )
            prompt.append("> ", style=self.COLORS["fg"])
            self.console.print(prompt, end="")
            return input()

    def _handle_command(self, user_input: str) -> None:
        """Handle slash commands."""
        if not user_input or not user_input.strip():
            return

        parts: list[str] = user_input.split(maxsplit=1)
        if not parts:
            return

        cmd: str = parts[0].lower()
        args: str = parts[1] if len(parts) > 1 else ""

        if cmd in self._commands:
            self._commands[cmd](args)
        else:
            lang: str = self.config.language
            msg: str = (
                "Bilinmeyen komut. /help yazın."
                if lang == "tr"
                else "Unknown command. Type /help."
            )
            self.console.print(f"❌ {msg}", style="red")

    def _process_with_ai(self, user_input: str) -> None:
        """Process with AI using the new orchestrator.

        Uses PentestOrchestrator for:
        - State management
        - Focused LLM prompts
        - Tool execution
        - Output analysis
        """
        lang: str = self.config.language

        # ====== DOĞAL DİLDEN HEDEF ÇIKARMA ======
        extracted_target = self._extract_target_from_text(user_input)
        if extracted_target and not self.config.target:
            self.config.target = extracted_target
            if self.orchestrator:
                self.orchestrator.set_target(extracted_target)
            self.console.print(
                f"[bold green]Hedef ayarlandı: {extracted_target}[/]",
            )

        # Use orchestrator if available
        if self.orchestrator:
            self._process_with_orchestrator(user_input, lang)
            return

        # Fallback to old brain if orchestrator not available
        self._process_with_brain_fallback(user_input, lang)

    def _process_with_orchestrator(self, user_input: str, lang: str) -> None:
        """Process input using the new orchestrator."""
        thinking = "İşleniyor..." if lang == "tr" else "Processing..."

        try:
            # Track if target was set before
            target_before = self.config.target

            with self.console.status(f"[bold {self.COLORS['purple']}]{thinking}"):
                # Sync language
                self.orchestrator.context.language = lang

                # Use orchestrator chat (handles action detection internally)
                result = self.orchestrator.chat(user_input)

            # Check if orchestrator extracted and set a new target
            new_target = self.orchestrator.context.target
            if new_target and new_target != target_before:
                # Sync to config
                self.config_manager.set_target(new_target)
                self.config = self.config_manager.config
                self.console.print(f"\n[bold green]Hedef ayarlandi: {new_target}[/]")

            if result.get("success"):
                response = result.get("response", "")
                intent = result.get("intent", "chat")

                # Show response
                if response:
                    self.console.print(f"\n[DRAKBEN] {response}\n", style=self.COLORS["cyan"])

                # If intent is needs_target, don't show actions
                if intent == "needs_target":
                    return

                # Show suggested actions if target is set and intent is action
                if self.config.target and intent == "action":
                    self._show_orchestrator_actions(lang)
            else:
                error = result.get("error", "Unknown error")
                self.console.print(f"\n[red]Hata: {error}[/]\n")

        except KeyboardInterrupt:
            cancel_msg = "Iptal edildi." if lang == "tr" else "Cancelled."
            self.console.print(f"\n[yellow]{cancel_msg}[/]")

    def _show_orchestrator_actions(self, lang: str) -> None:
        """Show suggested actions and ask user to run."""
        from rich.panel import Panel

        actions = self.orchestrator._get_phase_actions()
        if not actions:
            return

        # Build and show panel
        self._display_actions_panel(actions, lang, Panel)

        # Handle user input
        self._handle_action_selection(actions, lang)

    def _display_actions_panel(self, actions: list, lang: str, Panel: type) -> None:
        """Display the actions panel."""
        title = "Suggested Actions" if lang == "en" else "Önerilen Eylemler"
        lines = []
        for i, action in enumerate(actions[:3], 1):
            tool = action.get("tool", "?")
            desc = action.get("description", "")
            cmd = action.get("command", "")
            lines.append(f"  {i}. [{tool}] {desc}")
            if cmd:
                lines.append(f"     > {cmd}")
        content = "\n".join(lines)
        self.console.print(Panel(content, title=title, border_style=self.STYLE_DIM_CYAN, padding=(0, 1)))

    def _handle_action_selection(self, actions: list, lang: str) -> None:
        """Handle user selection of actions."""
        if not actions:
            return
        first_cmd = actions[0].get("command", "")
        if not first_cmd:
            return

        prompt_msg = "Run? [y/n/2/3/s]" if lang == "en" else "Çalıştır? [e/h/2/3/s]"
        try:
            resp = Prompt.ask(prompt_msg, default="y" if lang == "en" else "e").lower().strip()
            self._execute_selected_action(resp, actions, lang)
        except KeyboardInterrupt:
            pass

    def _execute_selected_action(self, resp: str, actions: list, lang: str) -> None:
        """Execute the selected action based on user response."""
        if resp in {"y", "e"}:
            self._execute_with_orchestrator(actions[0].get("command", ""))
        elif resp == "2" and len(actions) > 1:
            self._execute_with_orchestrator(actions[1].get("command", ""))
        elif resp == "3" and len(actions) > 2:
            self._execute_with_orchestrator(actions[2].get("command", ""))
        elif resp == "s":
            skip_msg = "Skipped." if lang == "en" else "Atlandı."
            self.console.print(f"[dim]{skip_msg}[/]\n")

    def _execute_with_orchestrator(self, command: str) -> None:
        """Execute command through orchestrator (with LLM analysis)."""
        self.console.print(f"\n[{self.STYLE_BOLD_CYAN}]> {command}[/]\n")

        try:
            # Execute via orchestrator - this triggers LLM analysis
            result = self.orchestrator.execute_tool(command, live_output=True, analyze=True)

            if result.get("success"):
                # Show analysis if present
                analysis = result.get("analysis", {})
                if analysis:
                    findings = analysis.get("findings", [])
                    next_action = analysis.get("next_action")

                    if findings:
                        self.console.print("\n[bold]Findings:[/]")
                        for f in findings[:5]:
                            self.console.print(f"  [+] {f}")

                    if next_action:
                        self.console.print(f"\n[dim]Suggested next: {next_action}[/]")

                # Advance phase if appropriate
                self.orchestrator.advance_phase()
            else:
                error = result.get("error", "Command failed")
                self.console.print(f"\n[red][-] {error}[/]")

        except Exception as e:
            self.console.print(f"\n[red][-] Error: {e}[/]")

    def _process_with_brain_fallback(self, user_input: str, lang: str) -> None:
        """Fallback to old brain processing."""
        from core.ui.unified_display import ThinkingDisplay

        # Lazy load brain
        if not self.brain:
            from core.agent.brain import DrakbenBrain
            self.brain = DrakbenBrain()

        # Use unified thinking display
        thinking_display = ThinkingDisplay(console=self.console, language=lang)

        try:
            # Get phase from orchestrator if available
            phase = ""
            if self.orchestrator:
                phase = getattr(self.orchestrator, "current_phase", "")

            thinking_display.start_thinking(
                target=self.config.target or "",
                phase=phase,
                model=getattr(self.brain, "model_name", "") if self.brain else "",
            )

            if self.brain is None:
                msg = "self.brain is not None"
                raise AssertionError(msg)

            # Update display while thinking
            thinking_display.update(sub_message=user_input[:50] + "..." if len(user_input) > 50 else user_input)

            result = self.brain.think(user_input, self.config.target, lang)

            # Check if LLM had errors
            llm_success = result.get("success", True) if isinstance(result, dict) else True
            if not llm_success:
                error_msg = result.get("error", "Unknown error") if isinstance(result, dict) else "Error"
                thinking_display.finish_thinking(success=False)
                self.console.print(f"[red]LLM Error: {error_msg}[/]")
                return

            # Mark as analyzing
            thinking_display.set_analyzing("response")

            # Finish thinking display
            thinking_display.finish_thinking(success=True)

            # Show AI response text
            self._handle_ai_response_text(result, lang)

            # Process steps with approval (interactive mode)
            steps = result.get("steps", [])
            if steps and isinstance(steps, list) and len(steps) > 0:
                self._execute_steps_with_approval(steps, lang)
            else:
                # Single command mode (backward compatibility)
                self._handle_ai_command(result, lang)

        except KeyboardInterrupt:
            # Ctrl+C during LLM thinking = Cancel and return to prompt
            self.console.print("\n🛑 İptal edildi.", style="yellow")

    def _execute_steps_with_approval(self, steps: list, lang: str) -> None:
        """Execute plan steps with user approval for each step.

        Args:
            steps: List of step dicts with 'command', 'tool', 'description'
            lang: Language code ('tr' or 'en')
        """
        total = len(steps)

        for i, step in enumerate(steps, 1):
            result = self._process_single_step(step, i, total, lang)
            if result == "stop":
                return
            # result == "skip" or "done" -> continue loop

        # Completion message
        done_msg = "✅ Tüm adımlar tamamlandı." if lang == "tr" else "✅ All steps completed."
        self.console.print(f"\n{done_msg}\n", style="green")

    def _process_single_step(self, step: dict, index: int, total: int, lang: str) -> str:
        """Process a single step with approval.

        Returns:
            'stop' - Stop all remaining steps
            'skip' - Step was skipped
            'done' - Step was executed
        """
        from core.ui.unified_display import ConfirmationRequest, RiskLevel, UnifiedConfirmation

        command = step.get("command") or step.get("tool", "")
        if not command:
            return "skip"

        # Determine risk level based on command
        risk_level = self._get_command_risk_level(command)

        # Show step info
        description = step.get("description", "")
        step_header = f"[{index}/{total}] {description}" if description else f"[{index}/{total}]"
        self.console.print(f"\n⏳ {step_header}", style="cyan")

        # Use unified confirmation
        confirmation = UnifiedConfirmation(console=self.console, language=lang)
        request = ConfirmationRequest(
            command=command,
            risk_level=risk_level,
            reason=description or (f"Step {index} of {total}"),
            details=[f"Tool: {step.get('tool', 'shell')}" if step.get("tool") else ""],
            allow_auto=risk_level == RiskLevel.LOW,
        )

        approved = confirmation.ask(request)

        if not approved:
            skip_msg = "⏭️ Adım atlandı." if lang == "tr" else "⏭️ Step skipped."
            self.console.print(skip_msg, style="dim")
            return "skip"

        # Execute the command
        self._execute_command(command)
        self._show_next_step_hint(index, total, step, lang)
        return "done"

    def _get_command_risk_level(self, command: str) -> Any:
        """Determine risk level for a command."""
        from core.ui.unified_display import RiskLevel

        command_lower = command.lower()

        # Critical risk patterns
        critical_patterns = ["rm -rf", "mkfs", "dd if=", "> /dev/", "shutdown", "reboot"]
        if any(p in command_lower for p in critical_patterns):
            return RiskLevel.CRITICAL

        # High risk patterns
        high_patterns = ["sudo", "exploit", "msfconsole", "reverse", "shell", "payload"]
        if any(p in command_lower for p in high_patterns):
            return RiskLevel.HIGH

        # Medium risk patterns
        medium_patterns = ["nmap", "nikto", "sqlmap", "hydra", "gobuster", "curl", "wget"]
        if any(p in command_lower for p in medium_patterns):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _show_next_step_hint(self, current_idx: int, total: int, steps: dict, lang: str) -> None:
        """Show hint about next step if available."""
        # Note: steps parameter not used here, but kept for potential future use
        if current_idx >= total:
            return
        next_msg = "⏳ Sonraki adıma geçiliyor..." if lang == "tr" else "⏳ Moving to next step..."
        self.console.print(f"\n{next_msg}", style=self.STYLE_DIM_CYAN)

    def _ask_step_approval(self, lang: str) -> str:
        """Ask user for step approval.

        Returns:
            'yes' - Execute the step
            'no' - Skip the step
            'stop' - Stop all remaining steps
        """
        prompt_text, choices, yes_set, stop_set = self._get_approval_config(lang)

        try:
            resp = Prompt.ask(prompt_text, choices=choices, default=choices[0])
            if resp in yes_set:
                return "yes"
            if resp in stop_set:
                return "stop"
            return "no"
        except KeyboardInterrupt:
            return "stop"

    def _get_approval_config(self, lang: str) -> tuple[str, list[str], set[str], set[str]]:
        """Get approval prompt configuration for language.

        Returns:
            Tuple of (prompt_text, choices, yes_choices_set, stop_choices_set)
        """
        if lang == "tr":
            return (
                "Çalıştır? [e]vet/[h]ayır/[d]urdur",
                ["e", "h", "d"],
                {"e"},
                {"d"},
            )
        return (
            "Run? [y]es/[n]o/[s]top",
            ["y", "n", "s"],
            {"y"},
            {"s"},
        )
    def _extract_target_from_text(self, text: str) -> str | None:
        """Doğal dilden hedef (domain/IP) çıkar.

        Örnekler:
        - "filmfabrikasi.com sitesini tara" -> filmfabrikasi.com
        - "192.168.1.1 adresini kontrol et" -> 192.168.1.1
        - "https://example.com'u tara" -> example.com
        """
        import re

        # URL pattern (with protocol)
        url_match = re.search(
            r"https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}",
            text,
        )
        if url_match:
            # Extract just the domain
            domain = url_match.group(0)
            domain = re.sub(r"^https?://", "", domain)
            domain = domain.split("/")[0]
            return domain

        # Domain pattern (without protocol)
        domain_match = re.search(
            r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b",
            text,
        )
        if domain_match:
            return domain_match.group(0)

        # IP address pattern
        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            text,
        )
        if ip_match:
            return ip_match.group(0)

        return None

    def _handle_ai_response_text(self, result: Any, lang: str) -> None:
        """Handle displaying the AI response text."""
        response_text = self._extract_response_text(result)

        if response_text:
            self.console.print(f"\n[DRAKBEN] {response_text}\n", style=self.COLORS["cyan"])
            self._show_planned_steps(result, lang)
        elif result.get("error"):
            self.console.print(f"\n❌ Hata: {result['error']}\n", style="red")
        else:
            self._show_offline_message(lang)

    def _extract_response_text(self, result: Any) -> str | None:
        """Extract response text from result dict."""
        return (
            result.get("llm_response")
            or result.get("reply")
            or result.get("response")
            or result.get("reasoning")
        )

    def _show_planned_steps(self, result: Any, lang: str) -> None:
        """Show planned steps from AI response."""
        from rich.panel import Panel

        steps = result.get("steps", [])
        if not steps or not isinstance(steps, list):
            return

        step_lines = []
        for i, s in enumerate(steps[:5]):
            action = s.get("action", s.get("tool", "unknown"))
            desc = s.get("description", s.get("tool", ""))[:50]
            step_lines.append(f"  {i+1}. {action} - {desc}")

        step_text = "\n".join(step_lines)
        if step_text.strip():
            title = "Planlanan Adimlar" if lang == "tr" else "Planned Steps"
            self.console.print(
                Panel(step_text, title=title, border_style=self.STYLE_DIM_CYAN, padding=(0, 1)),
            )

    def _show_confidence(self, result: Any) -> None:
        """Show confidence score with color coding."""
        confidence = result.get("confidence", 0)
        if confidence <= 0:
            return

        conf_color = self._get_confidence_color(confidence)
        self.console.print(f"   [dim]Güven: [{conf_color}]{confidence:.0%}[/][/dim]")

    def _get_confidence_color(self, confidence: float) -> str:
        """Get color for confidence level."""
        if confidence > 0.7:
            return "green"
        if confidence > 0.4:
            return "yellow"
        return "red"

    def _show_offline_message(self, lang: str) -> None:
        """Show offline/no connection message."""
        offline_msg = (
            "LLM bağlantısı yok. Lütfen API ayarlarını kontrol edin."
            if lang == "tr"
            else "No LLM connection. Please check API settings."
        )
        self.console.print(f"\n⚠️ {offline_msg}\n", style="yellow")

    def _handle_ai_command(self, result: Any, lang: str) -> None:
        """Handle executing a single command suggested by AI (backward compatibility)."""
        command = result.get("command")
        if not command:
            return

        # FIX: Auto-approve internal slash commands (/scan, /target)
        if command.strip().startswith("/"):
            # Print it so user sees it happens
            self.console.print(f"🤖 Otomatik işlem: {command}", style="dim")
            self._execute_command(command)
            return

        # Show command in panel
        from rich.panel import Panel
        self.console.print(
            Panel(
                f"💻 {command}",
                border_style="yellow",
                padding=(0, 1),
            ),
        )

        # Ask for approval with proper language support
        approval = self._ask_step_approval(lang)

        if approval == "yes":
            self._execute_command(command)
        elif approval == "stop":
            stop_msg = "⚠️ İşlem durduruldu." if lang == "tr" else "⚠️ Operation stopped."
            self.console.print(f"\n{stop_msg}\n", style="yellow")
        else:
            skip_msg = "⏭️ Komut atlandı." if lang == "tr" else "⏭️ Command skipped."
            self.console.print(skip_msg, style="dim")

    def _execute_command(self, command: str) -> None:
        """Execute command."""
        lang: str = self.config.language

        # FIX: Check if this is an internal slash command recommended by AI
        if command.strip().startswith("/"):
            self.console.print(
                f"🔄 Dahili komut çalıştırılıyor: {command}",
                style="dim",
            )
            self._handle_command(command)
            return

        # Agent lazy load
        if not self.agent:
            from core.agent.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)
            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)
            self.agent.initialize(target=self.config.target or "")

        msg: str = "Çalıştırılıyor..." if lang == "tr" else "Executing..."
        self.console.print(f"⚡ {msg}", style=self.COLORS["yellow"])

        if self.agent is None:
            raise AssertionError(self.MSG_AGENT_NOT_NONE)
        if self.agent.executor is None:
            msg = "self.agent.executor is not None"
            raise AssertionError(msg)
        result: ExecutionResult = self.agent.executor.terminal.execute(
            command,
            timeout=300,
        )

        if result.status.value == "success":
            self.console.print(
                f"✅ OK ({result.duration:.1f}s)",
                style=self.COLORS["green"],
            )
            if result.stdout:
                # First 500 chars for display
                self.console.print(result.stdout[:500], style="dim")
        else:
            self.console.print(f"❌ Hata: {result.stderr[:150]}", style="red")

        # FEEDBACK LOOP: Report back to brain so it remembers!
        if self.brain:
            output_content: str = result.stdout if result.stdout else result.stderr
            tool_name: str = command.split()[0]
            self.brain.observe(
                tool=tool_name,
                output=output_content,
                success=(result.status.value == "success"),
            )

    # ========== COMMANDS ==========

    def _cmd_research(self, args: str) -> None:
        """Web research command."""
        if not args:
            self.console.print("[dim]Usage: /research <query>[/]")
            return

        if isinstance(args, list):
            query: str = " ".join(args)
        else:
            query = str(args)
        self.console.print(f"[cyan]Searching: {query}[/]")

        try:
            from core.network.web_researcher import WebResearcher

            researcher = WebResearcher()
            results = researcher.search_tool(query)

            if not results:
                self.console.print("[red]No results found.[/]")
                return

            self.console.print(f"\n[green]Found {len(results)} results:[/]\n")
            for i, r in enumerate(results, 1):
                self.console.print(f"{i}. [bold]{r['title']}[/]")
                self.console.print(f"   [cyan underline]{r['href']}[/]")
                body: Any | str = (
                    r.get("body", "")[:200] + "..."
                    if r.get("body")
                    else "No description."
                )
                self.console.print(f"   [dim]{body}[/]\n")

        except Exception as e:
            self.console.print(f"[red]Error: {e}[/]")

    def _cmd_help(self, args: str = "") -> None:
        """Help command - Clean minimal style."""
        from rich.table import Table

        lang: str = self.config.language
        is_tr = lang == "tr"

        # Compact command table
        table = Table(show_header=True, box=None, padding=(0, 3))
        table.add_column("Command" if not is_tr else "Komut", style="cyan", width=18)
        table.add_column("Description" if not is_tr else "Açıklama", style="dim")

        if is_tr:
            commands: list[tuple[str, str]] = [
                ("/target <IP>", "Hedef belirle"),
                (self.CMD_UNTARGET, "Hedefi temizle"),
                (self.CMD_SCAN, "Tarama başlat"),
                (self.CMD_STATUS, "Durum göster"),
                (self.CMD_TOOLS, "Araçları listele"),
                (self.CMD_REPORT, "Rapor oluştur"),
                (self.CMD_SHELL, "Terminal erişimi"),
                (self.CMD_CONFIG, "Ayarlar"),
                (self.CMD_MEMORY, "Hafıza durumu"),
                ("/llm", "LLM ayarları"),
                ("/tr /en", "Dil değiştir"),
                (self.CMD_CLEAR, "Ekranı temizle"),
                (self.CMD_EXIT, "Çıkış"),
            ]
        else:
            commands: list[tuple[str, str]] = [
                ("/target <IP>", "Set target"),
                (self.CMD_UNTARGET, "Clear target"),
                (self.CMD_SCAN, "Start scan"),
                (self.CMD_STATUS, "Show status"),
                (self.CMD_TOOLS, "List tools"),
                (self.CMD_REPORT, "Generate report"),
                (self.CMD_SHELL, "Terminal access"),
                (self.CMD_CONFIG, "Settings"),
                (self.CMD_MEMORY, "Memory status"),
                ("/llm", "LLM settings"),
                ("/tr /en", "Change language"),
                (self.CMD_CLEAR, "Clear screen"),
                (self.CMD_EXIT, "Exit"),
            ]

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        self.console.print()
        self.console.print(table)
        self.console.print()

        # Natural language tip
        if is_tr:
            self.console.print('[dim]Doğal dilde de yazabilirsiniz: "10.0.0.1 tara"[/]')
        else:
            self.console.print('[dim]Or type naturally: "scan 10.0.0.1"[/]')
        self.console.print()

    def _validate_target(self, target: str) -> bool:
        """Validate if the target is a valid IP or Domain."""
        # IP Regex
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        # Domain Regex
        domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"

        return bool(
            re.match(ip_pattern, target)
            or re.match(domain_pattern, target, re.IGNORECASE),
        )

    def _show_current_target_info(self, lang: str) -> None:
        """Display current target information - minimal style."""
        current_target = self.config.target
        if current_target:
            if lang == "tr":
                self.console.print(f"Mevcut hedef: [bold]{current_target}[/]")
            else:
                self.console.print(f"Current target: [bold]{current_target}[/]")
        else:
            if lang == "tr":
                self.console.print("[dim]Hedef yok. Kullanım:[/] [green]/target <IP>[/]")
            else:
                self.console.print("[dim]No target set. Usage:[/] [green]/target <IP>[/]")

    def _cmd_target(self, args: str = "") -> None:
        """Set target - minimal style."""
        lang: str = self.config.language
        args = args.strip()

        if not args:
            self._show_current_target_info(lang)
            return

        # Explicit clear check
        clear_keywords = {"clear", "off", "none", "delete", "sil", "iptal", "remove"}
        if args.lower() in clear_keywords:
            self._cmd_untarget("")
            return

        # Validation
        if not self._validate_target(args):
            err_msg = (
                "Geçersiz hedef formatı (IP veya Domain girilmeli)."
                if lang == "tr"
                else "Invalid target format (Must be IP or Domain)."
            )
            self.console.print(f"   [red]❌ {err_msg}[/]")
            return

        self.config_manager.set_target(args)
        self.config = self.config_manager.config

        # Sync orchestrator target
        if self.orchestrator:
            self.orchestrator.set_target(args)

        if lang == "tr":
            self.console.print(f"[green]Hedef ayarlandı:[/] [bold]{args}[/]")
        else:
            self.console.print(f"[green]Target set:[/] [bold]{args}[/]")

    def _cmd_untarget(self, args: str = "") -> None:
        """Clear target command - minimal style."""
        lang: str = self.config.language

        if not self.config.target:
            msg = "Zaten hedef belirlenmemiş." if lang == "tr" else "No target is set."
            self.console.print(f"[yellow]{msg}[/]")
            return

        self.config_manager.set_target(None)
        self.config = self.config_manager.config

        # Also clear orchestrator target
        if self.orchestrator:
            self.orchestrator.clear_target()

        msg = "Hedef temizlendi." if lang == "tr" else "Target cleared."
        self.console.print(f"[green]{msg}[/]")

    def _cmd_tools(self, args: str = "") -> None:
        """List all available tools from the registry."""
        from rich.table import Table

        from core.tools.tool_registry import PentestPhase, get_registry

        lang = self.config.language
        registry = get_registry()

        # Filter by phase if specified
        phase_filter = None
        if args:
            phase_map = {
                "recon": PentestPhase.RECON,
                "vuln": PentestPhase.VULN_SCAN,
                "exploit": PentestPhase.EXPLOIT,
                "post": PentestPhase.POST_EXPLOIT,
                "lateral": PentestPhase.LATERAL,
            }
            phase_filter = phase_map.get(args.lower())

        tools = registry.list_tools(phase=phase_filter)

        title = "Mevcut Araçlar" if lang == "tr" else "Available Tools"
        table = Table(title=title, border_style=self.STYLE_DIM_CYAN)
        table.add_column("Tool", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Phase", style="yellow")
        table.add_column("Description", style="white")

        for tool in tools:
            table.add_row(
                tool.name,
                tool.type.value,
                tool.phase.value,
                tool.description[:50] + "..." if len(tool.description) > 50 else tool.description,
            )

        self.console.print(table)

        # Show usage hint
        if lang == "tr":
            self.console.print("\n[dim]Kullanım:[/] [green]/tools[/] [dim][recon|vuln|exploit|post|lateral][/]")
        else:
            self.console.print("\n[dim]Usage:[/] [green]/tools[/] [dim][recon|vuln|exploit|post|lateral][/]")

    def _cmd_scan(self, args: str = "") -> None:
        """Scan target - with visual feedback.

        Usage:
            /scan              - Auto mode (agent decides)
            /scan stealth      - Stealth/silent mode (slow, careful)
            /scan aggressive   - Aggressive mode (fast, noisy)
            /scan sessiz       - Stealth mode (Turkish alias)
            /scan hizli        - Aggressive mode (Turkish alias)
        """
        scan_mode: str = self._parse_scan_mode(args)

        # Check target FIRST before creating any display
        if not self._check_target_set():
            return

        # Only create display after target check passes
        from core.ui.unified_display import ScanDisplay

        lang: str = self.config.language
        scan_display = ScanDisplay(console=self.console, language=lang)

        try:
            scan_display.start_scan(
                target=self.config.target or "",
                mode=scan_mode,
                phase="RECON",
            )

            self._ensure_agent_initialized()
            self._initialize_agent_with_retry(scan_mode, lang)

            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)

            # Update display with tool info
            scan_display.update_progress(tool="nmap", current_action="Port scanning...")

            # Run autonomous loop (this will take over display)
            scan_display.stop(final_message="Starting autonomous scan...", success=True)
            self.agent.run_autonomous_loop()

        except KeyboardInterrupt:
            scan_display.finish_scan(success=False)
            self._handle_scan_interrupt(lang)
        except Exception as e:
            scan_display.finish_scan(success=False)
            self._handle_scan_error(e, lang)

    def _parse_scan_mode(self, args: str) -> str:
        """Parse scan mode from arguments."""
        args_lower: str = args.strip().lower()
        if args_lower in ["stealth", "sessiz", "silent", "quiet", "gizli"]:
            return "stealth"
        if args_lower in ["aggressive", "hizli", "fast", "agresif", "quick"]:
            return "aggressive"
        return "auto"

    def _check_target_set(self) -> bool:
        """Check if target is set, show error if not."""
        if self.config.target:
            return True

        lang: str = self.config.language
        if lang == "tr":
            self.console.print("[red]Hedef yok.[/] [dim]Kullanım:[/] [green]/target <IP>[/]")
        else:
            self.console.print("[red]No target.[/] [dim]Usage:[/] [green]/target <IP>[/]")

        return False

    def _display_scan_panel(self, scan_mode: str) -> None:
        """Display scan initialization panel."""

        lang: str = self.config.language
        mode_info: dict[str, tuple[str, str]] = {
            "stealth": (
                "STEALTH",
                "Silent mode - Slow but stealthy"
                if lang != "tr"
                else "Sessiz mod - Yavas ama gizli",
            ),
            "aggressive": (
                "AGGRESSIVE",
                "Fast mode - Aggressive scan"
                if lang != "tr"
                else "Hizli mod - Agresif tarama",
            ),
            "auto": ("AUTO", "Auto mode" if lang != "tr" else "Otomatik mod"),
        }
        mode_label, mode_desc = mode_info.get(scan_mode, mode_info["auto"])

        # Simple professional output
        self.console.print()
        self.console.print("[bold cyan]DRAKBEN Scanner[/]")
        self.console.print("─" * 40)
        self.console.print(f"[*] Target: {self.config.target}")
        self.console.print(f"[*] Mode: {mode_label} - {mode_desc}")
        self.console.print("─" * 40)
        self.console.print()

    def _start_scan_with_recovery(self, scan_mode: str) -> None:
        """Start scan with error recovery (legacy method)."""
        lang: str = self.config.language

        try:
            self._ensure_agent_initialized()
            self._initialize_agent_with_retry(scan_mode, lang)
            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)
            self.agent.run_autonomous_loop()
        except KeyboardInterrupt:
            self._handle_scan_interrupt(lang)
        except Exception as e:
            self._handle_scan_error(e, lang)

    def _handle_scan_interrupt(self, lang: str) -> None:
        """Handle scan interruption (Ctrl+C)."""
        try:
            from core.stop_controller import stop_controller
            stop_controller.stop()
        except ImportError:
            pass
        interrupt_msg: str = (
            "\nTarama durduruldu."
            if lang == "tr"
            else "\nScan stopped."
        )
        self.console.print(f"[yellow]{interrupt_msg}[/]")
        try:
            from core.stop_controller import stop_controller
            stop_controller.reset()
        except ImportError:
            pass

    def _handle_scan_error(self, error: Exception, lang: str) -> None:
        """Handle scan error."""
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Scan error: %s", error)
        error_msg: str = (
            f"Tarama hatası: {error}" if lang == "tr" else f"Scan error: {error}"
        )
        self.console.print(f"[red]{error_msg}[/]")

    def _ensure_agent_initialized(self) -> None:
        """Ensure agent is initialized."""
        if not self.agent:
            from core.agent.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)

    def _initialize_agent_with_retry(self, scan_mode: str, lang: str) -> None:
        """Initialize agent with retry on failure."""
        try:
            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)
            target: str = self.config.target or "localhost"
            self.agent.initialize(target=target, mode=scan_mode)
        except Exception as init_error:
            error_msg: str = (
                f"Agent hatası: {init_error}"
                if lang == "tr"
                else f"Agent error: {init_error}"
            )
            retry_msg = "Yeniden deneniyor..." if lang == "tr" else "Retrying..."
            self.console.print(f"[yellow]{error_msg}[/]")
            self.console.print(f"[dim]{retry_msg}[/]")

            # Retry with fresh agent
            from core.agent.refactored_agent import RefactoredDrakbenAgent

            target = self.config.target or "localhost"
            self.agent = RefactoredDrakbenAgent(self.config_manager)
            self.agent.initialize(target=target, mode=scan_mode)

    def _cmd_clear(self, args: str = "") -> None:
        """Clear screen - banner and menu remain."""
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _cmd_turkish(self, args: str = "") -> None:
        """Switch to Turkish."""
        self.config_manager.set_language("tr")
        self.config: DrakbenConfig = self.config_manager.config
        self.console.print("[green]Dil Türkçe olarak ayarlandı.[/]")

    def _cmd_english(self, args: str = "") -> None:
        """Switch to English."""
        self.config_manager.set_language("en")
        self.config: DrakbenConfig = self.config_manager.config
        self.console.print("[green]Language set to English.[/]")

    def _cmd_shell(self, args: str = "") -> None:
        """Launch interactive shell."""
        lang: str = self.config.language

        if lang == "tr":
            self.console.print("[İnteraktif kabuk başlatılıyor... Çıkmak için 'exit' yazın]")
        else:
            self.console.print("[Starting interactive shell... Type 'exit' to quit]")

        from core.ui.interactive_shell import InteractiveShell

        shell = InteractiveShell(config_manager=self.config_manager, agent=self.agent)
        shell.current_target = self.config.target
        shell.start()

        # Restore menu after shell exits
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _show_agent_panels(self, lang: str) -> None:
        """Show agent-related panels in status view."""
        from rich.panel import Panel

        if not (self.agent and self.agent.state):
            return

        agent_title: str = "🤖 Agent State" if lang == "en" else "🤖 Ajan Durumu"
        self.console.print(
            Panel(
                self._create_agent_table(),
                title=f"[bold {self.COLORS['yellow']}]{agent_title}[/]",
                border_style=self.COLORS["yellow"],
                padding=(0, 1),
            ),
        )

        findings_title = (
            "⚔️  War Room: Live Findings"
            if lang == "en"
            else "⚔️  Savaş Odası: Canlı Bulgular"
        )
        self.console.print(
            Panel(
                self._create_live_findings_table(),
                title=f"[bold red]{findings_title}[/]",
                border_style="red",
                padding=(0, 1),
            ),
        )

        if self.agent.planner and self.agent.planner.steps:
            plan_title = "Mission Plan" if lang == "en" else "Görev Planı"
            self.console.print(
                Panel(
                    self._create_plan_table(),
                    title=f"[bold cyan]{plan_title}[/]",
                    border_style="cyan",
                    padding=(0, 1),
                ),
            )

    def _show_idle_panel(self, lang: str) -> None:
        """Show idle message when agent is not active."""
        if lang == "tr":
            self.console.print("[dim]Ajan aktif değil. Başlatmak için: /target <IP> sonra /scan[/]")
        else:
            self.console.print("[dim]Agent idle. To start: /target <IP> then /scan[/]")

    def _cmd_status(self, args: str = "") -> None:
        """Show current status - Clean, professional dashboard."""
        from rich.panel import Panel
        from rich.table import Table

        lang: str = self.config.language
        is_tr = lang == "tr"
        self.console.print()

        # Single compact status table
        status_table = Table(box=None, padding=(0, 2), expand=True, show_header=False)
        status_table.add_column("Key", style="dim", width=15)
        status_table.add_column("Value", style="white")

        self._populate_status_rows(status_table, is_tr)
        self._add_llm_status_row(status_table, is_tr)

        title = "DRAKBEN Durumu" if is_tr else "DRAKBEN Status"
        self.console.print(Panel(
            status_table,
            title=f"[bold cyan]{title}[/]",
            border_style="cyan",
            padding=(0, 1),
        ))

        # Agent status if active
        if self.agent and self.agent.state:
            self._show_agent_status_compact(is_tr)

        self.console.print()

    def _populate_status_rows(self, status_table: "Table", is_tr: bool) -> None:
        """Populate basic status table rows (target, mode, threads, tools)."""
        target = self.config.target or ("Belirlenmedi" if is_tr else "Not set")
        target_style = self.STYLE_BOLD_GREEN if self.config.target else self.STYLE_DIM_RED
        status_table.add_row("Hedef" if is_tr else "Target", f"[{target_style}]{target}[/]")

        mode = "Stealth" if self.config.stealth_mode else "Normal"
        mode_style = "green" if self.config.stealth_mode else "dim"
        status_table.add_row("Mod" if is_tr else "Mode", f"[{mode_style}]{mode}[/]")

        status_table.add_row("Threads", f"{self.config.max_threads}")

        tools = self.system_info.get("available_tools", {})
        status_table.add_row("Araçlar" if is_tr else "Tools", f"{len(tools)}")

    def _add_llm_status_row(self, status_table: "Table", is_tr: bool) -> None:
        """Add LLM status row to the status table."""
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            model = info.get("model", "N/A")
            short_model = model.split("/")[-1][:25] if "/" in model else model[:25]
            status_table.add_row("LLM", f"[green]{short_model}[/]")
        else:
            off_text = "Kapalı" if is_tr else "Off"
            status_table.add_row("LLM", f"[dim]{off_text}[/]")

    def _show_agent_status_compact(self, is_tr: bool) -> None:
        """Show compact agent status."""
        from rich.panel import Panel
        from rich.table import Table

        state = self.agent.state
        phase_colors = {
            "init": "dim", "recon": "yellow", "vulnerability_scan": "cyan",
            "exploit": "red", "foothold": "green", "post_exploit": "magenta",
            "complete": self.STYLE_BOLD_GREEN, "failed": self.STYLE_BOLD_RED,
        }
        phase_color = phase_colors.get(state.phase.value, "white")
        phase_name = self._get_phase_display_name(state.phase.value, is_tr)

        agent_table = Table(box=None, padding=(0, 2), show_header=False, expand=True)
        agent_table.add_column("Key", style="dim", width=15)
        agent_table.add_column("Value", style="white")

        agent_table.add_row("Phase" if not is_tr else "Aşama", f"[{phase_color}]{phase_name}[/]")
        agent_table.add_row("Services" if not is_tr else "Servisler", f"{len(state.open_services)}")

        vuln_count = len(state.vulnerabilities)
        vuln_style = self.STYLE_BOLD_RED if vuln_count > 0 else "dim"
        agent_table.add_row("Vulns" if not is_tr else "Zafiyetler", f"[{vuln_style}]{vuln_count}[/]")

        foothold_text = "Yes" if state.has_foothold else "No"
        if is_tr:
            foothold_text = "Evet" if state.has_foothold else "Hayır"
        foothold_style = "green" if state.has_foothold else "dim"
        agent_table.add_row("Foothold" if not is_tr else "Erişim", f"[{foothold_style}]{foothold_text}[/]")

        title = "Agent Status" if not is_tr else "Ajan Durumu"
        self.console.print(Panel(
            agent_table,
            title=f"[bold yellow]{title}[/]",
            border_style="yellow",
            padding=(0, 1),
        ))

    def _get_service_status(self, svc: Any, vuln_map: dict, is_tr: bool) -> str:
        """Get status text for a service row."""
        if svc.port in vuln_map:
            v = vuln_map[svc.port]
            return f"[bold red]⚠ {v.vuln_id} ({v.severity})[/]"
        if svc.vulnerable:
            vuln_text = "Potansiyel Zafiyet" if is_tr else "Potentially Vulnerable"
            return f"[bold red]⚠ {vuln_text}[/]"
        open_text = "Açık" if is_tr else "Open"
        return f"[green]{open_text}[/]"

    def _cmd_memory(self, args: str = "") -> None:
        """Show memory system status - Stanford Memory + Evolution Memory."""
        from rich.panel import Panel
        from rich.table import Table

        lang: str = self.config.language
        is_tr = lang == "tr"
        self.console.print()

        mem_table = Table(box=None, padding=(0, 2), expand=True, show_header=False)
        mem_table.add_column("Key", style="dim", width=22)
        mem_table.add_column("Value", style="white")

        self._populate_stanford_memory_rows(mem_table, is_tr)
        mem_table.add_row("", "")  # Spacer
        self._populate_evolution_memory_rows(mem_table, is_tr)

        title = "Hafıza Sistemi" if is_tr else "Memory System"
        self.console.print(Panel(
            mem_table,
            title=f"[bold cyan]{title}[/]",
            border_style="cyan",
            padding=(0, 1),
        ))
        self.console.print()

    def _populate_stanford_memory_rows(self, mem_table: "Table", is_tr: bool) -> None:
        """Populate Stanford Memory Stream rows."""
        try:
            from core.agent.memory.memory_stream import get_memory_stream
            ms = get_memory_stream()
            stats = ms.get_stats()
            mem_table.add_row(
                "[bold cyan]Stanford Hafıza[/]" if is_tr else "[bold cyan]Stanford Memory[/]",
                "",
            )
            mem_table.add_row(
                "  Toplam Düğüm" if is_tr else "  Total Nodes",
                str(stats.get("total_nodes", 0)),
            )
            by_type = stats.get("by_type", {})
            if by_type:
                type_str = ", ".join(f"{k}: {v}" for k, v in by_type.items() if v > 0)
                mem_table.add_row(
                    "  Türe Göre" if is_tr else "  By Type",
                    type_str or "—",
                )
            targets = stats.get("targets", [])
            mem_table.add_row(
                "  Hedefler" if is_tr else "  Targets",
                ", ".join(targets[:5]) if targets else "—",
            )
            mem_table.add_row(
                "  Kalıcılık" if is_tr else "  Persistence",
                self._format_feature_flags(stats),
            )
        except Exception:
            mem_table.add_row(
                "Stanford Hafıza" if is_tr else "Stanford Memory",
                "[dim]Başlatılmadı[/]" if is_tr else "[dim]Not initialized[/]",
            )

    @staticmethod
    def _format_feature_flags(stats: dict) -> str:
        """Format persistence/embeddings feature flags."""
        persistence = "✓" if stats.get("persistence_enabled") else "✗"
        embeddings = "✓" if stats.get("embeddings_enabled") else "✗"
        return f"SQLite {persistence} | Embeddings {embeddings}"

    def _populate_evolution_memory_rows(self, mem_table: "Table", is_tr: bool) -> None:
        """Populate Evolution Memory rows."""
        try:
            from core.intelligence.evolution_memory import get_evolution_memory
            evo = get_evolution_memory()
            mem_table.add_row(
                "[bold yellow]Evrim Hafızası[/]" if is_tr else "[bold yellow]Evolution Memory[/]",
                "",
            )
            recent = evo.get_recent_actions(count=3)
            mem_table.add_row(
                "  Son Eylemler" if is_tr else "  Recent Actions",
                str(len(recent)),
            )
            penalties = evo.get_all_penalties()
            blocked = sum(1 for p in penalties.values() if p.get("blocked"))
            mem_table.add_row(
                "  Araç Cezaları" if is_tr else "  Tool Penalties",
                f"{len(penalties)} ({blocked} engellenmiş)" if is_tr
                else f"{len(penalties)} ({blocked} blocked)",
            )
            heuristics = evo.get_all_heuristics()
            mem_table.add_row(
                "  Sezgisel Kurallar" if is_tr else "  Heuristics",
                str(len(heuristics)),
            )
        except Exception:
            mem_table.add_row(
                "Evrim Hafızası" if is_tr else "Evolution Memory",
                "[dim]Başlatılmadı[/]" if is_tr else "[dim]Not initialized[/]",
            )

    def _create_findings_table_base(self, is_tr: bool) -> "Table":
        """Create base findings table with columns."""
        from rich.table import Table

        svc_col = "SERVİS" if is_tr else "SERVICE"
        status_col = "DURUM/ZAFİYET" if is_tr else "STATUS/VULN"
        table = Table(box=None, padding=(0, 1), expand=True)
        table.add_column("PORT", style=self.STYLE_BOLD_CYAN, width=10)
        table.add_column(svc_col, style="white", width=20)
        table.add_column(status_col, style="yellow")
        return table

    def _create_live_findings_table(self) -> "Table":
        """Create a table showing live ports and vulns."""
        is_tr = self.config.language == "tr"
        table = self._create_findings_table_base(is_tr)

        if not self.agent or not self.agent.state:
            no_agent = "Aktif ajan yok" if is_tr else "No active agent"
            table.add_row("-", no_agent, "[dim]N/A[/]")
            return table

        state: AgentState = self.agent.state
        if not state.open_services and not state.vulnerabilities:
            self._add_scanning_row(table, is_tr)
            return table

        vuln_map = {v.port: v for v in state.vulnerabilities}
        for svc in state.open_services:
            table.add_row(
                f"{svc.port}/{svc.protocol}",
                f"{svc.service} {svc.version or ''}",
                self._get_service_status(svc, vuln_map, is_tr),
            )
        return table

    def _add_scanning_row(self, table: Any, is_tr: bool) -> None:
        """Add scanning placeholder row to table."""
        wait = "Bekle" if is_tr else "Wait"
        scanning = "Tarama yapılıyor..." if is_tr else "Scanning..."
        no_findings = "Henüz bulgu yok" if is_tr else "No findings yet"
        table.add_row(f"[dim]{wait}[/]", f"[dim]{scanning}[/]", f"[dim]{no_findings}[/]")

    def _create_plan_table(self) -> "Table":
        """Create a table showing current plan steps."""
        from rich.table import Table

        from core.agent.planner import StepStatus

        lang = self.config.language
        is_tr = lang == "tr"

        table = Table(box=None, padding=(0, 1))
        table.add_column("Step" if not is_tr else "Adım", style="dim")
        table.add_column("Action" if not is_tr else "Eylem", style="bold")
        table.add_column("Tool" if not is_tr else "Araç", style="cyan")
        table.add_column("Status" if not is_tr else "Durum", style="bold")

        status_colors = {
            StepStatus.PENDING: "dim",
            StepStatus.EXECUTING: self.STYLE_BOLD_YELLOW,
            StepStatus.SUCCESS: self.STYLE_BOLD_GREEN,
            StepStatus.FAILED: self.STYLE_BOLD_RED,
            StepStatus.SKIPPED: "dim yellow",
        }

        for i, step in enumerate(self.agent.planner.steps, 1):
            color = status_colors.get(step.status, "white")
            status_text = step.status.value.upper()
            if is_tr:
                status_map = {
                    "pending": "BEKLİYOR",
                    "executing": "YÜRÜTÜLÜYOR",
                    "success": "BAŞARILI",
                    "failed": "BAŞARISIZ",
                    "skipped": "ATLANDI",
                }
                status_text = status_map.get(step.status.value, status_text)

            table.add_row(
                f"#{i}",
                step.action.replace("_", " ").title(),
                step.tool,
                f"[{color}]{status_text}[/]",
            )
        return table

    def _build_report_summary_table(self, lang: str, final_path: str) -> "Table":
        """Build summary table for report output."""
        from rich.table import Table

        summary_table = Table(show_header=False, box=None, padding=(0, 1))
        summary_table.add_column("K", style=self.STYLE_BOLD_CYAN)
        summary_table.add_column("V")

        s = self.agent.state  # type: ignore[union-attr]
        v_count = len(s.vulnerabilities)
        svc_count = len(s.open_services)

        if lang == "tr":
            summary_table.add_row("📊 Durum:", "[bold green]BAŞARILI[/]")
            summary_table.add_row("📂 Dosya:", f"[cyan]{final_path}[/]")
            summary_table.add_row("🔌 Servisler:", f"{svc_count}")
            summary_table.add_row("⚠️  Zafiyetler:", f"[bold red]{v_count}[/]")
        else:
            summary_table.add_row("📊 Status:", "[bold green]SUCCESS[/]")
            summary_table.add_row("📂 Path:", f"[cyan]{final_path}[/]")
            summary_table.add_row("🔌 Services:", f"{svc_count}")
            summary_table.add_row("⚠️  Vulns:", f"[bold red]{v_count}[/]")

        return summary_table

    def _cmd_report(self, args: str = "") -> None:
        """Generate professional report."""
        from modules.report_generator import (
            ReportConfig,
            ReportFormat,
            generate_report_from_state,
        )

        lang = self.config.language

        if not self.agent or not self.agent.state:
            msg = "Önce bir tarama başlatın." if lang == "tr" else "Start a scan first."
            self.console.print(f"[red]{msg}[/]")
            return

        gen_msg = "Rapor oluşturuluyor..." if lang == "tr" else "Generating report..."
        self.console.print(f"[{self.COLORS['purple']}]{gen_msg}[/]")

        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = (self.config.target or "unknown").replace(".", "_").replace("/", "_").replace(":", "_")
            output_path = reports_dir / f"drakben_report_{target_clean}_{timestamp}.html"

            config = ReportConfig(
                title=f"DRAKBEN AI Security Report - {self.config.target}",
                use_llm_summary=True,
            )
            final_path = generate_report_from_state(
                state=self.agent.state,
                output_path=str(output_path),
                format=ReportFormat.HTML,
                config=config,
            )

            stitle = "RAPOR" if lang == "tr" else "REPORT"
            self.console.print()
            self.console.print(f"[bold {self.COLORS['cyan']}]{stitle}[/]")
            self.console.print("─" * 40)
            self.console.print(self._build_report_summary_table(lang, final_path))
            self.console.print("─" * 40)

        except Exception as e:
            err_msg = f"Rapor hatası: {e}" if lang == "tr" else f"Report error: {e}"
            self.console.print(f"[red]{err_msg}[/]")

    def _get_localized_labels(self, is_tr: bool) -> dict[str, str]:
        """Get localized labels for system table."""
        return {
            "header_id": "DİJİTAL KİMLİK" if is_tr else "OPERATIONAL IDENTITY",
            "header_perf": "SİSTEM METRİKLERİ" if is_tr else "SYSTEM METRICS",
            "lbl_status": "DURUM" if is_tr else "STATUS",
            "lbl_value": "DEĞER" if is_tr else "VALUE",
            "lbl_scope": "Aktif Kapsam" if is_tr else "Active Scope",
            "lbl_lang": "Nöral Dil" if is_tr else "Neural Link",
            "lbl_os": "Ana Bilgisayar" if is_tr else "Host Machine",
            "lbl_tools": "Aktif Modüller" if is_tr else "Active Modules",
            "lbl_stealth": "Görünürlük" if is_tr else "Visibility",
            "lbl_threads": "İşlem Gücü" if is_tr else "Compute Power",
            "unit_str": "Modül" if is_tr else "Modules",
            "active_str": "GİZLİ (Korumalı)" if is_tr else "STEALTH (Secure)",
            "inactive_str": "İZLENEBİLİR (Riskli)" if is_tr else "VISIBLE (High Risk)",
            "core_str": "Çekirdek" if is_tr else "Cores",
        }

    def _create_system_table(self, lang: str) -> "Table":
        from rich.table import Table

        outer_table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
        outer_table.add_column("Left", ratio=1)
        outer_table.add_column("Right", ratio=1)

        is_tr = lang == "tr"
        labels = self._get_localized_labels(is_tr)

        target_val = self.config.target or ("HEDEF YOK" if is_tr else "NO TARGET")
        target_style = self.STYLE_BOLD_WHITE if self.config.target else self.STYLE_DIM_RED

        os_info = self.system_info.get("os", "Unknown")
        is_kali = self.system_info.get("is_kali", False)
        os_display = "Kali Linux" if is_kali else os_info

        tools = self.system_info.get("available_tools", {})
        tool_count = len(tools)
        tool_color = "green" if tool_count > 10 else "yellow"

        # LEFT COLUMN: IDENTITY
        left_content = Table(show_header=True, box=None, header_style=self.STYLE_BOLD_CYAN, padding=(0, 0))
        left_content.add_column("", width=2)
        left_content.add_column(labels["header_id"], width=22)
        left_content.add_column(labels["lbl_status"], justify="right", width=15)

        left_content.add_row("*", f"[dim]{labels['lbl_scope']}[/]", f"[{target_style}]{target_val}[/]")
        left_content.add_row("*", f"[dim]{labels['lbl_lang']}[/]", "TR" if is_tr else "EN")
        left_content.add_row("*", f"[dim]{labels['lbl_os']}[/]", os_display)

        # RIGHT COLUMN: PERFORMANCE
        right_content = Table(show_header=True, box=None, header_style=self.STYLE_BOLD_CYAN, padding=(0, 0))
        right_content.add_column("", width=2)
        right_content.add_column(labels["header_perf"], width=22)
        right_content.add_column(labels["lbl_value"], justify="right", width=15)

        tools_val = f"[{tool_color}]{tool_count} {labels['unit_str']}[/]"
        right_content.add_row("*", f"[dim]{labels['lbl_tools']}[/]", tools_val)
        if self.config.stealth_mode:
            stealth_str = "[green]STEALTH[/]"
        else:
            stealth_str = "[yellow]VISIBLE[/]"
        right_content.add_row("*", f"[dim]{labels['lbl_stealth']}[/]", stealth_str)
        threads_val = f"[yellow]{self.config.max_threads} {labels['core_str']}[/]"
        right_content.add_row("*", f"[dim]{labels['lbl_threads']}[/]", threads_val)

        outer_table.add_row(left_content, right_content)
        return outer_table

    def _get_phase_display_name(self, phase_value: str, is_tr: bool) -> str:
        """Get localized phase display name."""
        if not is_tr:
            return phase_value
        phase_map = {
            "init": "başlatma",
            "recon": "keşif",
            "vulnerability_scan": "zafiyet_taraması",
            "exploit": "sömürü",
            "foothold": "erişim",
            "post_exploit": "sızma_sonrası",
            "complete": "tamamlandı",
            "failed": "başarısız",
        }
        return phase_map.get(phase_value, phase_value)

    def _create_agent_table(self) -> "Table":
        from rich.table import Table

        lang = self.config.language
        is_tr = lang == "tr"
        state: AgentState | None = self.agent.state

        phase_colors: dict[str, str] = {
            "init": "dim", "recon": "yellow", "vulnerability_scan": "cyan",
            "exploit": "red", "foothold": "green", "post_exploit": "magenta",
            "complete": self.STYLE_BOLD_GREEN, "failed": self.STYLE_BOLD_RED,
        }
        phase_color: str = phase_colors.get(state.phase.value, "white")
        phase_name = self._get_phase_display_name(state.phase.value, is_tr)

        agent_table = Table(show_header=False, box=None, padding=(0, 1))
        agent_table.add_column("Key", style=f"bold {self.COLORS['purple']}")
        agent_table.add_column("Value", style=self.COLORS["fg"])

        lbl_phase = "Phase" if not is_tr else "Evre"
        lbl_svc = "Services" if not is_tr else "Servisler"
        lbl_vulns = "Vulns" if not is_tr else "Zafiyetler"
        lbl_foothold = "Foothold" if not is_tr else "Erişim"

        agent_table.add_row(lbl_phase, f"[{phase_color}]{phase_name.replace('_', ' ').title()}[/]")
        agent_table.add_row(lbl_svc, f"[cyan]{len(state.open_services)}[/]")
        vuln_color = "red" if state.vulnerabilities else "dim"
        agent_table.add_row(lbl_vulns, f"[{vuln_color}]{len(state.vulnerabilities)}[/]")
        agent_table.add_row(lbl_foothold, "[green]YES[/]" if state.has_foothold else "[dim]NO[/]")
        return agent_table

    def _create_llm_content(self) -> str:
        lang = self.config.language
        is_tr = lang == "tr"

        not_init = "Not initialized" if not is_tr else "Başlatılmadı"
        llm_content = f"[dim]{not_init}[/]"

        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            provider = info.get("provider", "N/A")
            model = info.get("model", "N/A")
            llm_content: str = f"[green]●[/] {provider}\n[dim]{model}[/]"

            if info.get("cache_stats"):
                cache = info["cache_stats"]
                hit_rate = cache.get("hit_rate", 0) * 100
                cache_lbl = "Cache" if not is_tr else "Önbellek"
                llm_content += f"\n[dim]{cache_lbl}: {hit_rate:.0f}%[/]"
        return llm_content

    def _cmd_llm_setup(self, args: str = "") -> None:
        """Interactive LLM/API setup wizard."""
        lang: str = self.config.language

        providers: dict[str, tuple[str, str]] = {
            "1": (
                "openrouter",
                "OpenRouter (Ücretsiz modeller var)"
                if lang == "tr"
                else "OpenRouter (Free models available)",
            ),
            "2": ("openai", "OpenAI (GPT-4, GPT-4o)"),
            "3": (
                "ollama",
                "Ollama (Yerel, Ücretsiz)" if lang == "tr" else "Ollama (Local, Free)",
            ),
        }

        self._display_llm_setup_status(lang)

        provider_key = self._select_provider_for_setup(lang, providers)
        if not provider_key:
            return

        selected_model, api_key = self._select_model_and_key(lang, provider_key)
        if not selected_model:
            return

        # Save to config/api.env
        self._save_llm_config(provider_key, selected_model, api_key)

    def _display_llm_setup_status(self, lang: str) -> None:
        # Show current status
        title: str = "LLM Kurulumu" if lang == "tr" else "LLM Setup"
        self.console.print()
        self.console.print(f"[bold {self.COLORS['cyan']}]{title}[/]")
        self.console.print("─" * 30)

        # Show current config
        current_info: str = (
            "[dim]Ayar yok[/]"
            if lang == "tr"
            else "[dim]No config[/]"
        )
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            current_info = f"[green]●[/] {info.get('provider', 'N/A')} / {info.get('model', 'N/A')}"

        lbl = "Mevcut" if lang == "tr" else "Current"
        self.console.print(f"{lbl}: {current_info}")
        self.console.print("─" * 30)

    def _select_provider_for_setup(self, lang: str, providers: dict[str, Any]) -> Any:
        from rich.table import Table

        # Provider selection
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("No", style=f"bold {self.COLORS['yellow']}")
        table.add_column("Provider", style=self.COLORS["fg"])

        for key, (_, desc) in providers.items():
            table.add_row(f"[{key}]", desc)

        # Add Quit option to table for consistency
        q_label = "Geri Dön / İptal" if lang == "tr" else "Go Back / Cancel"
        table.add_row("[0]", q_label)

        self.console.print()
        self.console.print(table)

        # Get provider choice
        prompt_text: str = (
            "Seçiminiz (1-3 veya 0)" if lang == "tr" else "Choice (1-3 or 0)"
        )
        self.console.print(f"   {prompt_text}: ", end="")
        choice: str = input().strip().lower()

        if choice == "0" or choice not in providers:
            return None

        return providers[choice][0]

    def _get_models_dict(self, lang: str) -> dict[str, list[tuple[str, str]]]:
        return {
            "openrouter": [
                (
                    "deepseek/deepseek-chat",
                    "DeepSeek Chat (Ücretsiz)"
                    if lang == "tr"
                    else "DeepSeek Chat (Free)",
                ),
                (
                    "meta-llama/llama-3.1-8b-instruct:free",
                    "Llama 3.1 8B (Ücretsiz)"
                    if lang == "tr"
                    else "Llama 3.1 8B (Free)",
                ),
                (
                    "google/gemma-2-9b-it:free",
                    "Gemma 2 9B (Ücretsiz)" if lang == "tr" else "Gemma 2 9B (Free)",
                ),
                ("anthropic/claude-3.5-sonnet", "Claude 3.5 Sonnet"),
                ("openai/gpt-4o", "GPT-4o"),
            ],
            "openai": [
                (
                    "gpt-4o-mini",
                    "GPT-4o Mini (Ucuz)" if lang == "tr" else "GPT-4o Mini (Cheap)",
                ),
                ("gpt-4o", "GPT-4o"),
                ("gpt-4-turbo", "GPT-4 Turbo"),
            ],
            "ollama": [
                ("llama3.2", "Llama 3.2"),
                ("llama3.1", "Llama 3.1"),
                ("mistral", "Mistral"),
                ("codellama", "Code Llama"),
            ],
        }

    def _select_model_and_key(
        self,
        lang: str,
        provider_key: str,
    ) -> tuple[None, None] | tuple[str, str]:
        from rich.table import Table

        models: dict[str, list[tuple[str, str]]] = self._get_models_dict(lang)

        # Model selection
        self.console.print()
        model_table = Table(show_header=False, box=None, padding=(0, 2))
        model_table.add_column("No", style=f"bold {self.COLORS['yellow']}")
        model_table.add_column("Model", style=self.COLORS["fg"])

        provider_models: list[tuple[str, str]] = models[provider_key]
        for i, (_, desc) in enumerate(provider_models, 1):
            model_table.add_row(f"[{i}]", desc)

        # Consistent Go Back option
        q_label = "Geri Dön" if lang == "tr" else "Go Back"
        model_table.add_row("[0]", q_label)

        self.console.print(model_table)

        prompt_text: str = (
            f"Seçiminiz (1-{len(provider_models)} veya 0)"
            if lang == "tr"
            else f"Choice (1-{len(provider_models)} or 0)"
        )
        self.console.print(f"   {prompt_text}: ", end="")
        model_choice: str = input().strip().lower()

        if model_choice == "0":
            return None, None

        selected_model = None
        try:
            model_idx: int = int(model_choice) - 1
            if 0 <= model_idx < len(provider_models):
                selected_model, _ = provider_models[model_idx]
            else:
                return None, None
        except ValueError:
            return None, None

        # API Key input (not needed for Ollama)
        api_key: str = ""
        if provider_key != "ollama":
            prompt_text: str = "API Key gir" if lang == "tr" else "Enter API Key"
            self.console.print(f"\n{prompt_text}: ", end="")
            api_key: str = input().strip()

            if not api_key:
                msg: str = "API key gerekli!" if lang == "tr" else "API key required!"
                self.console.print(f"[red]{msg}[/]")
                return None, None

        return selected_model, api_key

    def _save_llm_config(self, provider_key: str, selected_model: str, api_key: str) -> None:
        from pathlib import Path

        env_file = Path("config/api.env")

        # Configuration templates
        templates: dict[str, str] = {
            "openrouter": f"OPENROUTER_API_KEY={api_key}\nOPENROUTER_MODEL={selected_model}",
            "openai": f"OPENAI_API_KEY={api_key}\nOPENAI_MODEL={selected_model}",
            "ollama": f"LOCAL_LLM_URL=http://localhost:11434\nLOCAL_LLM_MODEL={selected_model}",
        }

        config_body: str | None = templates.get(provider_key)
        if not config_body:
            self.console.print(f"[red]Unknown provider: {provider_key}[/]")
            return

        env_content: str = f"# DRAKBEN LLM Configuration\n# Auto-generated by /llm command\n\n{config_body}\n"

        try:
            env_file.parent.mkdir(parents=True, exist_ok=True)
            with open(env_file, "w") as f:
                f.write(env_content)

            # Reload environment
            from dotenv import load_dotenv

            load_dotenv(env_file, override=True)

            # Update config manager
            self.config_manager.load_config()
            self.config: DrakbenConfig = self.config_manager.config

            # Reset brain to pick up new config
            self.brain = None

            # Success message
            lang: str = self.config.language
            msg: str = (
                f"LLM ayarlandı: {provider_key} / {selected_model}"
                if lang == "tr"
                else f"LLM configured: {provider_key} / {selected_model}"
            )
            self.console.print(f"\n[green]{msg}[/]")

            # Test connection
            test_msg: str = (
                "Bağlantı test ediliyor..." if lang == "tr" else "Testing connection..."
            )
            self.console.print(f"\n[dim]{test_msg}[/dim]")

            from core.agent.brain import DrakbenBrain

            self.brain = DrakbenBrain()

            if self.brain.llm_client:
                test_result = self.brain.test_llm()
                if test_result.get("connected"):
                    ok_msg: str = (
                        "Bağlantı başarılı."
                        if lang == "tr"
                        else "Connection OK."
                    )
                    self.console.print(f"[green]{ok_msg}[/]\n")
                else:
                    err_msg: str = (
                        "Bağlantı hatası:"
                        if lang == "tr"
                        else "Connection error:"
                    )
                    self.console.print(
                        f"[red]{err_msg} {test_result.get('error', 'Unknown')}[/]\n",
                    )

        except Exception as e:
            self.console.print(f"\n[red]Save error: {e}[/]")

    def _config_apply_defaults(self, lang: str) -> None:
        """Apply automatic default configuration."""
        self.config.stealth_mode = False
        self.config.max_threads = 4
        self.config.timeout = 30
        self.config.verbose = False
        self.config_manager.save_config()
        if lang == "tr":
            msg = "Standart ayarlar uygulandı (4 Thread, 30s)."
        else:
            msg = "Standard defaults applied (4 Threads, 30s)."
        self.console.print(f"\n[green]{msg}[/]\n")

    def _config_apply_shadow_mode(self, lang: str) -> None:
        """Apply shadow mode (hacker preset) configuration."""
        self.config.stealth_mode = True
        self.config.max_threads = 1
        self.config.timeout = 300
        self.config.verbose = True
        self.config_manager.save_config()
        if lang == "tr":
            msg = "Shadow Mode Aktif: Ghost Protocol ON, 1 Thread, 300s Timeout."
        else:
            msg = "Shadow Mode Active: Ghost Protocol ON, 1 Thread, 300s Timeout."
        self.console.print(f"\n[bold cyan]{msg}[/]\n")

    def _config_prompt_bool(self, prompt: str, current: bool, y_label: str, n_label: str) -> bool | None:
        """Prompt for boolean config value. Returns None if cancelled."""
        self.console.print(f"   > {prompt} [{y_label}/{n_label}] ({y_label if current else n_label}): ", end="")
        val = input().strip().lower()
        if val == "0":
            return None
        return val in ["e", "y", "yes", "evet"] if val else current

    def _config_prompt_int(self, prompt: str, current: int) -> int | None:
        """Prompt for integer config value. Returns None if cancelled."""
        self.console.print(f"   > {prompt} ({current}): ", end="")
        val = input().strip()
        if val == "0":
            return None
        return int(val) if val.isdigit() else current

    def _config_manual(self, lang: str) -> None:
        """Handle manual configuration."""
        y_label = "e" if lang == "tr" else "y"
        n_label = "h" if lang == "tr" else "n"
        header = "--- MANUEL AYARLAR ---" if lang == "tr" else "--- MANUAL SETTINGS ---"
        self.console.print(f"\n   [{self.STYLE_BOLD_CYAN}]{header}[/]")

        # 1. Ghost Protocol
        p_s = "Ghost Protocol (Gizli Mod)" if lang == "tr" else "Ghost Protocol (Stealth)"
        new_s = self._config_prompt_bool(p_s, getattr(self.config, "stealth_mode", False), y_label, n_label)
        if new_s is None:
            return

        # 2. Concurrency
        p_t = "Eşzamanlılık (Threads)" if lang == "tr" else "Concurrency (Threads)"
        new_t = self._config_prompt_int(p_t, getattr(self.config, "max_threads", 4))
        if new_t is None:
            return

        # 3. Timeout
        p_to = "Operasyon Zaman Aşımı (sn)" if lang == "tr" else "Operation Timeout (sec)"
        new_to = self._config_prompt_int(p_to, getattr(self.config, "timeout", 30))
        if new_to is None:
            return

        # 4. Verbose
        p_v = "Detaylı Çıktı (Verbose)" if lang == "tr" else "Neural Verbosity (Verbose)"
        new_v = self._config_prompt_bool(p_v, getattr(self.config, "verbose", False), y_label, n_label)
        if new_v is None:
            return

        # 5. Auto-Approve
        p_a = "Otonom Onay (Auto-Approve)" if lang == "tr" else "Autonomous Approval (Auto)"
        new_a = self._config_prompt_bool(p_a, getattr(self.config, "auto_approve", False), y_label, n_label)
        if new_a is None:
            return

        # Save all
        self.config.stealth_mode = new_s
        self.config.max_threads = new_t
        self.config.timeout = new_to
        self.config.verbose = new_v
        self.config.auto_approve = new_a
        self.config_manager.save_config()

        done_msg = "Sistem parametreleri güncellendi." if lang == "tr" else "System parameters optimized."
        self.console.print(f"\n   [bold green]✅ {done_msg}[/]\n")

    def _cmd_config(self, args: str) -> None:
        """System Configuration Menu."""
        from rich.table import Table

        lang = self.config.language
        title = "CONFIGURATION" if lang != "tr" else "YAPILANDIRMA"

        # Menu Table - clean
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style=self.STYLE_BOLD_CYAN, width=6)
        table.add_column("Desc", style="white")

        if lang == "tr":
            table.add_row("[1]", "Otomatik - Standart ayarlar")
            table.add_row("[2]", "Manuel - Ozel yapilandirma")
            table.add_row("[3]", "Stealth - Sessiz mod")
            table.add_row("[0]", "Geri")
            prompt = "Secim"
        else:
            table.add_row("[1]", "Auto - Standard defaults")
            table.add_row("[2]", "Manual - Custom settings")
            table.add_row("[3]", "Stealth - Silent mode")
            table.add_row("[0]", "Back")
            prompt = "Choice"

        self.console.print()
        self.console.print(f"[bold cyan]{title}[/]")
        self.console.print("─" * 30)
        self.console.print(table)
        self.console.print("─" * 30)
        self.console.print(f"{prompt} [0-3]: ", end="")
        choice = input().strip()

        if choice == "1":
            self._config_apply_defaults(lang)
        elif choice == "2":
            try:
                self._config_manual(lang)
            except Exception as e:
                self.console.print(f"   [red]❌ Hata: {e}[/red]")
        elif choice == "3":
            self._config_apply_shadow_mode(lang)
        elif choice == "0":
            self.console.print()
            return
        else:
            invalid_msg = "Geçersiz seçim." if lang == "tr" else "Invalid selection."
            self.console.print(f"   [red]❌ {invalid_msg}[/]")

        self.console.print()
        self.show_status_line()

    def _cmd_exit(self, args: str = "") -> None:
        """Çıkış."""
        self.running = False

    def _clear_screen(self) -> None:
        """Ekranı temizle."""
        os.system("clear" if os.name != "nt" else "cls")


def run_menu() -> None:
    """Menüyü başlat."""
    config_manager = ConfigManager()
    menu = DrakbenMenu(config_manager)
    menu.run()


if __name__ == "__main__":
    run_menu()
