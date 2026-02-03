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
    STYLE_DIM_CYAN = "dim cyan"
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

    BANNER = r"""
    ██████╗ ██████╗  █████╗ ██╗  ██╗██████╗ ███████╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝████╗  ██║
    ██║  ██║██████╔╝███████║█████╔╝ ██████╔╝█████╗  ██╔██╗ ██║
    ██║  ██║██╔══██╗██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝███████╗██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
    """

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
                if not llm_client.is_available():
                    llm_client = None
            except Exception:
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
        """Show banner - Stylized (Diagonal Split)."""
        # Diagonal Coloring: Top-Left (Red) -> Bottom-Right (Dark Gray)
        # Custom render for effective appearance

        if not self.BANNER.strip():
            return

        lines: list[LiteralString] = self.BANNER.strip("\n").split("\n")
        text = Text()

        color_primary: str = self.COLORS["red"]
        color_dark = "#6272a4"  # Dracula Comment (Dark elegant gray)

        max_width: int = max(len(line) for line in lines) if lines else 1
        total_lines: int = len(lines)

        for y, line in enumerate(lines):
            for x, char in enumerate(line):
                # Normalize coordinates (0.0 - 1.0)
                nx: float = x / max_width
                ny: float = y / total_lines

                # Diagonal Split (Top-Left -> Bottom-Right)
                # Threshold ~0.8-1.2 range. 0.95 provides balanced transition.
                if (nx + ny) < 0.95:
                    text.append(char, style=f"bold {color_primary}")
                else:
                    text.append(char, style=f"bold {color_dark}")
            text.append("\n")

        self.console.print(text)
        self.console.print(
            "    [*] DRAKBEN - Autonomous Pentest AI",
            style=f"bold {self.COLORS['purple']}",
        )
        self.console.print(
            "    [*] Kali Linux | AI-Powered | Autonomous Security Validation",
            style=self.COLORS["fg"],
        )
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
        icon = "🥷" if is_stealth else "📢"
        # Avoid nested ternary for SonarQube compliance
        on_text, off_text = ("AÇIK", "KAPALI") if is_tr else ("ON", "OFF")
        status = on_text if is_stealth else off_text
        color = self.STYLE_BOLD_GREEN if is_stealth else self.STYLE_BOLD_YELLOW
        return f"{icon} {status}", color

    def show_status_line(self) -> None:
        """Professional HUD Status Line (Premium Tactical Design)."""
        self.console.print()
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        is_tr = self.config.language == "tr"

        target = self.config.target or ("BELİRSİZ" if is_tr else "UNKNOWN")
        target_style = self.STYLE_BOLD_WHITE if self.config.target else "dim red"
        os_info = "Kali Linux" if self.system_info.get("is_kali") else self.system_info.get('os')
        mode_text, mode_color = self._get_mode_info(is_tr)
        lbl_target, lbl_system, lbl_mode, hint_lbl = self._get_status_labels(is_tr)

        # Build segments helper
        def get_seg(lbl: str, val: str, val_style: str = DrakbenMenu.STYLE_BOLD_WHITE) -> Text:
            t = Text()
            t.append(lbl, style=DrakbenMenu.STYLE_DIM_CYAN)
            t.append(f" {val}", style=val_style)
            return t

        # Tactical HUD Table
        status_table = Table(show_header=False, box=None, expand=True, padding=(0, 2))
        status_table.add_column("C1", ratio=1)
        status_table.add_column("C2", ratio=1)
        status_table.add_column("C3", ratio=1)
        status_table.add_row(
            get_seg(lbl_target, target, target_style),
            get_seg(lbl_system, os_info),
            get_seg(lbl_mode, mode_text, mode_color),
        )

        self.console.print(Panel(status_table, style="blue", border_style="dim blue", padding=(0, 1)))
        # Build commands string using constants
        cmd_list = ["/help", "/target", self.CMD_SCAN, self.CMD_STATUS, self.CMD_SHELL,
                    self.CMD_REPORT, "/llm", self.CMD_CONFIG, self.CMD_CLEAR, self.CMD_EXIT]
        commands = " • ".join(f"[dim cyan]{c}[/]" for c in cmd_list)
        self.console.print(f" [{self.STYLE_BOLD_CYAN}]{hint_lbl}:[/] {commands}")
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
        self.console.print(f"👋 {msg}", style=self.COLORS["purple"])

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
                "[DRAKBEN] Hazır. Doğal dilde komut verebilirsiniz.\n",
                style=self.COLORS["green"],
            )
        else:
            self.console.print(
                "[DRAKBEN] Ready. You can use natural language commands.\n",
                style=self.COLORS["green"],
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
            self.console.print(f"[dim red]Plugin Load Error: {e}[/dim]")

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
        # Lazy load brain
        if not self.brain:
            from core.agent.brain import DrakbenBrain
            self.brain = DrakbenBrain()

        thinking: str = "Düşünüyor..." if lang == "tr" else "Thinking..."

        try:
            with self.console.status(f"[bold {self.COLORS['purple']}]{thinking}"):
                if self.brain is None:
                    msg = "self.brain is not None"
                    raise AssertionError(msg)
                result = self.brain.think(user_input, self.config.target, lang)

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
        from rich.panel import Panel

        command = step.get("command") or step.get("tool", "")
        if not command:
            return "skip"

        # Show step info
        description = step.get("description", "")
        step_header = f"[{index}/{total}] {description}" if description else f"[{index}/{total}]"
        self.console.print(f"\n⏳ {step_header}", style="cyan")

        # Show command panel
        self.console.print(Panel(f"💻 {command}", border_style="yellow", padding=(0, 1)))

        # Ask for approval
        approval = self._ask_step_approval(lang)

        if approval == "stop":
            stop_msg = "⚠️ İşlem durduruldu. Menüye dönüldü." if lang == "tr" else "⚠️ Operation stopped. Returning to menu."
            self.console.print(f"\n{stop_msg}\n", style="yellow")
            return "stop"

        if approval == "no":
            skip_msg = "⏭️ Adım atlandı." if lang == "tr" else "⏭️ Step skipped."
            self.console.print(skip_msg, style="dim")
            return "skip"

        # Execute the command
        self._execute_command(command)
        self._show_next_step_hint(index, total, step, lang)
        return "done"

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
            self.console.print("Usage: /research <query>")
            return

        if isinstance(args, list):
            query: str = " ".join(args)
        else:
            query = str(args)
        self.console.print(f"[yellow]🔍 Searching for: {query}...[/yellow]")

        try:
            from core.network.web_researcher import WebResearcher

            researcher = WebResearcher()
            results = researcher.search_tool(query)

            if not results:
                self.console.print("[red]❌ No results found.[/red]")
                return

            self.console.print(
                f"\n[bold green]Found {len(results)} results:[/bold green]\n",
            )
            for i, r in enumerate(results, 1):
                self.console.print(f"{i}. [bold]{r['title']}[/bold]")
                self.console.print(f"   [blue underline]{r['href']}[/blue underline]")
                body: Any | str = (
                    r.get("body", "")[:200] + "..."
                    if r.get("body")
                    else "No description."
                )
                self.console.print(f"   [dim]{body}[/dim]\n")

        except Exception as e:
            self.console.print(f"[red]Error during research: {e}[/red]")

    def _cmd_help(self, args: str = "") -> None:
        """Help command - Professional CLI style."""
        from rich.table import Table

        lang: str = self.config.language

        # Commands table - clean, no emojis
        table = Table(show_header=True, box=None, padding=(0, 2))
        table.add_column("Command", style=self.STYLE_BOLD_CYAN, width=16)
        table.add_column("Description", style="white")

        if lang == "tr":
            commands: list[tuple[str, str]] = [
                ("/target <IP>", "Hedef belirle"),
                (self.CMD_UNTARGET, "Hedefi temizle"),
                (self.CMD_SCAN, "Otonom tarama baslat"),
                (self.CMD_TOOLS, "Mevcut araclari listele"),
                (self.CMD_STATUS, "Durum goster"),
                (self.CMD_REPORT, "Rapor olustur"),
                (self.CMD_SHELL, "Terminal erisimi"),
                (self.CMD_CONFIG, "Ayarlar"),
                ("/llm", "LLM yapilandirmasi"),
                ("/tr | /en", "Dil secimi"),
                (self.CMD_CLEAR, "Ekrani temizle"),
                (self.CMD_EXIT, "Cikis"),
            ]
            tip_text = '[dim]Dogal dilde konusabilirsin: "10.0.0.1 tara", "sql injection bul"[/]'
        else:
            commands: list[tuple[str, str]] = [
                ("/target <IP>", "Set target"),
                (self.CMD_UNTARGET, "Clear target"),
                (self.CMD_SCAN, "Start autonomous scan"),
                (self.CMD_TOOLS, "List available tools"),
                (self.CMD_STATUS, "Show status"),
                (self.CMD_REPORT, "Generate report"),
                (self.CMD_SHELL, "Terminal access"),
                (self.CMD_CONFIG, "Settings"),
                ("/llm", "LLM configuration"),
                ("/tr | /en", "Language"),
                (self.CMD_CLEAR, "Clear screen"),
                (self.CMD_EXIT, "Exit"),
            ]
            tip_text = '[dim]Chat naturally: "scan 10.0.0.1", "find sql injection"[/]'

        # Add rows to table
        for cmd, desc in commands:
            table.add_row(cmd, desc)

        # Simple output - no heavy panels
        self.console.print()
        self.console.print(f"[{self.STYLE_BOLD_CYAN}]DRAKBEN Commands[/]")
        self.console.print("─" * 40)
        self.console.print(table)
        self.console.print("─" * 40)
        self.console.print(tip_text)
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
        """Display current target information panel."""
        from rich.panel import Panel

        current_target = self.config.target
        if current_target:
            msg = (
                f"🎯 Mevcut hedef: [bold white]{current_target}[/]\nDeğiştirmek için: /target <IP>"
                if lang == "tr"
                else f"🎯 Current target: [bold white]{current_target}[/]\nTo change: /target <IP>"
            )
            title, border = ("Hedef Bilgisi", "cyan") if lang == "tr" else ("Target Info", "cyan")
        else:
            msg = (
                "Hedef ayarlanmamış. Kullanım: [bold]/target <IP>[/]"
                if lang == "tr"
                else "No target set. Usage: [bold]/target <IP>[/]"
            )
            title, border = ("Hedef Yok", "red") if lang == "tr" else ("No Target", "red")

        self.console.print(Panel(f"{msg}", title=f"[bold]{title}[/]", border_style=border, padding=(0, 1)))

    def _cmd_target(self, args: str = "") -> None:
        """Set target - with visual feedback."""
        from rich.panel import Panel

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

        content = (
            f"[bold {self.COLORS['green']}]Hedef ayarlandı:[/] [bold white]{args}[/]"
            if lang == "tr"
            else f"[bold {self.COLORS['green']}]Target set:[/] [bold white]{args}[/]"
        )
        self.console.print(Panel(content, border_style=self.COLORS["green"], padding=(0, 1)))

    def _cmd_untarget(self, args: str = "") -> None:
        """Clear target command."""
        from rich.panel import Panel

        lang: str = self.config.language

        if not self.config.target:
            msg = "Zaten hedef belirlenmemiş." if lang == "tr" else "No target is set."
            self.console.print(
                Panel(f"[yellow]⚠️  {msg}[/]", border_style="yellow", padding=(0, 1)),
            )
            return

        self.config_manager.set_target(None)
        self.config = self.config_manager.config

        # Also clear orchestrator target
        if self.orchestrator:
            self.orchestrator.clear_target()

        msg = (
            "[bold green]✅ Hedef temizlendi[/]"
            if lang == "tr"
            else "[bold green]✅ Target cleared[/]"
        )
        self.console.print(Panel(msg, border_style="green", padding=(0, 1)))

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
        hint = "Kullanım: /tools [recon|vuln|exploit|post|lateral]" if lang == "tr" else "Usage: /tools [recon|vuln|exploit|post|lateral]"
        self.console.print(f"\n[dim]{hint}[/]")

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

        if not self._check_target_set():
            return

        self._display_scan_panel(scan_mode)
        self._start_scan_with_recovery(scan_mode)

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
        from rich.panel import Panel

        if self.config.target:
            return True

        lang: str = self.config.language
        if lang == "tr":
            msg = "Önce hedef belirle: [bold]/target <IP>[/]"
            title = "❌ Hedef Yok"
        else:
            msg = "Set target first: [bold]/target <IP>[/]"
            title = "❌ No Target"

        self.console.print(
            Panel(
                f"[red]{msg}[/]",
                title=f"[red]{title}[/]",
                border_style="red",
                padding=(0, 1),
            ),
        )
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
        """Start scan with error recovery."""
        lang: str = self.config.language

        try:
            self._ensure_agent_initialized()
            self._initialize_agent_with_retry(scan_mode, lang)
            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)
            self.agent.run_autonomous_loop()
        except KeyboardInterrupt:
            # Ctrl+C during scan = Stop scan, return to menu
            try:
                from core.stop_controller import stop_controller
                stop_controller.stop()
            except ImportError:
                pass
            interrupt_msg: str = (
                "\n🛑 Tarama durduruldu. Menüye dönülüyor..."
                if lang == "tr"
                else "\n🛑 Scan stopped. Returning to menu..."
            )
            self.console.print(interrupt_msg, style="yellow")
            # Reset stop controller for next operation
            try:
                from core.stop_controller import stop_controller
                stop_controller.reset()
            except ImportError:
                pass
            # Don't re-raise - return to menu gracefully
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.exception("Scan error: %s", e)
            error_msg: str = (
                f"Tarama sırasında hata: {e}" if lang == "tr" else f"Scan error: {e}"
            )
            self.console.print(f"❌ {error_msg}", style="red")

    def _ensure_agent_initialized(self) -> None:
        """Ensure agent is initialized."""
        if not self.agent:
            from core.agent.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)

    def _initialize_agent_with_retry(self, scan_mode: str, lang: str) -> None:
        """Initialize agent with retry on failure."""
        from rich.panel import Panel

        try:
            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)
            target: str = self.config.target or "localhost"
            self.agent.initialize(target=target, mode=scan_mode)
        except Exception as init_error:
            error_msg: str = (
                f"Agent başlatma hatası: {init_error}"
                if lang == "tr"
                else f"Agent initialization error: {init_error}"
            )
            self.console.print(
                Panel(
                    f"[red]{error_msg}[/]\n[dim]Yeniden deneniyor... / Retrying...[/]",
                    title="[red]⚠️ Hata / Error[/]",
                    border_style="yellow",
                    padding=(0, 1),
                ),
            )
            # Retry with fresh agent
            from core.agent.refactored_agent import RefactoredDrakbenAgent

            target: str = self.config.target or "localhost"
            self.agent = RefactoredDrakbenAgent(self.config_manager)
            self.agent.initialize(target=target, mode=scan_mode)

    def _cmd_clear(self, args: str = "") -> None:
        """Clear screen - banner and menu remain."""
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _cmd_turkish(self, args: str = "") -> None:
        """Switch to Turkish."""
        from rich.panel import Panel

        self.config_manager.set_language("tr")
        self.config: DrakbenConfig = self.config_manager.config
        self.console.print(
            Panel(
                "[bold]🇹🇷 Dil Türkçe olarak ayarlandı[/]",
                border_style=self.COLORS["green"],
                padding=(0, 1),
            ),
        )

    def _cmd_english(self, args: str = "") -> None:
        """Switch to English."""
        from rich.panel import Panel

        self.config_manager.set_language("en")
        self.config: DrakbenConfig = self.config_manager.config
        self.console.print(
            Panel(
                "[bold]🇬🇧 Language set to English[/]",
                border_style=self.COLORS["green"],
                padding=(0, 1),
            ),
        )

    def _cmd_shell(self, args: str = "") -> None:
        """Launch interactive shell."""
        from rich.panel import Panel

        lang: str = self.config.language

        if lang == "tr":
            msg = "[bold]💻 İnteraktif kabuk başlatılıyor...[/]\n[dim]Çıkmak için 'exit' yazın[/]"
        else:
            msg = (
                "[bold]💻 Starting interactive shell...[/]\n[dim]Type 'exit' to quit[/]"
            )

        self.console.print(
            Panel(
                msg,
                title=f"[bold {self.COLORS['cyan']}]DRAKBEN Shell[/]",
                border_style=self.COLORS["cyan"],
                padding=(0, 1),
            ),
        )

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
            plan_title = "📋 Mission Plan" if lang == "en" else "📋 Görev Planı"
            self.console.print(
                Panel(
                    self._create_plan_table(),
                    title=f"[bold {self.COLORS['pink']}]{plan_title}[/]",
                    border_style=self.COLORS["pink"],
                    padding=(0, 1),
                ),
            )

    def _show_idle_panel(self, lang: str) -> None:
        """Show idle message panel when agent is not active."""
        from rich.panel import Panel

        idle_msg = (
            "[dim]Ajan şu an aktif değil. Bir tarama başlatmak için:[/]\n"
            f"[{self.STYLE_BOLD_CYAN}]1.[/] /target <IP>\n"
            f"[{self.STYLE_BOLD_CYAN}]2.[/] /scan"
            if lang == "tr"
            else "[dim]Agent is currently idle. To start a scan:[/]\n"
            f"[{self.STYLE_BOLD_CYAN}]1.[/] /target <IP>\n"
            f"[{self.STYLE_BOLD_CYAN}]2.[/] /scan"
        )
        idle_title = "🤖 Agent Idle" if lang == "en" else "🤖 Ajan Beklemede"
        self.console.print(
            Panel(
                idle_msg,
                title=f"[bold yellow]{idle_title}[/]",
                border_style="yellow",
                padding=(0, 1),
            ),
        )

    def _cmd_status(self, args: str = "") -> None:
        """Show current status - Modern dashboard style."""
        from rich.panel import Panel

        lang: str = self.config.language
        self.console.print()

        title: str = "📊 DRAKBEN Status" if lang == "en" else "📊 DRAKBEN Durumu"
        self.console.print(
            Panel(
                self._create_system_table(lang),
                title=f"[bold {self.COLORS['cyan']}]{title}[/]",
                border_style=self.COLORS["purple"],
                padding=(0, 1),
            ),
        )

        if self.agent and self.agent.state:
            self._show_agent_panels(lang)
        else:
            self._show_idle_panel(lang)

        llm_title = "🧠 LLM"
        self.console.print(
            Panel(
                self._create_llm_content(),
                title=f"[bold {self.COLORS['green']}]{llm_title}[/]",
                border_style=self.COLORS["green"],
                padding=(0, 1),
            ),
        )
        self.console.print()

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
            StepStatus.FAILED: "bold red",
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
        summary_table.add_column("K", style="bold purple")
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
        from rich.panel import Panel

        from modules.report_generator import (
            ReportConfig,
            ReportFormat,
            generate_report_from_state,
        )

        lang = self.config.language

        if not self.agent or not self.agent.state:
            msg = "Önce bir tarama başlatmalısın." if lang == "tr" else "You must start a scan first."
            self.console.print(Panel(f"[red]❌ {msg}[/]", style="red"))
            return

        gen_msg = "Profesyonel rapor oluşturuluyor..." if lang == "tr" else "Generating professional report..."
        self.console.print(f"[bold {self.COLORS['purple']}]📝 {gen_msg}[/]")

        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = (self.config.target or "unknown").replace(".", "_").replace("/", "_").replace(":", "_")
            output_path = reports_dir / f"drakben_report_{target_clean}_{timestamp}.html"

            config = ReportConfig(title=f"DRAKBEN AI Security Report - {self.config.target}", use_llm_summary=True)
            final_path = generate_report_from_state(state=self.agent.state, output_path=str(output_path), format=ReportFormat.HTML, config=config)

            stitle = "RAPOR ÖZETİ" if lang == "tr" else "REPORT SUMMARY"
            self.console.print()
            self.console.print(
                Panel(
                    self._build_report_summary_table(lang, final_path),
                    title=f"[bold {self.COLORS['purple']}]{stitle}[/]",
                    border_style=self.COLORS["purple"],
                    padding=(1, 2),
                ),
            )

        except Exception as e:
            err_msg = f"Rapor oluşturma hatası: {e}" if lang == "tr" else f"Report generation error: {e}"
            self.console.print(f"[bold red]❌ {err_msg}[/]")

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
        target_style = "bold white" if self.config.target else "dim red"

        os_info = self.system_info.get("os", "Unknown")
        is_kali = self.system_info.get("is_kali", False)
        os_display = "Kali Linux" if is_kali else os_info

        tools = self.system_info.get("available_tools", {})
        tool_count = len(tools)
        tool_color = "green" if tool_count > 10 else "yellow"

        # LEFT COLUMN: IDENTITY
        left_content = Table(show_header=True, box=None, header_style=self.STYLE_BOLD_CYAN, padding=(0, 0))
        left_content.add_column("🛡️", width=3)
        left_content.add_column(labels["header_id"], width=22)
        left_content.add_column(labels["lbl_status"], justify="right", width=15)

        left_content.add_row("🎯", f"[dim]{labels['lbl_scope']}[/]", f"[{target_style}]{target_val}[/]")
        left_content.add_row("🌍", f"[dim]{labels['lbl_lang']}[/]", "Türkçe 🇹🇷" if is_tr else "English 🇬🇧")
        left_content.add_row("💻", f"[dim]{labels['lbl_os']}[/]", os_display)

        # RIGHT COLUMN: PERFORMANCE
        right_content = Table(show_header=True, box=None, header_style=self.STYLE_BOLD_CYAN, padding=(0, 0))
        right_content.add_column("🚀", width=3)
        right_content.add_column(labels["header_perf"], width=22)
        right_content.add_column(labels["lbl_value"], justify="right", width=15)

        right_content.add_row("🛠️", f"[dim]{labels['lbl_tools']}[/]", f"[{tool_color}]{tool_count} {labels['unit_str']}[/]")
        stealth_str = f"[bold green]{labels['active_str']}[/]" if self.config.stealth_mode else f"[bold yellow]{labels['inactive_str']}[/]"
        right_content.add_row("🥷", f"[dim]{labels['lbl_stealth']}[/]", stealth_str)
        right_content.add_row("⚡", f"[dim]{labels['lbl_threads']}[/]", f"[bold yellow]{self.config.max_threads} {labels['core_str']}[/]")

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
            "complete": "bold green", "failed": "bold red",
        }
        phase_color: str = phase_colors.get(state.phase.value, "white")
        phase_name = self._get_phase_display_name(state.phase.value, is_tr)

        agent_table = Table(show_header=False, box=None, padding=(0, 1))
        agent_table.add_column("Key", style=f"bold {self.COLORS['purple']}")
        agent_table.add_column("Value", style=self.COLORS["fg"])

        lbl_phase = "📍 Evre" if is_tr else "📍 Phase"
        lbl_svc = "🔌 Servisler" if is_tr else "🔌 Services"
        lbl_vulns = "⚠️  Zafiyetler" if is_tr else "⚠️  Vulns"
        lbl_foothold = "🚩 Erişim" if is_tr else "🚩 Foothold"

        agent_table.add_row(lbl_phase, f"[{phase_color}]{phase_name.replace('_', ' ').title()}[/]")
        agent_table.add_row(lbl_svc, f"[cyan]{len(state.open_services)}[/]")
        vuln_color = "red" if state.vulnerabilities else "dim"
        agent_table.add_row(lbl_vulns, f"[{vuln_color}]{len(state.vulnerabilities)}[/]")
        agent_table.add_row(lbl_foothold, "✅" if state.has_foothold else "❌")
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
        from rich.panel import Panel

        # Show current status
        title: str = "🤖 LLM Kurulumu" if lang == "tr" else "🤖 LLM Setup"
        self.console.print()

        # Show current config
        current_info: str = (
            "[dim]Mevcut ayar yok[/dim]"
            if lang == "tr"
            else "[dim]No current config[/dim]"
        )
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            current_info: str = f"[green]●[/green] {info.get('provider', 'N/A')} / {info.get('model', 'N/A')}"

        self.console.print(
            Panel(
                f"{'Mevcut' if lang == 'tr' else 'Current'}: {current_info}",
                title=f"[bold {self.COLORS['cyan']}]{title}[/]",
                border_style=self.COLORS["purple"],
                padding=(0, 1),
            ),
        )

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
                self.console.print(f"[red]❌ {msg}[/red]")
                return None, None

        return selected_model, api_key

    def _save_llm_config(self, provider_key: str, selected_model: str, api_key: str) -> None:
        from pathlib import Path

        from rich.panel import Panel

        env_file = Path("config/api.env")

        # Configuration templates
        templates: dict[str, str] = {
            "openrouter": f"OPENROUTER_API_KEY={api_key}\nOPENROUTER_MODEL={selected_model}",
            "openai": f"OPENAI_API_KEY={api_key}\nOPENAI_MODEL={selected_model}",
            "ollama": f"LOCAL_LLM_URL=http://localhost:11434\nLOCAL_LLM_MODEL={selected_model}",
        }

        config_body: str | None = templates.get(provider_key)
        if not config_body:
            self.console.print(f"[red]❌ Unknown provider: {provider_key}[/red]")
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
                f"✅ LLM ayarlandı: {provider_key} / {selected_model}"
                if lang == "tr"
                else f"✅ LLM configured: {provider_key} / {selected_model}"
            )
            self.console.print(
                Panel(
                    f"[bold green]{msg}[/bold green]",
                    border_style="green",
                    padding=(0, 1),
                ),
            )

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
                        "✅ Bağlantı başarılı!"
                        if lang == "tr"
                        else "✅ Connection successful!"
                    )
                    self.console.print(f"[green]{ok_msg}[/green]\n")
                else:
                    err_msg: str = (
                        "❌ Bağlantı hatası:"
                        if lang == "tr"
                        else "❌ Connection error:"
                    )
                    self.console.print(
                        f"[red]{err_msg} {test_result.get('error', 'Unknown')}[/red]\n",
                    )

        except Exception as e:
            self.console.print(f"\n[red]❌ Save error: {e}[/]")

    def _config_apply_defaults(self, lang: str) -> None:
        """Apply automatic default configuration."""
        self.config.stealth_mode = False
        self.config.max_threads = 4
        self.config.timeout = 30
        self.config.verbose = False
        self.config_manager.save_config()
        msg = "Standart ayarlar uygulandı (4 Thread, 30s)." if lang == "tr" else "Standard defaults applied (4 Threads, 30s)."
        self.console.print(f"\n   [bold green]✅ {msg}[/]\n")

    def _config_apply_shadow_mode(self, lang: str) -> None:
        """Apply shadow mode (hacker preset) configuration."""
        self.config.stealth_mode = True
        self.config.max_threads = 1
        self.config.timeout = 300
        self.config.verbose = True
        self.config_manager.save_config()
        msg = "Shadow Mode Aktif: Ghost Protocol ON, 1 Thread, 300s Timeout." if lang == "tr" else "Shadow Mode Active: Ghost Protocol ON, 1 Thread, 300s Timeout."
        self.console.print(f"\n   [bold purple]🥷 {msg}[/]\n")

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
        table.add_column("Option", style="bold cyan", width=6)
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
