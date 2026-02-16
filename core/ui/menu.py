from typing import TYPE_CHECKING, Any, LiteralString

if TYPE_CHECKING:
    from collections.abc import Callable

    from core.agent.brain import DrakbenBrain
    from core.agent.refactored_agent import RefactoredDrakbenAgent
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
from core.ui.menu_ai_processing import MenuAIProcessingMixin
from core.ui.menu_commands import MenuCommandsMixin
from core.ui.menu_config import MenuConfigMixin


class DrakbenMenu(MenuAIProcessingMixin, MenuCommandsMixin, MenuConfigMixin):
    """DRAKBEN Minimal Menu System.

    COMMANDS (16):
    - /help      : Help
    - /target    : Set target
    - /untarget  : Clear target
    - /scan      : Scan
    - /shell     : Terminal access
    - /status    : Show status
    - /llm       : LLM settings
    - /clear     : Clear screen
    - /tr        : Turkish
    - /en        : English
    - /research  : Research mode
    - /report    : Generate report
    - /config    : Settings
    - /tools     : List tools
    - /memory    : Memory status
    - /exit      : Exit

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
    MSG_AGENT_NOT_NONE = "self.agent must not be None"

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

            # Try to get LLM client (only if real API key exists)
            llm_client = None
            try:
                from llm.openrouter_client import OpenRouterClient
                llm_client = OpenRouterClient()
                # Check if API key is configured and not a placeholder
                api_key = getattr(llm_client, "api_key", None)
                if not api_key or api_key in (
                    "your_key_here", "your-key-here", "YOUR_KEY_HERE",
                    "sk-xxx", "sk-your-key",
                ):
                    llm_client = None
            except (ImportError, OSError, AttributeError):
                pass

            self.orchestrator = get_orchestrator(llm_client)  # type: ignore[assignment]
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

def run_menu() -> None:
    """Menüyü başlat."""
    config_manager = ConfigManager()
    menu = DrakbenMenu(config_manager)
    menu.run()


if __name__ == "__main__":
    run_menu()
