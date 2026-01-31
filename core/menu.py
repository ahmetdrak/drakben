import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, LiteralString, Optional

from core.execution_engine import ExecutionResult
from core.state import AgentState
from core.tool_selector import ToolSpec

if TYPE_CHECKING:
    from rich.table import Table

    from core.brain import DrakbenBrain
    from core.refactored_agent import RefactoredDrakbenAgent

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
from core.kali_detector import KaliDetector


class DrakbenMenu:
    """
    DRAKBEN Minimal Menu System.

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
    COLORS: Dict[str, str] = {
        "red": "#FF5555",
        "green": "#50FA7B",
        "yellow": "#F1FA8C",
        "purple": "#8BE9FD",  # Cyan (Hacker Blue) - Dracula Cyan
        "cyan": "#8BE9FD",
        "pink": "#FFB86C",  # Orange - Replaced Pink
        "fg": "#F8F8F2",
    }

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
        self.agent: Optional["RefactoredDrakbenAgent"] = None
        self.brain: Optional["DrakbenBrain"] = None
        self.running = True
        self.system_info: Dict[str, Any] = {}
        self._commands: Dict[str, Callable[[str], Any]] = {
            "/help": self._cmd_help,
            "/target": self._cmd_target,
            "/scan": self._cmd_scan,
            "/shell": self._cmd_shell,
            "/status": self._cmd_status,
            "/llm": self._cmd_llm_setup,
            "/clear": self._cmd_clear,
            "/tr": self._cmd_turkish,
            "/en": self._cmd_english,
            "/exit": self._cmd_exit,
            "/research": self._cmd_research,
            "/report": self._cmd_report,
            "/config": self._cmd_config,
            "/untarget": lambda x: self._cmd_target("clear"),
        }

        # System detection
        self._detect_system()

    def _detect_system(self) -> None:
        """Detect system and save info"""
        import platform

        self.system_info = {
            "os": platform.system(),
            "os_version": platform.release(),
            "is_kali": self.kali.is_kali(),
            "python_version": platform.python_version(),
            "available_tools": self.kali.get_available_tools(),
        }

    def show_banner(self) -> None:
        """Show banner - Stylized (Diagonal Split)"""
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
            "    [*] Kali Linux | AI-Powered | Autonomous Security Validation", style=self.COLORS["fg"]
        )
        self.console.print()

    def show_status_line(self) -> None:
        """Professional HUD Status Line (Next-Gen Design)"""
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        lang = self.config.language
        target = self.config.target or ("UNKNOWN" if lang != "tr" else "BELİRSİZ")
        os_info = "Kali Linux 🐉" if self.system_info.get("is_kali") else f"{self.system_info.get('os')} 💻"
        
        # Get Stealth Mode (Default False if not set)
        is_stealth = getattr(self.config, "stealth_mode", False)
        stealth_icon = "🥷" if is_stealth else "📢"
        stealth_text = "ON" if is_stealth else "OFF"
        
        # Status Bar Table
        status_table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
        # Define 3 main columns with labels and values
        status_table.add_column("Label1", justify="right", style="dim cyan", ratio=1)
        status_table.add_column("Value1", justify="left", style="bold white", ratio=2)
        status_table.add_column("Label2", justify="right", style="dim cyan", ratio=1)
        status_table.add_column("Value2", justify="left", style="bold green", ratio=2)
        status_table.add_column("Label3", justify="right", style="dim cyan", ratio=1)
        status_table.add_column("Value3", justify="left", style="bold yellow", ratio=1)

        status_table.add_row(
            "TARGET:", target,
            "SYSTEM:", os_info,
            "MODE:", f"{stealth_icon} {stealth_text}"
        )
        
        # Command Hint
        commands = "[dim cyan]/help[/] • [dim cyan]/target[/] • [dim cyan]/untarget[/] • [dim cyan]/scan[/] • [dim cyan]/config[/] • [dim cyan]/clear[/] • [dim cyan]/report[/] • [dim cyan]/exit[/]"
        
        # Render
        self.console.print(Panel(status_table, style="blue", border_style="dim blue", padding=(0, 1)))
        self.console.print(f"[center]{commands}[/center]")
        self.console.print()

    def run(self) -> None:
        """Main loop"""
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
            try:
                # Get user input with protected prompt
                user_input: str = self._get_input().strip()

                if not user_input:
                    continue

                # Is it a slash command?
                if user_input.startswith("/"):
                    self._handle_command(user_input)
                else:
                    # Send to AI
                    self._process_with_ai(user_input)

            except KeyboardInterrupt:
                # Ctrl+C = Direct exit
                self.console.print("\n")
                break
            except EOFError:
                break

        # Exit
        msg: str = "Görüşürüz!" if lang == "tr" else "Goodbye!"
        self.console.print(f"👋 {msg}", style=self.COLORS["purple"])

    def _show_welcome_message(self, lang) -> None:
        """Helper to show welcome message"""
        if lang == "tr":
            self.console.print(
                "💬 Merhaba! Benimle doğal dilde konuşabilirsin.\n",
                style=self.COLORS["green"],
            )
        else:
            self.console.print(
                "💬 Hello! You can talk to me in natural language.\n",
                style=self.COLORS["green"],
            )

    def _load_plugins_at_startup(self, lang) -> None:
        """Helper to safely load plugins without polluting run() method"""
        try:
            from core.plugin_loader import PluginLoader

            loader = PluginLoader()
            plugins: Dict[str, ToolSpec] = loader.load_plugins()

            if plugins:
                msg: str = (
                    f"🔌 {len(plugins)} Plugin Yüklendi"
                    if lang == "tr"
                    else f"🔌 {len(plugins)} Plugins Loaded"
                )
                self.console.print(f"[dim green]{msg}[/dim]")

                # Enterprise Plugin Registration (No Monkey Patching)
                from core.tool_selector import ToolSelector
                ToolSelector.register_global_plugins(plugins)

        except Exception as e:
            self.console.print(f"[dim red]Plugin Load Error: {e}[/dim]")

    def _get_input(self) -> str:
        """Get user input with protected prompt that can't be deleted"""
        if PROMPT_TOOLKIT_AVAILABLE:
            # prompt_toolkit protects the prompt from being deleted
            if self.config.target:
                prompt_text = HTML(
                    f'<style fg="#8BE9FD" bg="" bold="true">drakben</style>'
                    f'<style fg="#8BE9FD">@{self.config.target}</style>'
                    f'<style fg="#F8F8F2">&gt; </style>'
                )
            else:
                prompt_text = HTML(
                    '<style fg="#8BE9FD" bg="" bold="true">drakben</style>'
                    '<style fg="#F8F8F2">&gt; </style>'
                )
            try:
                return pt_prompt(prompt_text)
            except (EOFError, KeyboardInterrupt):
                return "/exit"
        else:
            # Fallback: print prompt then input
            prompt = Text()
            prompt.append("drakben", style=f"bold {self.COLORS['purple']}")
            if self.config.target:
                prompt.append(
                    f"@{self.config.target}", style=f"bold {self.COLORS['cyan']}"
                )
            prompt.append("> ", style=self.COLORS["fg"])
            self.console.print(prompt, end="")
            return input()

    def _handle_command(self, user_input: str) -> None:
        """Handle slash commands"""
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
        """Process with AI"""
        lang: str = self.config.language

        # Lazy load brain
        if not self.brain:
            from core.brain import DrakbenBrain

            self.brain = DrakbenBrain()

        thinking: str = "Düşünüyor..." if lang == "tr" else "Thinking..."

        with self.console.status(f"[bold {self.COLORS['purple']}]🧠 {thinking}"):
            assert self.brain is not None
            result = self.brain.think(user_input, self.config.target)

        self._handle_ai_response_text(result, lang)
        self._handle_ai_command(result, lang)

    def _handle_ai_response_text(self, result, lang) -> None:
        """Handle displaying the AI response text"""
        response_text = (
            result.get("llm_response")
            or result.get("reply")
            or result.get("response")
            or result.get("reasoning")
        )

        if response_text:
            self.console.print(f"\n🤖 {response_text}\n", style=self.COLORS["cyan"])
        else:
            # No response - show error or offline message
            if result.get("error"):
                self.console.print(f"\n❌ Hata: {result['error']}\n", style="red")
            else:
                offline_msg: str = (
                    "LLM bağlantısı yok. Lütfen API ayarlarını kontrol edin."
                    if lang == "tr"
                    else "No LLM connection. Please check API settings."
                )
                self.console.print(f"\n⚠️ {offline_msg}\n", style="yellow")

    def _handle_ai_command(self, result, lang) -> None:
        """Handle executing the command suggested by AI"""
        command = result.get("command")
        if not command:
            return

        # FIX: Auto-approve internal slash commands (/scan, /target)
        if command.strip().startswith("/"):
            # Print it so user sees it happens
            self.console.print(f"🤖 Otomatik işlem: {command}", style="dim")
            self._execute_command(command)
            return

        self.console.print(f"📝 Komut: [bold yellow]{command}[/]")

        # Check approval
        if result.get("needs_approval", True):
            q: str = "Çalıştır? (e/h)" if lang == "tr" else "Run? (y/n)"
            # ... prompt code ...
            # For now just default to asking
            resp: str = Prompt.ask(q, choices=["e", "h", "y", "n"], default="e")
            if resp.lower() in ["e", "y"]:
                self._execute_command(command)
        else:
            self._execute_command(command)

    def _execute_command(self, command: str) -> None:
        """Execute command"""
        lang: str = self.config.language

        # FIX: Check if this is an internal slash command recommended by AI
        if command.strip().startswith("/"):
            self.console.print(
                f"🔄 Dahili komut çalıştırılıyor: {command}", style="dim"
            )
            self._handle_command(command)
            return

        # Agent lazy load
        if not self.agent:
            from core.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)
            assert self.agent is not None
            self.agent.initialize(target=self.config.target or "")

        msg: str = "Çalıştırılıyor..." if lang == "tr" else "Executing..."
        self.console.print(f"⚡ {msg}", style=self.COLORS["yellow"])

        assert self.agent is not None
        assert self.agent.executor is not None
        result: ExecutionResult = self.agent.executor.terminal.execute(
            command, timeout=300
        )

        if result.status.value == "success":
            self.console.print(
                f"✅ OK ({result.duration:.1f}s)", style=self.COLORS["green"]
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

    def _cmd_research(self, args) -> None:
        """Web research command"""
        if not args:
            self.console.print("Usage: /research <query>")
            return

        if isinstance(args, list):
            query: str = " ".join(args)
        else:
            query = str(args)
        self.console.print(f"[yellow]🔍 Searching for: {query}...[/yellow]")

        try:
            from core.web_researcher import WebResearcher

            researcher = WebResearcher()
            results = researcher.search_tool(query)

            if not results:
                self.console.print("[red]❌ No results found.[/red]")
                return

            self.console.print(
                f"\n[bold green]Found {len(results)} results:[/bold green]\n"
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
        """Help command - Modern Dracula themed"""
        from rich.panel import Panel
        from rich.table import Table

        lang: str = self.config.language

        # Commands table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Cmd", style=f"bold {self.COLORS['red']}")  # Komutlar kırmızı
        table.add_column("Desc", style=self.COLORS["fg"])

        if lang == "tr":
            commands: list[tuple[str, str]] = [
                ("❓ /help", "Yardım menüsü"),
                ("🎯 /target <IP>", "Hedef belirle"),
                ("� /untarget", "Hedefi temizle"),
                ("�🔍 /scan", "Otonom tarama başlat"),
                ("💻 /shell", "İnteraktif kabuk"),
                ("📊 /status", "Durum bilgisi"),
                ("🤖 /llm", "LLM/API ayarları"),
                ("� /config", "Sistem yapılandırması"),
                ("🌐 /research", "İnternet araştırması"),
                ("�📝 /report", "Rapor oluştur"),
                ("🧹 /clear", "Ekranı temizle"),
                ("🇹🇷 /tr", "Türkçe mod"),
                ("🇬🇧 /en", "English mode"),
                ("🚪 /exit", "Çıkış"),
            ]
            title = "DRAKBEN Komutları"
            tip_title = "💡 İpucu"
            tip_text = 'Doğal dilde konuşabilirsin:\n[dim]• "10.0.0.1 portlarını tara"\n• "sql injection test et"[/]'
        else:
            commands: list[tuple[str, str]] = [
                ("❓ /help", "Help menu"),
                ("🎯 /target <IP>", "Set target"),
                ("� /untarget", "Clear target"),
                ("�🔍 /scan", "Start autonomous scan"),
                ("💻 /shell", "Interactive shell"),
                ("📊 /status", "Status info"),
                ("🤖 /llm", "LLM/API settings"),
                ("🔧 /config", "System config"),
                ("🌐 /research", "Web research"),
                ("📝 /report", "Generate report"),
                ("🧹 /clear", "Clear screen"),
                ("🇹🇷 /tr", "Turkish mode"),
                ("🇬🇧 /en", "English mode"),
                ("🚪 /exit", "Exit"),
            ]
            title = "DRAKBEN Commands"
            tip_title = "💡 Tip"
            tip_text = 'Talk naturally:\n[dim]• "scan ports on 10.0.0.1"\n• "test sql injection"[/]'

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        # Main panel
        self.console.print()
        self.console.print(
            Panel(
                table,
                title=f"[bold {self.COLORS['red']}]{title}[/]",
                border_style=self.COLORS["purple"],
                padding=(1, 2),
            )
        )

        # Tip panel
        self.console.print(
            Panel(
                tip_text,
                title=f"[bold {self.COLORS['yellow']}]{tip_title}[/]",
                border_style=self.COLORS["green"],
                padding=(0, 2),
            )
        )
        self.console.print()

    def _cmd_target(self, args: str = "") -> None:
        """Set or clear target - with visual feedback"""
        from rich.panel import Panel

        lang: str = self.config.language
        args = args.strip()

        # Check for clear command
        if args.lower() in ["clear", "off", "none", "delete", "sil", "iptal", "remove"]:
            self.config_manager.set_target(None)
            self.config: DrakbenConfig = self.config_manager.config

            if lang == "tr":
                msg = "[bold green]✅ Hedef temizlendi[/]"
            else:
                msg = "[bold green]✅ Target cleared[/]"

            self.console.print(Panel(msg, border_style="green", padding=(0, 1)))
            return

        if not args:
            if lang == "tr":
                msg = "Kullanım: /target <IP>\nTemizlemek için: /target sil"
            else:
                msg = "Usage: /target <IP>\nTo clear: /target clear"

            self.console.print(
                Panel(
                    f"[bold red]{msg}[/]",
                    title="[red]❌ Hata[/]" if lang == "tr" else "[red]❌ Error[/]",
                    border_style="red",
                    padding=(0, 1),
                )
            )
            return

        self.config_manager.set_target(args)
        self.config: DrakbenConfig = self.config_manager.config

        if lang == "tr":
            content: str = f"[bold {self.COLORS['green']}]🎯 Hedef ayarlandı:[/] [bold white]{args}[/]"
        else:
            content: str = (
                f"[bold {self.COLORS['green']}]🎯 Target set:[/] [bold white]{args}[/]"
            )

        self.console.print(
            Panel(content, border_style=self.COLORS["green"], padding=(0, 1))
        )

    def _cmd_scan(self, args: str = "") -> None:
        """
        Scan target - with visual feedback

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
        """Parse scan mode from arguments"""
        args_lower: str = args.strip().lower()
        if args_lower in ["stealth", "sessiz", "silent", "quiet", "gizli"]:
            return "stealth"
        elif args_lower in ["aggressive", "hizli", "fast", "agresif", "quick"]:
            return "aggressive"
        return "auto"

    def _check_target_set(self) -> bool:
        """Check if target is set, show error if not"""
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
            )
        )
        return False

    def _display_scan_panel(self, scan_mode: str) -> None:
        """Display scan initialization panel"""
        from rich.panel import Panel

        lang: str = self.config.language
        mode_info: Dict[str, tuple[str, str]] = {
            "stealth": (
                "🥷 STEALTH",
                "Sessiz mod - Yavaş ama gizli"
                if lang == "tr"
                else "Silent mode - Slow but stealthy",
            ),
            "aggressive": (
                "⚡ AGGRESSIVE",
                "Hızlı mod - Agresif tarama"
                if lang == "tr"
                else "Fast mode - Aggressive scan",
            ),
            "auto": ("🤖 AUTO", "Otomatik mod" if lang == "tr" else "Auto mode"),
        }
        mode_label, mode_desc = mode_info.get(scan_mode, mode_info["auto"])

        if lang == "tr":
            content: str = f"[bold]🔍 Otonom tarama başlatılıyor...[/]\n[dim]Hedef: {self.config.target}[/]\n[dim]Mod: {mode_label} - {mode_desc}[/]"
            title = "DRAKBEN Scanner"
        else:
            content: str = f"[bold]🔍 Starting autonomous scan...[/]\n[dim]Target: {self.config.target}[/]\n[dim]Mode: {mode_label} - {mode_desc}[/]"
            title = "DRAKBEN Scanner"

        self.console.print(
            Panel(
                content,
                title=f"[bold {self.COLORS['cyan']}]{title}[/]",
                border_style=self.COLORS["cyan"],
                padding=(0, 1),
            )
        )

    def _start_scan_with_recovery(self, scan_mode: str) -> None:
        """Start scan with error recovery"""
        lang: str = self.config.language

        try:
            self._ensure_agent_initialized()
            self._initialize_agent_with_retry(scan_mode, lang)
            assert self.agent is not None
            self.agent.run_autonomous_loop()
        except KeyboardInterrupt:
            interrupt_msg: str = (
                "Tarama kullanıcı tarafından durduruldu."
                if lang == "tr"
                else "Scan stopped by user."
            )
            self.console.print(f"\n⚠️ {interrupt_msg}", style="yellow")
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.exception(f"Scan error: {e}")
            error_msg: str = (
                f"Tarama sırasında hata: {e}" if lang == "tr" else f"Scan error: {e}"
            )
            self.console.print(f"❌ {error_msg}", style="red")

    def _ensure_agent_initialized(self) -> None:
        """Ensure agent is initialized"""
        if not self.agent:
            from core.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)

    def _initialize_agent_with_retry(self, scan_mode: str, lang: str) -> None:
        """Initialize agent with retry on failure"""
        from rich.panel import Panel

        try:
            assert self.agent is not None
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
                )
            )
            # Retry with fresh agent
            from core.refactored_agent import RefactoredDrakbenAgent

            target: str = self.config.target or "localhost"
            self.agent = RefactoredDrakbenAgent(self.config_manager)
            self.agent.initialize(target=target, mode=scan_mode)

    def _cmd_clear(self, args: str = "") -> None:
        """Clear screen - banner and menu remain"""
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _cmd_turkish(self, args: str = "") -> None:
        """Switch to Turkish"""
        from rich.panel import Panel

        self.config_manager.set_language("tr")
        self.config: DrakbenConfig = self.config_manager.config
        self.console.print(
            Panel(
                "[bold]🇹🇷 Dil Türkçe olarak ayarlandı[/]",
                border_style=self.COLORS["green"],
                padding=(0, 1),
            )
        )

    def _cmd_english(self, args: str = "") -> None:
        """Switch to English"""
        from rich.panel import Panel

        self.config_manager.set_language("en")
        self.config: DrakbenConfig = self.config_manager.config
        self.console.print(
            Panel(
                "[bold]🇬🇧 Language set to English[/]",
                border_style=self.COLORS["green"],
                padding=(0, 1),
            )
        )

    def _cmd_shell(self, args: str = "") -> None:
        """Launch interactive shell"""
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
            )
        )

        from core.interactive_shell import InteractiveShell

        shell = InteractiveShell(config_manager=self.config_manager, agent=self.agent)
        shell.current_target = self.config.target
        shell.start()

        # Restore menu after shell exits
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _cmd_status(self, args: str = "") -> None:
        """Show current status - Modern dashboard style"""
        from rich.panel import Panel

        lang: str = self.config.language

        # Build panels
        self.console.print()

        title: str = "📊 DRAKBEN Status" if lang == "en" else "📊 DRAKBEN Durumu"
        self.console.print(
            Panel(
                self._create_system_table(lang),
                title=f"[bold {self.COLORS['cyan']}]{title}[/]",
                border_style=self.COLORS["purple"],
                padding=(0, 1),
            )
        )

        if self.agent and self.agent.state:
            agent_title: str = "🤖 Agent State" if lang == "en" else "🤖 Ajan Durumu"
            self.console.print(
                Panel(
                    self._create_agent_table(),
                    title=f"[bold {self.COLORS['yellow']}]{agent_title}[/]",
                    border_style=self.COLORS["yellow"],
                    padding=(0, 1),
                )
            )

            # Show Plan Table
            if self.agent.planner and self.agent.planner.steps:
                plan_title = "📋 Mission Plan" if lang == "en" else "📋 Görev Planı"
                self.console.print(
                    Panel(
                        self._create_plan_table(),
                        title=f"[bold {self.COLORS['pink']}]{plan_title}[/]",
                        border_style=self.COLORS["pink"],
                        padding=(0, 1),
                    )
                )

        llm_title = "🧠 LLM"
        self.console.print(
            Panel(
                self._create_llm_content(),
                title=f"[bold {self.COLORS['green']}]{llm_title}[/]",
                border_style=self.COLORS["green"],
                padding=(0, 1),
            )
        )
        self.console.print()

    def _create_plan_table(self) -> "Table":
        """Create a table showing current plan steps"""
        from rich.table import Table

        from core.planner import StepStatus

        table = Table(box=None, padding=(0, 1))
        table.add_column("Step", style="dim")
        table.add_column("Action", style="bold")
        table.add_column("Tool", style="cyan")
        table.add_column("Status", style="bold")

        status_colors = {
            StepStatus.PENDING: "dim",
            StepStatus.EXECUTING: "bold yellow",
            StepStatus.SUCCESS: "bold green",
            StepStatus.FAILED: "bold red",
            StepStatus.SKIPPED: "dim yellow",
        }

        for i, step in enumerate(self.agent.planner.steps, 1):
            color = status_colors.get(step.status, "white")
            table.add_row(
                f"#{i}",
                step.action.replace("_", " ").title(),
                step.tool,
                f"[{color}]{step.status.value.upper()}[/]",
            )
        return table

    def _cmd_report(self, args: str = "") -> None:
        """Generate professional report"""
        from rich.panel import Panel

        from modules.report_generator import (
            ReportConfig,
            ReportFormat,
            generate_report_from_state,
        )

        lang = self.config.language

        if not self.agent or not self.agent.state:
            msg = (
                "Önce bir tarama başlatmalısın."
                if lang == "tr"
                else "You must start a scan first."
            )
            self.console.print(Panel(f"[red]❌ {msg}[/]", style="red"))
            return

        gen_msg = (
            "Profesyonel rapor oluşturuluyor..."
            if lang == "tr"
            else "Generating professional report..."
        )
        self.console.print(f"[bold {self.COLORS['purple']}]📝 {gen_msg}[/]")

        try:
            # Create reports directory
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = (
                (self.config.target or "unknown")
                .replace(".", "_")
                .replace("/", "_")
                .replace(":", "_")
            )
            output_path = (
                reports_dir / f"drakben_report_{target_clean}_{timestamp}.html"
            )

            # Use ReportGenerator
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

            success_msg = (
                f"Rapor başarıyla oluşturuldu: {final_path}"
                if lang == "tr"
                else f"Report generated successfully: {final_path}"
            )
            self.console.print(
                Panel(
                    f"[bold green]✅ {success_msg}[/]",
                    border_style="green",
                    padding=(1, 2),
                )
            )

        except Exception as e:
            err_msg = (
                f"Rapor oluşturma hatası: {e}"
                if lang == "tr"
                else f"Report generation error: {e}"
            )
            self.console.print(f"[bold red]❌ {err_msg}[/]")

    def _create_system_table(self, lang) -> "Table":
        from rich.table import Table

        sys_table = Table(show_header=False, box=None, padding=(0, 1))
        sys_table.add_column("Key", style=f"bold {self.COLORS['purple']}")
        sys_table.add_column("Value", style=self.COLORS["fg"])

        target: str = self.config.target or ("[dim]—[/dim]")
        lang_display: str = "🇹🇷 Türkçe" if lang == "tr" else "🇬🇧 English"
        os_info = self.system_info.get("os", "?")
        is_kali = self.system_info.get("is_kali", False)
        os_display: str | Any = f"{os_info} [green](Kali)[/]" if is_kali else os_info
        tools = self.system_info.get("available_tools", {})

        sys_table.add_row("🎯 Target", f"[bold white]{target}[/]")
        sys_table.add_row("🌐 Language", lang_display)
        sys_table.add_row("💻 OS", os_display)
        sys_table.add_row("🔧 Tools", f"[cyan]{len(tools)}[/] available")
        return sys_table

    def _create_agent_table(self) -> "Table":
        from rich.table import Table

        state: AgentState | None = self.agent.state
        phase_colors: Dict[str, str] = {
            "init": "dim",
            "recon": "yellow",
            "vulnerability_scan": "cyan",
            "exploit": "red",
            "foothold": "green",
            "post_exploit": "magenta",
            "complete": "bold green",
            "failed": "bold red",
        }
        phase_color: str = phase_colors.get(state.phase.value, "white")
        foothold_icon: str = "✅" if state.has_foothold else "❌"

        agent_table = Table(show_header=False, box=None, padding=(0, 1))
        agent_table.add_column("Key", style=f"bold {self.COLORS['purple']}")
        agent_table.add_column("Value", style=self.COLORS["fg"])

        agent_table.add_row("📍 Phase", f"[{phase_color}]{state.phase.value}[/]")
        agent_table.add_row("🔌 Services", f"[cyan]{len(state.open_services)}[/]")
        agent_table.add_row(
            "⚠️  Vulns",
            f"[{'red' if state.vulnerabilities else 'dim'}]{len(state.vulnerabilities)}[/]",
        )
        agent_table.add_row("🚩 Foothold", foothold_icon)
        return agent_table

    def _create_llm_content(self) -> str:
        llm_content = "[dim]Not initialized[/]"
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            provider = info.get("provider", "N/A")
            model = info.get("model", "N/A")
            llm_content: str = f"[green]●[/] {provider}\n[dim]{model}[/]"

            if info.get("cache_stats"):
                cache = info["cache_stats"]
                hit_rate = cache.get("hit_rate", 0) * 100
                llm_content += f"\n[dim]Cache: {hit_rate:.0f}%[/]"
        return llm_content

    def _cmd_llm_setup(self, args: str = "") -> None:
        """Interactive LLM/API setup wizard"""

        lang: str = self.config.language

        providers: Dict[str, tuple[str, str]] = {
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

    def _display_llm_setup_status(self, lang) -> None:
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
            )
        )

    def _select_provider_for_setup(self, lang, providers):
        from rich.table import Table

        # Provider selection
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("No", style=f"bold {self.COLORS['yellow']}")
        table.add_column("Provider", style=self.COLORS["fg"])

        for key, (_, desc) in providers.items():
            table.add_row(f"[{key}]", desc)

        self.console.print()
        self.console.print(table)

        # Get provider choice
        prompt_text: str = (
            "Provider seç (1-3) veya [q] çıkış"
            if lang == "tr"
            else "Select provider (1-3) or [q] to quit"
        )
        self.console.print(f"\n{prompt_text}: ", end="")
        choice: str = input().strip().lower()

        if choice == "q" or choice not in providers:
            return None

        return providers[choice][0]

    def _get_models_dict(self, lang) -> Dict[str, list[tuple[str, str]]]:
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
        self, lang, provider_key
    ) -> tuple[None, None] | tuple[str, str]:
        from rich.table import Table

        models: Dict[str, list[tuple[str, str]]] = self._get_models_dict(lang)

        # Model selection
        self.console.print()
        model_table = Table(show_header=False, box=None, padding=(0, 2))
        model_table.add_column("No", style=f"bold {self.COLORS['yellow']}")
        model_table.add_column("Model", style=self.COLORS["fg"])

        provider_models: list[tuple[str, str]] = models[provider_key]
        for i, (_, desc) in enumerate(provider_models, 1):
            model_table.add_row(f"[{i}]", desc)

        self.console.print(model_table)

        prompt_text: str = (
            f"Model seç (1-{len(provider_models)})"
            if lang == "tr"
            else f"Select model (1-{len(provider_models)})"
        )
        self.console.print(f"\n{prompt_text}: ", end="")
        model_choice: str = input().strip()

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

    def _save_llm_config(self, provider_key, selected_model, api_key):
        from pathlib import Path

        from rich.panel import Panel

        env_file = Path("config/api.env")

        # Configuration templates
        templates: Dict[str, str] = {
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
                )
            )

            # Test connection
            test_msg: str = (
                "Bağlantı test ediliyor..." if lang == "tr" else "Testing connection..."
            )
            self.console.print(f"\n[dim]{test_msg}[/dim]")

            from core.brain import DrakbenBrain

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
                        f"[red]{err_msg} {test_result.get('error', 'Unknown')}[/red]\n"
                    )

        except Exception as e:
            self.console.print(f"\n[red]❌ Save error: {e}[/]")

    def _cmd_config(self, args: str) -> None:
        """System Configuration Menu"""
        from rich.prompt import Confirm, IntPrompt
        from rich.panel import Panel

        self.console.print(Panel("[bold cyan]🔧 SYSTEM CONFIGURATION[/bold cyan]", border_style="cyan"))
        
        # 1. Stealth Mode (Dynamic Attribute)
        current_stealth = getattr(self.config, "stealth_mode", False)
        # 2. Max Threads
        current_threads = getattr(self.config, "max_threads", 4)
        # 3. Timeout
        current_timeout = getattr(self.config, "timeout", 30)

        new_stealth = Confirm.ask("Enable Stealth Mode (Slower but safer)", default=current_stealth)
        new_threads = IntPrompt.ask("Max Threads (Parallel Actions)", default=current_threads)
        new_timeout = IntPrompt.ask("Network Timeout (seconds)", default=current_timeout)
        
        # Update Config Object
        self.config.stealth_mode = new_stealth
        self.config.max_threads = new_threads
        self.config.timeout = new_timeout

        # Visual Feedback
        self.console.print()
        status_msg = (
            f"[green]✅ Configuration Updated![/green]\n"
            f"   Stealth Mode: {'[bold green]ON[/]' if new_stealth else '[bold red]OFF[/]'}\n"
            f"   Threads: {new_threads}\n"
            f"   Timeout: {new_timeout}s"
        )
        self.console.print(Panel(status_msg, border_style="green", padding=(0,1)))
        
        # Note: We are not persisting to file yet, just runtime update.
        # To persist, we'd need to update ConfigManager to support arbitrary keys or add them to model.
        
        self.show_status_line()

    def _cmd_exit(self, args: str = "") -> None:
        """Çıkış"""
        self.running = False

    def _clear_screen(self) -> None:
        """Ekranı temizle"""
        os.system("clear" if os.name != "nt" else "cls")


def run_menu() -> None:
    """Menüyü başlat"""
    config_manager = ConfigManager()
    menu = DrakbenMenu(config_manager)
    menu.run()


if __name__ == "__main__":
    run_menu()
