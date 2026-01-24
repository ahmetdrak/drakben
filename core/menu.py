# core/menu.py
# DRAKBEN - Minimal Interactive Menu System
# Optimized for Kali Linux - Fixed Menu

import os

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

from core.config import ConfigManager
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
    COLORS = {
        "red": "#FF5555",
        "green": "#50FA7B",
        "yellow": "#F1FA8C",
        "purple": "#8BE9FD",  # Cyan (Hacker Blue) - Replaced Purple
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

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.config
        self.console = Console(color_system="truecolor")
        self.kali = KaliDetector()
        self.agent = None
        self.brain = None
        self.running = True
        self.system_info = {}

        # Menu commands
        self._commands = {
            "/help": self._cmd_help,
            "/target": self._cmd_target,
            "/scan": self._cmd_scan,
            "/shell": self._cmd_shell,
            "/status": self._cmd_status,
            "/clear": self._cmd_clear,
            "/tr": self._cmd_turkish,
            "/en": self._cmd_english,
            "/exit": self._cmd_exit,
        }

        # System detection
        self._detect_system()

    def _detect_system(self):
        """Detect system and save info"""
        import platform

        self.system_info = {
            "os": platform.system(),
            "os_version": platform.release(),
            "is_kali": self.kali.is_kali(),
            "python_version": platform.python_version(),
            "available_tools": self.kali.get_available_tools(),
        }

    def show_banner(self):
        """Show banner - Stylized (Diagonal Split)"""
        # Diagonal Coloring: Top-Left (Red) -> Bottom-Right (Dark Gray)
        # Custom render for effective appearance

        if not self.BANNER.strip():
            return

        lines = self.BANNER.strip("\n").split("\n")
        text = Text()

        color_primary = self.COLORS["red"]
        color_dark = "#6272a4"  # Dracula Comment (Dark elegant gray)

        max_width = max(len(line) for line in lines) if lines else 1
        total_lines = len(lines)

        for y, line in enumerate(lines):
            for x, char in enumerate(line):
                # Normalize coordinates (0.0 - 1.0)
                nx = x / max_width
                ny = y / total_lines

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
            "    [*] Kali Linux | AI-Powered | Auto-Exploit", style=self.COLORS["fg"]
        )
        self.console.print()

    def show_status_line(self):
        """Minimal status line"""
        lang = self.config.language
        target = self.config.target or ("Yok" if lang == "tr" else "None")
        lang_text = "TR" if lang == "tr" else "EN"
        kali_status = (
            "Kali"
            if self.system_info.get("is_kali")
            else self.system_info.get("os", "?")
        )
        tools_count = len(self.system_info.get("available_tools", {}))

        self.console.print(
            f"  [>] Target: {target}  |  Lang: {lang_text}  |  OS: {kali_status}  |  Tools: {tools_count}",
            style=f"bold {self.COLORS['cyan']}",
        )
        self.console.print(
            "  /help /target /scan /shell /status /clear /tr /en /exit",
            style=f"bold {self.COLORS['cyan']}",
        )
        self.console.print()

    def run(self):
        """Main loop"""
        # Initial start - show banner and status
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

        # Welcome message
        lang = self.config.language
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

        # MAIN LOOP
        while self.running:
            try:
                # Get user input with protected prompt
                user_input = self._get_input().strip()

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
        msg = "Görüşürüz!" if lang == "tr" else "Goodbye!"
        self.console.print(f"👋 {msg}", style=self.COLORS["purple"])

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
                    f'<style fg="#8BE9FD" bg="" bold="true">drakben</style>'
                    f'<style fg="#F8F8F2">&gt; </style>'
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
                prompt.append(f"@{self.config.target}", style=f"bold {self.COLORS['cyan']}")
            prompt.append("> ", style=self.COLORS["fg"])
            self.console.print(prompt, end="")
            return input()

    def _handle_command(self, user_input: str):
        """Handle slash commands"""
        parts = user_input.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd in self._commands:
            self._commands[cmd](args)
        else:
            lang = self.config.language
            msg = (
                "Bilinmeyen komut. /help yazın."
                if lang == "tr"
                else "Unknown command. Type /help."
            )
            self.console.print(f"❌ {msg}", style="red")

    def _process_with_ai(self, user_input: str):
        """Process with AI"""
        lang = self.config.language

        # Lazy load brain
        if not self.brain:
            from core.brain import DrakbenBrain

            self.brain = DrakbenBrain()

        thinking = "Düşünüyor..." if lang == "tr" else "Thinking..."

        with self.console.status(f"[bold {self.COLORS['purple']}]🧠 {thinking}"):
            result = self.brain.think(user_input, self.config.target)

        # Show response - check multiple fields
        response_text = (
            result.get("llm_response") or 
            result.get("reply") or 
            result.get("response") or
            result.get("reasoning")
        )
        
        if response_text:
            self.console.print(
                f"\n🤖 {response_text}\n", style=self.COLORS["cyan"]
            )
        else:
            # No response - show error or offline message
            if result.get("error"):
                self.console.print(
                    f"\n❌ Hata: {result['error']}\n", style="red"
                )
            else:
                offline_msg = (
                    "LLM bağlantısı yok. Lütfen API ayarlarını kontrol edin."
                    if lang == "tr" else
                    "No LLM connection. Please check API settings."
                )
                self.console.print(f"\n⚠️ {offline_msg}\n", style="yellow")

        # Command suggestion
        if result.get("command"):
            self.console.print(f"📝 Komut: [bold yellow]{result['command']}[/]")

            if result.get("needs_approval"):
                q = "Çalıştır? (e/h)" if lang == "tr" else "Run? (y/n)"
                resp = Prompt.ask(q, choices=["e", "h", "y", "n"], default="h")
                if resp.lower() in ["e", "y"]:
                    self._execute_command(result["command"])

    def _execute_command(self, command: str):
        """Execute command"""
        lang = self.config.language

        # Agent lazy load
        if not self.agent:
            from core.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)
            self.agent.initialize(target=self.config.target or "")

        msg = "Çalıştırılıyor..." if lang == "tr" else "Executing..."
        self.console.print(f"⚡ {msg}", style=self.COLORS["yellow"])

        result = self.agent.executor.terminal.execute(command, timeout=300)

        if result.status.value == "success":
            self.console.print(
                f"✅ OK ({result.duration:.1f}s)", style=self.COLORS["green"]
            )
            if result.stdout:
                # First 500 chars
                self.console.print(result.stdout[:500], style="dim")
        else:
            self.console.print(f"❌ Hata: {result.stderr[:150]}", style="red")

    # ========== COMMANDS ==========

    def _cmd_help(self, args: str = ""):
        """Help command - Modern Dracula themed"""
        from rich.table import Table
        from rich.panel import Panel
        
        lang = self.config.language
        
        # Commands table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Cmd", style=f"bold {self.COLORS['purple']}")
        table.add_column("Desc", style=self.COLORS["fg"])
        
        if lang == "tr":
            commands = [
                ("❓ /help", "Yardım menüsü"),
                ("🎯 /target <IP>", "Hedef belirle"),
                ("🔍 /scan", "Otonom tarama başlat"),
                ("💻 /shell", "İnteraktif kabuk"),
                ("📊 /status", "Durum bilgisi"),
                ("🧹 /clear", "Ekranı temizle"),
                ("🇹🇷 /tr", "Türkçe mod"),
                ("🇬🇧 /en", "English mode"),
                ("🚪 /exit", "Çıkış"),
            ]
            title = "DRAKBEN Komutları"
            tip_title = "💡 İpucu"
            tip_text = "Doğal dilde konuşabilirsin:\n[dim]• \"10.0.0.1 portlarını tara\"\n• \"sql injection test et\"[/dim]"
        else:
            commands = [
                ("❓ /help", "Help menu"),
                ("🎯 /target <IP>", "Set target"),
                ("🔍 /scan", "Start autonomous scan"),
                ("💻 /shell", "Interactive shell"),
                ("📊 /status", "Status info"),
                ("🧹 /clear", "Clear screen"),
                ("🇹🇷 /tr", "Turkish mode"),
                ("🇬🇧 /en", "English mode"),
                ("🚪 /exit", "Exit"),
            ]
            title = "DRAKBEN Commands"
            tip_title = "💡 Tip"
            tip_text = "Talk naturally:\n[dim]• \"scan ports on 10.0.0.1\"\n• \"test sql injection\"[/dim]"
        
        for cmd, desc in commands:
            table.add_row(cmd, desc)
        
        # Main panel
        self.console.print()
        self.console.print(Panel(
            table,
            title=f"[bold {self.COLORS['red']}]{title}[/]",
            border_style=self.COLORS["purple"],
            padding=(1, 2)
        ))
        
        # Tip panel
        self.console.print(Panel(
            tip_text,
            title=f"[bold {self.COLORS['yellow']}]{tip_title}[/]",
            border_style=self.COLORS["green"],
            padding=(0, 2)
        ))
        self.console.print()

    def _cmd_target(self, args: str = ""):
        """Set target - with visual feedback"""
        from rich.panel import Panel
        
        lang = self.config.language

        if not args:
            msg = "Kullanım: /target <IP>" if lang == "tr" else "Usage: /target <IP>"
            self.console.print(Panel(
                f"[bold red]{msg}[/]",
                title="[red]❌ Hata[/]" if lang == "tr" else "[red]❌ Error[/]",
                border_style="red",
                padding=(0, 1)
            ))
            return

        self.config_manager.set_target(args.strip())
        self.config = self.config_manager.config

        if lang == "tr":
            content = f"[bold {self.COLORS['green']}]🎯 Hedef ayarlandı:[/] [bold white]{args}[/]"
        else:
            content = f"[bold {self.COLORS['green']}]🎯 Target set:[/] [bold white]{args}[/]"
        
        self.console.print(Panel(
            content,
            border_style=self.COLORS["green"],
            padding=(0, 1)
        ))

    def _cmd_scan(self, args: str = ""):
        """Scan target - with visual feedback"""
        from rich.panel import Panel
        
        lang = self.config.language

        if not self.config.target:
            if lang == "tr":
                msg = "Önce hedef belirle: [bold]/target <IP>[/]"
                title = "❌ Hedef Yok"
            else:
                msg = "Set target first: [bold]/target <IP>[/]"
                title = "❌ No Target"
            
            self.console.print(Panel(
                f"[red]{msg}[/]",
                title=f"[red]{title}[/]",
                border_style="red",
                padding=(0, 1)
            ))
            return

        if lang == "tr":
            content = f"[bold]🔍 Otonom tarama başlatılıyor...[/]\n[dim]Hedef: {self.config.target}[/]"
            title = "DRAKBEN Scanner"
        else:
            content = f"[bold]🔍 Starting autonomous scan...[/]\n[dim]Target: {self.config.target}[/]"
            title = "DRAKBEN Scanner"
        
        self.console.print(Panel(
            content,
            title=f"[bold {self.COLORS['cyan']}]{title}[/]",
            border_style=self.COLORS["cyan"],
            padding=(0, 1)
        ))

        # Start agent
        if not self.agent:
            from core.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)
            self.agent.initialize(target=self.config.target)

        self.agent.run_autonomous_loop()

    def _cmd_clear(self, args: str = ""):
        """Clear screen - banner and menu remain"""
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _cmd_turkish(self, args: str = ""):
        """Switch to Turkish"""
        from rich.panel import Panel
        self.config_manager.set_language("tr")
        self.config = self.config_manager.config
        self.console.print(Panel(
            "[bold]🇹🇷 Dil Türkçe olarak ayarlandı[/]",
            border_style=self.COLORS["green"],
            padding=(0, 1)
        ))

    def _cmd_english(self, args: str = ""):
        """Switch to English"""
        from rich.panel import Panel
        self.config_manager.set_language("en")
        self.config = self.config_manager.config
        self.console.print(Panel(
            "[bold]🇬🇧 Language set to English[/]",
            border_style=self.COLORS["green"],
            padding=(0, 1)
        ))

    def _cmd_shell(self, args: str = ""):
        """Launch interactive shell"""
        from rich.panel import Panel
        lang = self.config.language
        
        if lang == "tr":
            msg = "[bold]💻 İnteraktif kabuk başlatılıyor...[/]\n[dim]Çıkmak için 'exit' yazın[/]"
        else:
            msg = "[bold]💻 Starting interactive shell...[/]\n[dim]Type 'exit' to quit[/]"
        
        self.console.print(Panel(
            msg,
            title=f"[bold {self.COLORS['cyan']}]DRAKBEN Shell[/]",
            border_style=self.COLORS["cyan"],
            padding=(0, 1)
        ))
        
        from core.interactive_shell import InteractiveShell
        
        shell = InteractiveShell(
            config_manager=self.config_manager,
            agent=self.agent
        )
        shell.current_target = self.config.target
        shell.start()
        
        # Restore menu after shell exits
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _cmd_status(self, args: str = ""):
        """Show current status - Modern dashboard style"""
        from rich.table import Table
        from rich.panel import Panel
        from rich.columns import Columns
        
        lang = self.config.language
        
        # System table
        sys_table = Table(show_header=False, box=None, padding=(0, 1))
        sys_table.add_column("Key", style=f"bold {self.COLORS['purple']}")
        sys_table.add_column("Value", style=self.COLORS["fg"])
        
        target = self.config.target or ("[dim]—[/dim]")
        lang_display = "🇹🇷 Türkçe" if lang == "tr" else "🇬🇧 English"
        os_info = self.system_info.get("os", "?")
        is_kali = self.system_info.get("is_kali", False)
        os_display = f"{os_info} [green](Kali)[/]" if is_kali else os_info
        tools = self.system_info.get("available_tools", {})
        
        sys_table.add_row("🎯 Target", f"[bold white]{target}[/]")
        sys_table.add_row("🌐 Language", lang_display)
        sys_table.add_row("💻 OS", os_display)
        sys_table.add_row("🔧 Tools", f"[cyan]{len(tools)}[/] available")
        
        # Agent state table (if active)
        agent_content = ""
        if self.agent and self.agent.state:
            state = self.agent.state
            phase_colors = {
                "init": "dim", "recon": "yellow", "vulnerability_scan": "cyan",
                "exploit": "red", "foothold": "green", "post_exploit": "magenta",
                "complete": "bold green", "failed": "bold red"
            }
            phase_color = phase_colors.get(state.phase.value, "white")
            foothold_icon = "✅" if state.has_foothold else "❌"
            
            agent_table = Table(show_header=False, box=None, padding=(0, 1))
            agent_table.add_column("Key", style=f"bold {self.COLORS['purple']}")
            agent_table.add_column("Value", style=self.COLORS["fg"])
            
            agent_table.add_row("📍 Phase", f"[{phase_color}]{state.phase.value}[/]")
            agent_table.add_row("🔌 Services", f"[cyan]{len(state.open_services)}[/]")
            agent_table.add_row("⚠️  Vulns", f"[{'red' if state.vulnerabilities else 'dim'}]{len(state.vulnerabilities)}[/]")
            agent_table.add_row("🚩 Foothold", foothold_icon)
            
            agent_content = agent_table
        
        # LLM status
        llm_content = "[dim]Not initialized[/]"
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            provider = info.get('provider', 'N/A')
            model = info.get('model', 'N/A')
            llm_content = f"[green]●[/] {provider}\n[dim]{model}[/]"
            
            if info.get("cache_stats"):
                cache = info["cache_stats"]
                hit_rate = cache.get("hit_rate", 0) * 100
                llm_content += f"\n[dim]Cache: {hit_rate:.0f}%[/]"
        
        # Build panels
        self.console.print()
        
        title = "📊 DRAKBEN Status" if lang == "en" else "📊 DRAKBEN Durumu"
        self.console.print(Panel(
            sys_table,
            title=f"[bold {self.COLORS['cyan']}]{title}[/]",
            border_style=self.COLORS["purple"],
            padding=(0, 1)
        ))
        
        if agent_content:
            agent_title = "🤖 Agent State" if lang == "en" else "🤖 Ajan Durumu"
            self.console.print(Panel(
                agent_content,
                title=f"[bold {self.COLORS['yellow']}]{agent_title}[/]",
                border_style=self.COLORS["yellow"],
                padding=(0, 1)
            ))
        
        llm_title = "🧠 LLM" 
        self.console.print(Panel(
            llm_content,
            title=f"[bold {self.COLORS['green']}]{llm_title}[/]",
            border_style=self.COLORS["green"],
            padding=(0, 1)
        ))
        self.console.print()

    def _cmd_exit(self, args: str = ""):
        """Çıkış"""
        self.running = False

    def _clear_screen(self):
        """Ekranı temizle"""
        os.system("clear" if os.name != "nt" else "cls")


def run_menu():
    """Menüyü başlat"""
    config_manager = ConfigManager()
    menu = DrakbenMenu(config_manager)
    menu.run()


if __name__ == "__main__":
    run_menu()
