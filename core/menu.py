# core/menu.py
# DRAKBEN - Minimal Interactive Menu System
# Optimized for Kali Linux - Fixed Menu

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
import os
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from core.refactored_agent import RefactoredDrakbenAgent
    from core.brain import DrakbenBrain

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

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.config
        self.console = Console(color_system="truecolor")
        self.kali = KaliDetector()
        self.agent: Optional['RefactoredDrakbenAgent'] = None
        self.brain: Optional['DrakbenBrain'] = None
        self.running = True
        self.system_info: Dict[str, Any] = {}

        # Menu commands
        self._commands = {
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
            "  /help /target /scan /shell /status /llm /clear /tr /en /exit",
            style=f"bold {self.COLORS['cyan']}",
        )
        self.console.print()

    def run(self):
        """Main loop"""
        # Initial start - show banner and status
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

        lang = self.config.language
        self._show_welcome_message(lang)

        # PLUGINS: Register external tools
        self._load_plugins_at_startup(lang)

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

    def _show_welcome_message(self, lang):
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

    def _load_plugins_at_startup(self, lang):
        """Helper to safely load plugins without polluting run() method"""
        try:
            from core.plugin_loader import PluginLoader
            
            loader = PluginLoader()
            plugins = loader.load_plugins()
            
            if plugins:
                msg = f"🔌 {len(plugins)} Plugin Yüklendi" if lang == "tr" else f"🔌 {len(plugins)} Plugins Loaded"
                self.console.print(f"[dim green]{msg}[/dim]")
                
                # Dynamic ToolSelector update (Monkey Patching)
                from core.tool_selector import ToolSelector
                
                original_init = ToolSelector.__init__
                
                def patched_init(ts_self, *args, **kwargs):
                    original_init(ts_self, *args, **kwargs)
                    ts_self.register_plugin_tools(plugins)
                    
                ToolSelector.__init__ = patched_init
                
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
                prompt.append(f"@{self.config.target}", style=f"bold {self.COLORS['cyan']}")
            prompt.append("> ", style=self.COLORS["fg"])
            self.console.print(prompt, end="")
            return input()

    def _handle_command(self, user_input: str):
        """Handle slash commands"""
        if not user_input or not user_input.strip():
            return

        parts = user_input.split(maxsplit=1)
        if not parts:
            return

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
            assert self.brain is not None
            result = self.brain.think(user_input, self.config.target)

        self._handle_ai_response_text(result, lang)
        self._handle_ai_command(result, lang)

    def _handle_ai_response_text(self, result, lang):
        """Handle displaying the AI response text"""
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

    def _handle_ai_command(self, result, lang):
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
            q = "Çalıştır? (e/h)" if lang == "tr" else "Run? (y/n)"
            # ... prompt code ...
            # For now just default to asking 
            resp = Prompt.ask(q, choices=["e", "h", "y", "n"], default="e")
            if resp.lower() in ["e", "y"]:
                self._execute_command(command)
        else:
            self._execute_command(command)

    def _execute_command(self, command: str):
        """Execute command"""
        lang = self.config.language

        # FIX: Check if this is an internal slash command recommended by AI
        if command.strip().startswith("/"):
            self.console.print(f"🔄 Dahili komut çalıştırılıyor: {command}", style="dim")
            self._handle_command(command)
            return

        # Agent lazy load
        if not self.agent:
            from core.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)
            assert self.agent is not None
            self.agent.initialize(target=self.config.target or "")

        msg = "Çalıştırılıyor..." if lang == "tr" else "Executing..."
        self.console.print(f"⚡ {msg}", style=self.COLORS["yellow"])

        assert self.agent is not None
        assert self.agent.executor is not None
        result = self.agent.executor.terminal.execute(command, timeout=300)

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
            output_content = result.stdout if result.stdout else result.stderr
            tool_name = command.split()[0]
            self.brain.observe(
                tool=tool_name,
                output=output_content,
                success=(result.status.value == "success")
            )

    # ========== COMMANDS ==========

    def _cmd_research(self, args):
        """Web research command"""
        if not args:
            self.console.print("Usage: /research <query>")
            return

        if isinstance(args, list):
            query = " ".join(args)
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

            self.console.print(f"\n[bold green]Found {len(results)} results:[/bold green]\n")
            for i, r in enumerate(results, 1):
                self.console.print(f"{i}. [bold]{r['title']}[/bold]")
                self.console.print(f"   [blue underline]{r['href']}[/blue underline]")
                body = r.get('body', '')[:200] + "..." if r.get('body') else "No description."
                self.console.print(f"   [dim]{body}[/dim]\n")
                
        except Exception as e:
            self.console.print(f"[red]Error during research: {e}[/red]")

    def _cmd_help(self, args: str = ""):
        """Help command - Modern Dracula themed"""
        from rich.table import Table
        from rich.panel import Panel
        
        lang = self.config.language
        
        # Commands table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Cmd", style=f"bold {self.COLORS['red']}")  # Komutlar kırmızı
        table.add_column("Desc", style=self.COLORS["fg"])
        
        if lang == "tr":
            commands = [
                ("❓ /help", "Yardım menüsü"),
                ("🎯 /target <IP>", "Hedef belirle"),
                ("🔍 /scan", "Otonom tarama başlat"),
                ("💻 /shell", "İnteraktif kabuk"),
                ("📊 /status", "Durum bilgisi"),
                ("🤖 /llm", "LLM/API ayarları"),
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
                ("🤖 /llm", "LLM/API settings"),
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
        """Set or clear target - with visual feedback"""
        from rich.panel import Panel
        
        lang = self.config.language
        args = args.strip()

        # Check for clear command
        if args.lower() in ["clear", "off", "none", "delete", "sil", "iptal", "remove"]:
            self.config_manager.set_target(None)
            self.config = self.config_manager.config
            
            if lang == "tr":
                msg = "[bold green]✅ Hedef temizlendi[/]"
            else:
                msg = "[bold green]✅ Target cleared[/]"
            
            self.console.print(Panel(
                msg,
                border_style="green",
                padding=(0, 1)
            ))
            return

        if not args:
            if lang == "tr":
                msg = "Kullanım: /target <IP>\nTemizlemek için: /target sil"
            else:
                msg = "Usage: /target <IP>\nTo clear: /target clear"
                
            self.console.print(Panel(
                f"[bold red]{msg}[/]",
                title="[red]❌ Hata[/]" if lang == "tr" else "[red]❌ Error[/]",
                border_style="red",
                padding=(0, 1)
            ))
            return

        self.config_manager.set_target(args)
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
        """
        Scan target - with visual feedback
        
        Usage:
            /scan              - Auto mode (agent decides)
            /scan stealth      - Stealth/silent mode (slow, careful)
            /scan aggressive   - Aggressive mode (fast, noisy)
            /scan sessiz       - Stealth mode (Turkish alias)
            /scan hizli        - Aggressive mode (Turkish alias)
        """
        scan_mode = self._parse_scan_mode(args)
        
        if not self._check_target_set():
            return
        
        self._display_scan_panel(scan_mode)
        self._start_scan_with_recovery(scan_mode)
    
    def _parse_scan_mode(self, args: str) -> str:
        """Parse scan mode from arguments"""
        args_lower = args.strip().lower()
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
        
        lang = self.config.language
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
        return False
    
    def _display_scan_panel(self, scan_mode: str) -> None:
        """Display scan initialization panel"""
        from rich.panel import Panel
        
        lang = self.config.language
        mode_info = {
            "stealth": ("🥷 STEALTH", "Sessiz mod - Yavaş ama gizli" if lang == "tr" else "Silent mode - Slow but stealthy"),
            "aggressive": ("⚡ AGGRESSIVE", "Hızlı mod - Agresif tarama" if lang == "tr" else "Fast mode - Aggressive scan"),
            "auto": ("🤖 AUTO", "Otomatik mod" if lang == "tr" else "Auto mode")
        }
        mode_label, mode_desc = mode_info.get(scan_mode, mode_info["auto"])

        if lang == "tr":
            content = f"[bold]🔍 Otonom tarama başlatılıyor...[/]\n[dim]Hedef: {self.config.target}[/]\n[dim]Mod: {mode_label} - {mode_desc}[/]"
            title = "DRAKBEN Scanner"
        else:
            content = f"[bold]🔍 Starting autonomous scan...[/]\n[dim]Target: {self.config.target}[/]\n[dim]Mode: {mode_label} - {mode_desc}[/]"
            title = "DRAKBEN Scanner"
        
        self.console.print(Panel(
            content,
            title=f"[bold {self.COLORS['cyan']}]{title}[/]",
            border_style=self.COLORS["cyan"],
            padding=(0, 1)
        ))
    
    def _start_scan_with_recovery(self, scan_mode: str) -> None:
        """Start scan with error recovery"""
        lang = self.config.language
        
        try:
            self._ensure_agent_initialized()
            self._initialize_agent_with_retry(scan_mode, lang)
            assert self.agent is not None
            self.agent.run_autonomous_loop()
        except KeyboardInterrupt:
            interrupt_msg = "Tarama kullanıcı tarafından durduruldu." if lang == "tr" else "Scan stopped by user."
            self.console.print(f"\n⚠️ {interrupt_msg}", style="yellow")
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.exception(f"Scan error: {e}")
            error_msg = f"Tarama sırasında hata: {e}" if lang == "tr" else f"Scan error: {e}"
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
            self.agent.initialize(target=self.config.target, mode=scan_mode)
        except Exception as init_error:
            error_msg = (
                f"Agent başlatma hatası: {init_error}" if lang == "tr" 
                else f"Agent initialization error: {init_error}"
            )
            self.console.print(Panel(
                f"[red]{error_msg}[/]\n[dim]Yeniden deneniyor... / Retrying...[/]",
                title="[red]⚠️ Hata / Error[/]",
                border_style="yellow",
                padding=(0, 1)
            ))
            # Retry with fresh agent
            from core.refactored_agent import RefactoredDrakbenAgent
            self.agent = RefactoredDrakbenAgent(self.config_manager)
            self.agent.initialize(target=self.config.target, mode=scan_mode)

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
        
        # Build panels
        self.console.print()
        
        title = "📊 DRAKBEN Status" if lang == "en" else "📊 DRAKBEN Durumu"
        self.console.print(Panel(
            self._create_system_table(lang),
            title=f"[bold {self.COLORS['cyan']}]{title}[/]",
            border_style=self.COLORS["purple"],
            padding=(0, 1)
        ))
        
        if self.agent and self.agent.state:
            agent_title = "🤖 Agent State" if lang == "en" else "🤖 Ajan Durumu"
            self.console.print(Panel(
                self._create_agent_table(),
                title=f"[bold {self.COLORS['yellow']}]{agent_title}[/]",
                border_style=self.COLORS["yellow"],
                padding=(0, 1)
            ))
        
        llm_title = "🧠 LLM" 
        self.console.print(Panel(
            self._create_llm_content(),
            title=f"[bold {self.COLORS['green']}]{llm_title}[/]",
            border_style=self.COLORS["green"],
            padding=(0, 1)
        ))
        self.console.print()

    def _create_system_table(self, lang):
        from rich.table import Table
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
        return sys_table

    def _create_agent_table(self):
        from rich.table import Table
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
        return agent_table

    def _create_llm_content(self):
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
        return llm_content

    def _cmd_llm_setup(self, args: str = ""):
        """Interactive LLM/API setup wizard"""
        from rich.panel import Panel
        from rich.table import Table
        from pathlib import Path
        
        lang = self.config.language
        
        providers = {
            "1": ("openrouter", "OpenRouter (Ücretsiz modeller var)" if lang == "tr" else "OpenRouter (Free models available)"),
            "2": ("openai", "OpenAI (GPT-4, GPT-4o)"),
            "3": ("ollama", "Ollama (Yerel, Ücretsiz)" if lang == "tr" else "Ollama (Local, Free)"),
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

    def _display_llm_setup_status(self, lang):
        from rich.panel import Panel
        # Show current status
        title = "🤖 LLM Kurulumu" if lang == "tr" else "🤖 LLM Setup"
        self.console.print()
        
        # Show current config
        current_info = "[dim]Mevcut ayar yok[/dim]" if lang == "tr" else "[dim]No current config[/dim]"
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            current_info = f"[green]●[/green] {info.get('provider', 'N/A')} / {info.get('model', 'N/A')}"
        
        self.console.print(Panel(
            f"{'Mevcut' if lang == 'tr' else 'Current'}: {current_info}",
            title=f"[bold {self.COLORS['cyan']}]{title}[/]",
            border_style=self.COLORS["purple"],
            padding=(0, 1)
        ))

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
        prompt_text = "Provider seç (1-3) veya [q] çıkış" if lang == "tr" else "Select provider (1-3) or [q] to quit"
        self.console.print(f"\n{prompt_text}: ", end="")
        choice = input().strip().lower()
        
        if choice == "q" or choice not in providers:
            return None
            
        return providers[choice][0]

    def _get_models_dict(self, lang):
        return {
            "openrouter": [
                ("deepseek/deepseek-chat", "DeepSeek Chat (Ücretsiz)" if lang == "tr" else "DeepSeek Chat (Free)"),
                ("meta-llama/llama-3.1-8b-instruct:free", "Llama 3.1 8B (Ücretsiz)" if lang == "tr" else "Llama 3.1 8B (Free)"),
                ("google/gemma-2-9b-it:free", "Gemma 2 9B (Ücretsiz)" if lang == "tr" else "Gemma 2 9B (Free)"),
                ("anthropic/claude-3.5-sonnet", "Claude 3.5 Sonnet"),
                ("openai/gpt-4o", "GPT-4o"),
            ],
            "openai": [
                ("gpt-4o-mini", "GPT-4o Mini (Ucuz)" if lang == "tr" else "GPT-4o Mini (Cheap)"),
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

    def _select_model_and_key(self, lang, provider_key):
        from rich.table import Table
        
        models = self._get_models_dict(lang)
        
        # Model selection
        self.console.print()
        model_table = Table(show_header=False, box=None, padding=(0, 2))
        model_table.add_column("No", style=f"bold {self.COLORS['yellow']}")
        model_table.add_column("Model", style=self.COLORS["fg"])
        
        provider_models = models[provider_key]
        for i, (_, desc) in enumerate(provider_models, 1):
            model_table.add_row(f"[{i}]", desc)
        
        self.console.print(model_table)
        
        prompt_text = f"Model seç (1-{len(provider_models)})" if lang == "tr" else f"Select model (1-{len(provider_models)})"
        self.console.print(f"\n{prompt_text}: ", end="")
        model_choice = input().strip()
        
        selected_model = None
        try:
            model_idx = int(model_choice) - 1
            if 0 <= model_idx < len(provider_models):
                selected_model, _ = provider_models[model_idx]
            else:
                return None, None
        except ValueError:
            return None, None
            
        # API Key input (not needed for Ollama)
        api_key = ""
        if provider_key != "ollama":
            prompt_text = "API Key gir" if lang == "tr" else "Enter API Key"
            self.console.print(f"\n{prompt_text}: ", end="")
            api_key = input().strip()
            
            if not api_key:
                msg = "API key gerekli!" if lang == "tr" else "API key required!"
                self.console.print(f"[red]❌ {msg}[/red]")
                return None, None
        
        return selected_model, api_key

    def _save_llm_config(self, provider_key, selected_model, api_key):
        from pathlib import Path
        from rich.panel import Panel
        env_file = Path("config/api.env")
        
        # Configuration templates
        templates = {
            "openrouter": f"OPENROUTER_API_KEY={api_key}\nOPENROUTER_MODEL={selected_model}",
            "openai": f"OPENAI_API_KEY={api_key}\nOPENAI_MODEL={selected_model}",
            "ollama": f"LOCAL_LLM_URL=http://localhost:11434\nLOCAL_LLM_MODEL={selected_model}"
        }

        config_body = templates.get(provider_key)
        if not config_body:
             self.console.print(f"[red]❌ Unknown provider: {provider_key}[/red]")
             return

        env_content = f"# DRAKBEN LLM Configuration\n# Auto-generated by /llm command\n\n{config_body}\n"
        
        try:
            env_file.parent.mkdir(parents=True, exist_ok=True)
            with open(env_file, "w") as f:
                f.write(env_content)
            
            # Reload environment
            from dotenv import load_dotenv
            load_dotenv(env_file, override=True)
            
            # Update config manager
            self.config_manager.load_config()
            self.config = self.config_manager.config
            
            # Reset brain to pick up new config
            self.brain = None
            
            # Success message
            lang = self.config.language
            msg = f"✅ LLM ayarlandı: {provider_key} / {selected_model}" if lang == "tr" else f"✅ LLM configured: {provider_key} / {selected_model}"
            self.console.print(Panel(
                f"[bold green]{msg}[/bold green]",
                border_style="green",
                padding=(0, 1)
            ))
            
            # Test connection
            test_msg = "Bağlantı test ediliyor..." if lang == "tr" else "Testing connection..."
            self.console.print(f"\n[dim]{test_msg}[/dim]")
            
            from core.brain import DrakbenBrain
            self.brain = DrakbenBrain()
            
            if self.brain.llm_client:
                test_result = self.brain.test_llm()
                if test_result.get("connected"):
                    ok_msg = "✅ Bağlantı başarılı!" if lang == "tr" else "✅ Connection successful!"
                    self.console.print(f"[green]{ok_msg}[/green]\n")
                else:
                    err_msg = "❌ Bağlantı hatası:" if lang == "tr" else "❌ Connection error:"
                    self.console.print(f"[red]{err_msg} {test_result.get('error', 'Unknown')}[/red]\n")
            
        except Exception as e:
            self.console.print(f"\n[red]❌ Save error: {e}[/]")

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
