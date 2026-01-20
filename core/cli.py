# core/cli.py
# DRAKBEN v2.0 - Modern Async CLI
# Event-driven command line interface

import asyncio
import sys
from typing import Optional, Dict, Callable, List
from dataclasses import dataclass
from enum import Enum

# Rich UI imports
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.text import Text
    from rich.style import Style
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

# Internal imports
from .brain import DrakbenBrain
from .i18n import t
from .plugins.registry import get_registry
from .events import EventEmitter, Event, EventType


class CLIState(Enum):
    """CLI durumları"""
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING_APPROVAL = "waiting_approval"


@dataclass
class CLIContext:
    """CLI bağlam bilgisi"""
    target: Optional[str] = None
    language: str = "tr"
    state: CLIState = CLIState.IDLE
    last_command: Optional[str] = None
    approved_once: bool = False


class DrakbenCLI:
    """
    Modern Async CLI for DRAKBEN
    Event-driven, rich UI, plugin-aware
    """
    
    # Dracula theme colors
    COLORS = {
        "red": "#FF5555",
        "green": "#50FA7B",
        "yellow": "#F1FA8C",
        "blue": "#6272A4",
        "purple": "#BD93F9",
        "cyan": "#8BE9FD",
        "orange": "#FFB86C",
        "pink": "#FF79C6",
        "bg": "#282A36",
        "fg": "#F8F8F2"
    }
    
    def __init__(self, config=None):
        self.context = CLIContext()
        self.brain = DrakbenBrain()
        self.registry = get_registry()
        self.events = EventEmitter()
        self.running = False
        
        # Rich console
        if RICH_AVAILABLE:
            self.console = Console(color_system="truecolor")
        else:
            self.console = None
        
        # Command handlers
        self._commands: Dict[str, Callable] = {
            "help": self._cmd_help,
            "yardım": self._cmd_help,
            "target": self._cmd_target,
            "hedef": self._cmd_target,
            "lang": self._cmd_lang,
            "dil": self._cmd_lang,
            "status": self._cmd_status,
            "durum": self._cmd_status,
            "plugins": self._cmd_plugins,
            "clear": self._cmd_clear,
            "temizle": self._cmd_clear,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "çıkış": self._cmd_exit,
            "scan": self._cmd_scan,
            "tara": self._cmd_scan,
            "test": self._cmd_test_llm,
        }
        
        # Setup event handlers
        self._setup_events()
    
    def _setup_events(self):
        """Setup event handlers"""
        self.events.on(EventType.STEP_START, self._on_step_start)
        self.events.on(EventType.STEP_COMPLETE, self._on_step_complete)
        self.events.on(EventType.STEP_ERROR, self._on_step_error)
        self.events.on(EventType.NOTIFY_USER, self._on_notify)
    
    def _on_step_start(self, event: Event):
        """Handle step start event"""
        self._print(f"⏳ {event.data.get('description', 'İşlem başlatılıyor...')}", "yellow")
    
    def _on_step_complete(self, event: Event):
        """Handle step complete event"""
        self._print(f"✅ {event.data.get('description', 'Tamamlandı')}", "green")
    
    def _on_step_error(self, event: Event):
        """Handle step error event"""
        self._print(f"❌ Hata: {event.data.get('error', 'Bilinmeyen hata')}", "red")
    
    def _on_notify(self, event: Event):
        """Handle notification event"""
        self._print(f"ℹ️  {event.data.get('message', '')}", "cyan")
    
    def _print(self, message: str, color: str = None):
        """Print with optional color"""
        if self.console and color and color in self.COLORS:
            self.console.print(message, style=self.COLORS[color])
        elif self.console:
            self.console.print(message)
        else:
            print(message)
    
    def _show_banner(self):
        """Show DRAKBEN banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ██████╗ ██████╗  █████╗ ██╗  ██╗██████╗ ███████╗███╗   ██╗║
║     ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝████╗  ██║║
║     ██║  ██║██████╔╝███████║█████╔╝ ██████╔╝█████╗  ██╔██╗ ██║║
║     ██║  ██║██╔══██╗██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║╚██╗██║║
║     ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝███████╗██║ ╚████║║
║     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝║
║                                                              ║
║           🔥 AI-Powered Penetration Testing Assistant 🔥      ║
║                        v2.0 - 2026                           ║
╚══════════════════════════════════════════════════════════════╝
        """
        if self.console:
            self.console.print(banner, style=self.COLORS["purple"])
        else:
            print(banner)
    
    async def _cmd_help(self, args: List[str] = None):
        """Show help"""
        if self.console:
            table = Table(title="🆘 DRAKBEN Komutları", border_style=self.COLORS["purple"])
            table.add_column("Komut", style=self.COLORS["cyan"])
            table.add_column("Açıklama", style=self.COLORS["fg"])
            
            table.add_row("target <IP>", "Hedef belirle")
            table.add_row("scan [quick|full]", "Port taraması başlat")
            table.add_row("status", "Mevcut durumu göster")
            table.add_row("plugins", "Yüklü plugin'leri listele")
            table.add_row("lang <tr|en>", "Dil değiştir")
            table.add_row("test", "LLM bağlantısını test et")
            table.add_row("clear", "Ekranı temizle")
            table.add_row("exit", "Çıkış")
            table.add_row("", "")
            table.add_row("Doğal dil", "Herhangi bir soru veya komut yaz")
            
            self.console.print(table)
        else:
            print("""
DRAKBEN Komutları:
  target <IP>     - Hedef belirle
  scan [quick]    - Port taraması
  status          - Durum göster
  plugins         - Plugin listesi
  lang <tr|en>    - Dil değiştir
  test            - LLM test
  clear           - Temizle
  exit            - Çıkış
  
Veya doğal dil ile komut yazın.
            """)
    
    async def _cmd_target(self, args: List[str]):
        """Set target"""
        if not args:
            self._print("❌ Hedef belirtilmedi. Kullanım: target <IP>", "red")
            return
        
        self.context.target = args[0]
        self._print(f"✅ Hedef ayarlandı: {self.context.target}", "green")
    
    async def _cmd_lang(self, args: List[str]):
        """Set language"""
        if not args or args[0] not in ["tr", "en"]:
            self._print("❌ Kullanım: lang <tr|en>", "red")
            return
        
        self.context.language = args[0]
        self._print(f"✅ Dil ayarlandı: {args[0]}", "green")
    
    async def _cmd_status(self, args: List[str] = None):
        """Show status"""
        if self.console:
            table = Table(title="📊 DRAKBEN Durumu", border_style=self.COLORS["cyan"])
            table.add_column("Özellik", style=self.COLORS["purple"])
            table.add_column("Değer", style=self.COLORS["fg"])
            
            table.add_row("Hedef", self.context.target or "Belirlenmedi")
            table.add_row("Dil", self.context.language)
            table.add_row("Durum", self.context.state.value)
            
            # Brain stats
            stats = self.brain.get_stats()
            table.add_row("LLM Bağlantısı", "✅ Aktif" if stats.get("llm_available") else "❌ Offline")
            table.add_row("Karar Sayısı", str(stats.get("decisions_made", 0)))
            
            self.console.print(table)
        else:
            print(f"Hedef: {self.context.target or 'Belirlenmedi'}")
            print(f"Dil: {self.context.language}")
    
    async def _cmd_plugins(self, args: List[str] = None):
        """List plugins"""
        plugins = self.registry.list_plugins()
        
        if self.console:
            table = Table(title="🔌 Yüklü Plugin'ler", border_style=self.COLORS["orange"])
            table.add_column("ID", style=self.COLORS["cyan"])
            table.add_column("Ad", style=self.COLORS["fg"])
            table.add_column("Tür", style=self.COLORS["purple"])
            table.add_column("Durum", style=self.COLORS["green"])
            
            for p in plugins:
                status = "✅" if p.get("available") else "❌"
                table.add_row(p["id"], p["name"], p["kind"], status)
            
            self.console.print(table)
        else:
            for p in plugins:
                print(f"  {p['id']} - {p['name']} ({p['kind']})")
    
    async def _cmd_clear(self, args: List[str] = None):
        """Clear screen"""
        if self.console:
            self.console.clear()
        else:
            print("\033c", end="")
    
    async def _cmd_exit(self, args: List[str] = None):
        """Exit CLI"""
        self._print("👋 Görüşürüz!", "purple")
        self.running = False
    
    async def _cmd_scan(self, args: List[str] = None):
        """Quick scan"""
        if not self.context.target:
            self._print("❌ Önce hedef belirleyin: target <IP>", "red")
            return
        
        scan_type = args[0] if args else "quick"
        self._print(f"🔍 Tarama başlatılıyor: {self.context.target} ({scan_type})", "yellow")
        
        # Use plugin
        result = await self.registry.execute_plugin(
            "recon.nmap",
            target=self.context.target,
            scan_type=scan_type
        )
        
        if result.success:
            self._print(f"✅ Tarama tamamlandı!", "green")
            if result.data.get("open_ports"):
                self._print(f"📡 Açık portlar: {result.data['open_ports']}", "cyan")
            if result.next_steps:
                self._print("💡 Önerilen adımlar:", "yellow")
                for step in result.next_steps:
                    self._print(f"   → {step}", "fg")
        else:
            self._print(f"❌ Hata: {result.errors}", "red")
    
    async def _cmd_test_llm(self, args: List[str] = None):
        """Test LLM connection"""
        self._print("🔄 LLM bağlantısı test ediliyor...", "yellow")
        
        result = self.brain.test_llm()
        
        if result.get("connected"):
            self._print("✅ LLM bağlantısı aktif!", "green")
            self._print(f"   Provider: {result['provider'].get('provider')}", "cyan")
            self._print(f"   Model: {result['provider'].get('model')}", "cyan")
        else:
            self._print(f"❌ LLM bağlantısı yok: {result.get('error')}", "red")
    
    async def _process_natural_language(self, user_input: str):
        """Process natural language input through brain"""
        self.context.state = CLIState.THINKING
        
        if self.console:
            with self.console.status("[bold purple]Düşünüyor...", spinner="dots"):
                result = self.brain.think(user_input, self.context.target)
        else:
            print("Düşünüyor...")
            result = self.brain.think(user_input, self.context.target)
        
        self.context.state = CLIState.IDLE
        
        # Show LLM response if available
        if result.get("llm_response"):
            self._print(f"\n🤖 {result['llm_response']}\n", "cyan")
        elif result.get("reply"):
            self._print(f"\n💭 {result['reply']}\n", "cyan")
        
        # Show command if generated
        if result.get("command"):
            self._print(f"📝 Önerilen komut: {result['command']}", "yellow")
            
            if result.get("needs_approval"):
                response = Prompt.ask("Bu komutu çalıştırmak ister misiniz?", choices=["e", "h"], default="h") if self.console else input("Çalıştır? [e/h]: ")
                if response.lower() in ["e", "y", "evet", "yes"]:
                    self._print("⏳ Komut çalıştırılıyor...", "yellow")
                    # Execute via plugin or terminal
        
        # Show next steps
        if result.get("steps"):
            self._print("📋 Plan:", "purple")
            for i, step in enumerate(result["steps"], 1):
                action = step.get("action", step) if isinstance(step, dict) else step
                self._print(f"   {i}. {action}", "fg")
    
    async def run(self):
        """Main run loop"""
        self._show_banner()
        self._print(f"\n{t('welcome', self.context.language)}", "green")
        self._print("Yardım için 'help' yazın.\n", "blue")
        
        self.running = True
        
        while self.running:
            try:
                # Get input
                if self.console:
                    prompt_text = Text()
                    prompt_text.append("drakben", style=self.COLORS["purple"])
                    if self.context.target:
                        prompt_text.append(f"@{self.context.target}", style=self.COLORS["cyan"])
                    prompt_text.append("> ", style=self.COLORS["fg"])
                    
                    user_input = Prompt.ask(prompt_text)
                else:
                    prompt = f"drakben"
                    if self.context.target:
                        prompt += f"@{self.context.target}"
                    user_input = input(f"{prompt}> ")
                
                if not user_input.strip():
                    continue
                
                self.context.last_command = user_input
                
                # Check if it's a command
                parts = user_input.strip().split(maxsplit=1)
                cmd = parts[0].lower()
                args = parts[1].split() if len(parts) > 1 else []
                
                if cmd in self._commands:
                    await self._commands[cmd](args)
                else:
                    # Process as natural language
                    await self._process_natural_language(user_input)
                    
            except KeyboardInterrupt:
                self._print("\n\n👋 İşlem iptal edildi.", "yellow")
                break
            except EOFError:
                break
            except Exception as e:
                self._print(f"❌ Hata: {e}", "red")
        
        self._print("\n🙏 DRAKBEN'i kullandığınız için teşekkürler!", "purple")


# Entry point
async def main():
    """CLI entry point"""
    cli = DrakbenCLI()
    await cli.run()


def run():
    """Sync entry point"""
    asyncio.run(main())


if __name__ == "__main__":
    run()
