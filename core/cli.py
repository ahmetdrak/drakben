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
    """
    Legacy `core.cli` removed.

    This module was replaced with a fail-fast stub to eliminate alternate execution
    paths and loops. Use the `drakben.py` entrypoint with `RefactoredDrakbenAgent`.
    """

    raise RuntimeError("LEGACY CLI REMOVED: Use drakben.py with RefactoredDrakbenAgent.")
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
        raise RuntimeError(
            "Legacy DrakbenCLI is disabled. Use RefactoredDrakbenAgent via drakben.py."
        )
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
    """CLI entry point (shim redirect)

    Legacy interactive CLI is disabled by default. This shim safely redirects
    execution to the RefactoredDrakbenAgent used by the main entrypoint
    (`drakben.py`). It avoids accidental activation of legacy loops.
    """
    # Lightweight notice for users invoking the legacy CLI
    try:
        from rich.console import Console
        console = Console()
        console.print("⚠️  Legacy CLI disabled — redirecting to RefactoredDrakbenAgent...", style="yellow")
    except Exception:
        print("Legacy CLI disabled — redirecting to RefactoredDrakbenAgent...")

    # Instantiate and run the refactored agent (same behavior as drakben.py)
    from core.refactored_agent import RefactoredDrakbenAgent
    from core.config import ConfigManager

    config_manager = ConfigManager()
    # Ensure any necessary prompts are handled consistently
    try:
        config_manager.prompt_llm_setup_if_needed()
    except Exception:
        # Non-fatal — continue with defaults
        pass

    agent = RefactoredDrakbenAgent(config_manager)
    agent.initialize(target=getattr(config_manager.config, 'target', '') or "")
    # Run the deterministic single-loop (sync blocking call)
    agent.run_autonomous_loop()


def run():
    """Sync entry point"""
    # Run the async shim which immediately redirects to the refactored agent.
    asyncio.run(main())


if __name__ == "__main__":
    run()
