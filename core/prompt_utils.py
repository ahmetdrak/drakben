# core/prompt_utils.py
# DRAKBEN Enhanced Prompt Utilities
# Auto-complete, history, and progress indicators

import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.live import Live
from rich.table import Table
from rich.panel import Panel

logger = logging.getLogger(__name__)

# Constants
EXIT_COMMAND = "/exit"
PROCESSING_TEXT = "Processing..."

# Try to import prompt_toolkit for advanced features
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter, NestedCompleter, Completer, Completion
    from prompt_toolkit.history import FileHistory, InMemoryHistory
    from prompt_toolkit.styles import Style
    from prompt_toolkit.formatted_text import HTML
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    logger.info("prompt_toolkit not installed - using basic input")


# =========================================
# COMMAND COMPLETER
# =========================================

class DrakbenCompleter(Completer if PROMPT_TOOLKIT_AVAILABLE else object):
    """Custom completer for DRAKBEN commands"""
    
    def __init__(self):
        self.commands = {
            "/help": "Show help menu",
            "/target": "Set target - /target <ip/domain>",
            "/scan": "Start autonomous scan",
            "/shell": "Interactive shell",
            "/status": "Show system status",
            "/clear": "Clear screen",
            "/tr": "Switch to Turkish",
            "/en": "Switch to English",
            EXIT_COMMAND: "Exit DRAKBEN",
            "/report": "Generate report",
            "/nuclei": "Run Nuclei scan",
            "/subdomain": "Enumerate subdomains",
            "/exploit": "Run exploit",
            "/payload": "Generate payload",
        }
        
        self.tool_commands = [
            "nmap", "nikto", "gobuster", "sqlmap", "hydra",
            "nuclei", "subfinder", "amass", "dirb", "wfuzz"
        ]
        
        self.targets_history = []
    
    def get_completions(self, document, complete_event):
        """Generate completions"""
        if not PROMPT_TOOLKIT_AVAILABLE:
            return
        
        text = document.text_before_cursor
        word = document.get_word_before_cursor()
        
        # Command completions
        if text.startswith('/'):
            yield from self._get_command_completions(text)
        
        # Tool completions
        elif any(text.startswith(t) for t in ['scan', 'run', 'use']):
            yield from self._get_tool_completions(word)
        
        # Target completions from history
        elif text.startswith('/target '):
            yield from self._get_target_completions(word)

    def _get_command_completions(self, text):
        """Get completions for commands"""
        for cmd, desc in self.commands.items():
            if cmd.startswith(text):
                yield Completion(
                    cmd,
                    start_position=-len(text),
                    display_meta=desc
                )

    def _get_tool_completions(self, word):
        """Get completions for tools"""
        for tool in self.tool_commands:
            if tool.startswith(word):
                yield Completion(tool, start_position=-len(word))

    def _get_target_completions(self, word):
        """Get completions for targets"""
        for target in self.targets_history:
            if target.startswith(word):
                yield Completion(target, start_position=-len(word))
    
    def add_target(self, target: str):
        """Add target to history for completion"""
        if target and target not in self.targets_history:
            self.targets_history.append(target)


# =========================================
# PROMPT SESSION
# =========================================

class EnhancedPrompt:
    """
    Enhanced prompt with auto-complete and history.
    
    Features:
    - Command auto-completion
    - History with file persistence
    - Syntax highlighting
    - Auto-suggestions
    """
    
    def __init__(
        self,
        history_file: str = ".drakben_history",
        enable_history: bool = True
    ):
        self.history_file = Path(history_file)
        self.enable_history = enable_history
        self.completer = DrakbenCompleter() if PROMPT_TOOLKIT_AVAILABLE else None
        
        if PROMPT_TOOLKIT_AVAILABLE:
            self._init_prompt_toolkit()
        else:
            self.session = None
        
        logger.info("EnhancedPrompt initialized")
    
    def _init_prompt_toolkit(self):
        """Initialize prompt_toolkit session"""
        # Style
        style = Style.from_dict({
            'prompt': '#bd93f9 bold',
            'command': '#50fa7b',
            'path': '#8be9fd',
        })
        
        # History
        if self.enable_history:
            history = FileHistory(str(self.history_file))
        else:
            history = InMemoryHistory()
        
        # Session
        self.session = PromptSession(
            completer=self.completer,
            auto_suggest=AutoSuggestFromHistory(),
            history=history,
            style=style,
            complete_while_typing=True,
            enable_history_search=True,
        )
    
    def prompt(
        self,
        message: str = "DRAKBEN> ",
        default: str = ""
    ) -> str:
        """
        Get input with enhanced features.
        
        Args:
            message: Prompt message
            default: Default value
            
        Returns:
            User input
        """
        if PROMPT_TOOLKIT_AVAILABLE and self.session:
            try:
                return self.session.prompt(
                    HTML(f'<prompt>{message}</prompt>'),
                    default=default
                )
            except (EOFError, KeyboardInterrupt):
                return EXIT_COMMAND
        else:
            # Fallback to basic input
            try:
                return input(message) or default
            except (EOFError, KeyboardInterrupt):
                return EXIT_COMMAND
    
    def add_target_to_history(self, target: str):
        """Add target for completion suggestions"""
        if self.completer:
            self.completer.add_target(target)


# =========================================
# PROGRESS INDICATORS
# =========================================

class DrakbenProgress:
    """
    Progress indicators for long-running operations.
    
    Provides:
    - Spinner for indeterminate tasks
    - Progress bar for determinate tasks
    - Multi-task progress
    - Status updates
    """
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
    
    def spinner(
        self,
        description: str = PROCESSING_TEXT,
        style: str = "bold cyan"
    ):
        """
        Create a spinner context manager.
        
        Usage:
            with progress.spinner("Scanning..."):
                do_scan()
        """
        return Progress(
            SpinnerColumn(),
            TextColumn(f"[{style}]{description}"),
            console=self.console,
            transient=True
        )
    
    def bar(
        self
    ):
        """
        Create a progress bar context manager.
        
        Usage:
            with progress.bar() as p:
                task = p.add_task("download", total=100)
                for i in range(100):
                    p.update(task, advance=1)
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            transient=True
        )
    
    async def async_spinner(
        self,
        coro,
        description: str = PROCESSING_TEXT
    ):
        """
        Run async coroutine with spinner.
        
        Args:
            coro: Async coroutine to run
            description: Spinner description
            
        Returns:
            Coroutine result
        """
        with self.spinner(description) as progress:
            task = progress.add_task(description, total=None)
            result = await coro
            progress.update(task, completed=True)
        return result
    
    def scan_progress(
        self,
        targets: List[str],
        scan_func: Callable,
        description: str = "Scanning"
    ):
        """
        Show progress for scanning multiple targets.
        
        Args:
            targets: List of targets
            scan_func: Function to call for each target
            description: Progress description
            
        Returns:
            List of scan results
        """
        results = []
        
        with self.bar() as progress:
            task = progress.add_task(description, total=len(targets))
            
            for target in targets:
                progress.update(task, description=f"[cyan]Scanning {target}")
                result = scan_func(target)
                results.append(result)
                progress.update(task, advance=1)
        
        return results
    
    async def async_scan_progress(
        self,
        targets: List[str],
        scan_func: Callable,
        description: str = "Scanning",
        concurrency: int = 5
    ):
        """
        Show progress for async scanning.
        
        Args:
            targets: List of targets
            scan_func: Async function to call
            description: Progress description
            concurrency: Max concurrent scans
            
        Returns:
            List of scan results
        """
        results = []
        semaphore = asyncio.Semaphore(concurrency)
        
        async def limited_scan(target):
            async with semaphore:
                return await scan_func(target)
        
        with self.bar() as progress:
            task = progress.add_task(description, total=len(targets))
            
            tasks = []
            for target in targets:
                tasks.append(limited_scan(target))
            
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.update(task, advance=1)
        
        return results


class StatusDisplay:
    """Real-time status display using Rich Live"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.status_data = {}
        self._live = None
    
    def _generate_table(self) -> Table:
        """Generate status table"""
        table = Table(title="DRAKBEN Status", show_header=True)
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="dim")
        
        for component, data in self.status_data.items():
            status = data.get("status", "Unknown")
            details = data.get("details", "")
            
            status_style = "green" if status == "OK" else "yellow" if status == "Running" else "red"
            table.add_row(component, f"[{status_style}]{status}[/]", details)
        
        return table
    
    def start(self):
        """Start live display"""
        self._live = Live(
            self._generate_table(),
            console=self.console,
            refresh_per_second=4
        )
        self._live.start()
    
    def stop(self):
        """Stop live display"""
        if self._live:
            self._live.stop()
            self._live = None
    
    def update(self, component: str, status: str, details: str = ""):
        """Update component status"""
        self.status_data[component] = {
            "status": status,
            "details": details,
            "updated": time.time()
        }
        
        if self._live:
            self._live.update(self._generate_table())
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# =========================================
# COMMAND HISTORY
# =========================================

class CommandHistory:
    """
    Command history manager with file persistence.
    """
    
    def __init__(
        self,
        history_file: str = ".drakben_history",
        max_entries: int = 1000
    ):
        self.history_file = Path(history_file)
        self.max_entries = max_entries
        self.entries: List[Dict[str, Any]] = []
        self._load()
    
    def _load(self):
        """Load history from file"""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self.entries.append({
                                "command": line,
                                "timestamp": None
                            })
            except Exception as e:
                logger.error(f"Failed to load history: {e}")
    
    def _save(self):
        """Save history to file"""
        try:
            with open(self.history_file, 'w') as f:
                for entry in self.entries[-self.max_entries:]:
                    f.write(entry["command"] + "\n")
        except Exception as e:
            logger.error(f"Failed to save history: {e}")
    
    def add(self, command: str):
        """Add command to history"""
        if command and not command.startswith('#'):
            self.entries.append({
                "command": command,
                "timestamp": time.time()
            })
            self._save()
    
    def search(self, prefix: str) -> List[str]:
        """Search history by prefix"""
        return [
            e["command"] for e in self.entries
            if e["command"].startswith(prefix)
        ]
    
    def get_recent(self, count: int = 10) -> List[str]:
        """Get recent commands"""
        return [e["command"] for e in self.entries[-count:]]
    
    def clear(self):
        """Clear history"""
        self.entries.clear()
        if self.history_file.exists():
            self.history_file.unlink()


# =========================================
# CONVENIENCE FUNCTIONS
# =========================================

def create_prompt() -> EnhancedPrompt:
    """Create enhanced prompt instance"""
    return EnhancedPrompt()


def create_progress(console: Optional[Console] = None) -> DrakbenProgress:
    """Create progress instance"""
    return DrakbenProgress(console)


def show_spinner(description: str = PROCESSING_TEXT):
    """Show simple spinner"""
    progress = DrakbenProgress()
    return progress.spinner(description)


async def run_with_spinner(coro, description: str = PROCESSING_TEXT):
    """Run coroutine with spinner"""
    progress = DrakbenProgress()
    return await progress.async_spinner(coro, description)
