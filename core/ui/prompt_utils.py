# core/prompt_utils.py
# DRAKBEN Enhanced Prompt Utilities
# Auto-complete, history, and progress indicators

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.live import Live
from rich.table import Table

logger = logging.getLogger(__name__)

# Constants
EXIT_COMMAND = "/exit"
PROCESSING_TEXT = "Processing..."

# Try to import prompt_toolkit for advanced features
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import FileHistory, InMemoryHistory
    from prompt_toolkit.styles import Style

    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    logger.info("prompt_toolkit not installed - using basic input")
    # Stub for Mypy when toolkit is missing
    if not TYPE_CHECKING:

        class Completer:
            """Stub class when prompt_toolkit is not installed."""



# =========================================
# COMMAND COMPLETER
# =========================================

# Handle optional completer base class for Mypy
if TYPE_CHECKING:
    BaseCompleter = Completer
else:
    BaseCompleter = Completer if PROMPT_TOOLKIT_AVAILABLE else object


class DrakbenCompleter(BaseCompleter):  # type: ignore
    """Custom completer for DRAKBEN commands.

    Uses centralized command registry from core.ui.commands.
    """

    def __init__(self) -> None:
        # Import from centralized command registry
        from core.ui.commands import TOOL_COMMANDS, get_command_list

        # Get commands from central registry
        self.commands = get_command_list(lang="en")

        # Tool commands from central registry
        self.tool_commands = list(TOOL_COMMANDS)

        self.targets_history: list[str] = []

    def get_completions(self, document, complete_event):  # type: ignore[override]
        """Yield completions for current input."""
        text = document.text_before_cursor.lstrip()
        for cmd in self.commands:
            if cmd.startswith(text):
                yield Completion(cmd, start_position=-len(text))  # type: ignore[misc]
        for tool in self.tool_commands:
            if tool.startswith(text):
                yield Completion(tool, start_position=-len(text))  # type: ignore[misc]


# =========================================
# PROMPT SESSION
# =========================================


class EnhancedPrompt:
    """Enhanced prompt with auto-complete and history.

    Features:
    - Command auto-completion
    - History with file persistence
    - Syntax highlighting
    - Auto-suggestions
    """

    def __init__(
        self,
        history_file: str = ".drakben_history",
        enable_history: bool = True,
    ) -> None:
        self.history_file = Path(history_file)
        self.enable_history = enable_history
        self.completer = DrakbenCompleter() if PROMPT_TOOLKIT_AVAILABLE else None

        if PROMPT_TOOLKIT_AVAILABLE:
            self._init_prompt_toolkit()
        else:
            self.session = None

        logger.info("EnhancedPrompt initialized")

    def _init_prompt_toolkit(self) -> None:
        """Initialize prompt_toolkit session."""
        # Style
        style = Style.from_dict(
            {
                "prompt": "#8BE9FD bold",  # Cyan (Hacker Blue) - Dracula Cyan
                "command": "#50fa7b",
                "path": "#8be9fd",
            },
        )

        # History
        if self.enable_history:
            history = FileHistory(str(self.history_file))
        else:
            history = InMemoryHistory()  # type: ignore[assignment]

        # Session
        self.session = PromptSession(  # type: ignore[assignment]
            completer=self.completer,
            auto_suggest=AutoSuggestFromHistory(),
            history=history,
            style=style,
            complete_while_typing=True,
            enable_history_search=True,
        )

    def prompt(self, message: str = "DRAKBEN> ", default: str = "") -> str:
        """Get input with enhanced features.

        Args:
            message: Prompt message
            default: Default value

        Returns:
            User input

        """
        if PROMPT_TOOLKIT_AVAILABLE and self.session:
            try:
                return self.session.prompt(
                    HTML(f"<prompt>{message}</prompt>"),
                    default=default,
                )
            except (EOFError, KeyboardInterrupt):
                return EXIT_COMMAND
        else:
            # Fallback to basic input
            try:
                return input(message) or default
            except (EOFError, KeyboardInterrupt):
                return EXIT_COMMAND


# =========================================
# PROGRESS INDICATORS
# =========================================


class DrakbenProgress:
    """Progress indicators for long-running operations.

    Provides:
    - Spinner for indeterminate tasks
    - Progress bar for determinate tasks
    - Multi-task progress
    - Status updates
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()


class StatusDisplay:
    """Real-time status display using Rich Live."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.status_data: dict[str, Any] = {}
        self._live = None

    def _generate_table(self) -> Table:
        """Generate status table."""
        table = Table(title="DRAKBEN Status", show_header=True)
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="dim")

        for component, data in self.status_data.items():
            status = data.get("status", "Unknown")
            details = data.get("details", "")

            if status == "OK":
                status_style = "green"
            elif status == "Running":
                status_style = "yellow"
            else:
                status_style = "red"
            table.add_row(component, f"[{status_style}]{status}[/]", details)

        return table

    def start(self) -> None:
        """Start live display."""
        self._live = Live(  # type: ignore[assignment]
            self._generate_table(),
            console=self.console,
            refresh_per_second=4,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop live display."""
        if self._live:
            self._live.stop()
            self._live = None

    def update(self, component: str, status: str, details: str = "") -> None:
        """Update component status."""
        self.status_data[component] = {
            "status": status,
            "details": details,
            "updated": time.time(),
        }

        if self._live:
            self._live.update(self._generate_table())

    def __enter__(self) -> "StatusDisplay":
        self.start()
        return self

    def __exit__(self, _exc_type: Any, _exc_val: Any, _exc_tb: Any) -> None:
        self.stop()
