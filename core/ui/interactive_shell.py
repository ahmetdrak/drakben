# core/interactive_shell.py
# DRAKBEN Interactive Shell - REPL-like interface
# Similar to Open Interpreter's interactive mode

from __future__ import annotations

import contextlib
import logging
import os
import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from rich.console import Console

if TYPE_CHECKING:
    from collections.abc import Callable

    from core.ui.unified_display import RiskLevel
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

# Setup logger
logger = logging.getLogger(__name__)

# Cross-platform readline support
try:
    import readline as readline_mod

    READLINE_AVAILABLE = True
except ImportError:
    # Windows fallback
    try:
        import pyreadline3 as readline_mod  # type: ignore

        READLINE_AVAILABLE = True
    except ImportError:
        readline_mod = None  # type: ignore
        READLINE_AVAILABLE = False
        logger.debug("readline not available - history and completion disabled")


@dataclass
class CommandResult:
    """# noqa: RUF001Result of an interactive command."""

    success: bool
    output: str = ""
    error: str | None = None
    data: dict | None = None


class InteractiveShell:
    """Interactive shell for DRAKBEN.

    Features:
    - Command history with readline
    - Tab completion for commands
    - Multi-line input support
    - Session persistence
    - Output streaming
    """

    # Shell prompt templates
    PROMPT = "drakben> "
    CONTINUATION_PROMPT = "... "

    # Built-in commands
    BUILTIN_COMMANDS = {
        "help": "Show help message",
        "exit": "Exit the shell",
        "quit": "Exit the shell",
        "clear": "Clear the screen",
        "history": "Show command history",
        "target": "Set/show target",
        "status": "Show current status",
        "run": "Run a command",
        "scan": "Run a scan on current target",
        "exploit": "Run exploit module",
        "shell": "Execute system shell command",
        "python": "Execute Python code",
        "reset": "Reset session state",
        "export": "Export results",
        "config": "Show/edit configuration",
    }

    def __init__(
        self,
        config_manager=None,
        agent=None,
        enable_history: bool = True,
        history_file: str = ".drakben_history",
    ) -> None:
        self.config = config_manager
        self.agent = agent
        self.console = Console()
        self.running = False

        # Command handlers
        self.command_handlers: dict[str, Callable] = {}
        self._register_builtin_commands()

        # Session state
        self.current_target: str | None = None
        self.session_vars: dict[str, str] = {}
        self.command_history: list[str] = []

        # History management
        self.enable_history = enable_history
        self.history_file = history_file

        # Multi-line input state
        self.multiline_buffer: list[str] = []
        self.in_multiline: bool = False

        # Initialize readline
        if enable_history:
            self._setup_readline()

    def _setup_readline(self) -> None:
        """Setup readline for history and completion."""
        if not READLINE_AVAILABLE or readline_mod is None:
            logger.debug("readline not available, skipping setup")
            return

        try:
            # History file
            if os.path.exists(self.history_file):
                readline_mod.read_history_file(self.history_file)

            # Set history length
            readline_mod.set_history_length(1000)

            # Tab completion
            readline_mod.parse_and_bind("tab: complete")
            readline_mod.set_completer(self._completer)

            logger.debug("Readline initialized with history")
        except Exception as e:
            logger.warning("Could not initialize readline: %s", e)

    def _completer(self, text: str, state: int) -> str | None:
        """Tab completion for commands."""
        options: list[str] = []

        # Complete commands
        if not text or text.startswith("/"):
            prefix = text.lstrip("/")
            options.extend(
                "/" + cmd for cmd in self.BUILTIN_COMMANDS if cmd.startswith(prefix)
            )

        # Complete target-related
        if text.startswith("target "):
            # Could add recent targets here
            pass

        if 0 <= state < len(options):
            return options[state]
        return None

    def _register_builtin_commands(self) -> None:
        """Register built-in command handlers."""
        self.command_handlers = {
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "clear": self._cmd_clear,
            "history": self._cmd_history,
            "target": self._cmd_target,
            "status": self._cmd_status,
            "run": self._cmd_run,
            "scan": self._cmd_scan,
            "exploit": self._cmd_exploit,
            "shell": self._cmd_shell,
            "python": self._cmd_python,
            "reset": self._cmd_reset,
            "export": self._cmd_export,
            "config": self._cmd_config,
        }

    def start(self) -> None:
        """Start the interactive shell."""
        self.running = True
        self._show_banner()

        while self.running:
            self._run_single_loop_iteration()

        self._save_history()

    def _run_single_loop_iteration(self) -> None:
        """Handle a single input cycle."""
        try:
            # Get input
            prompt = self.CONTINUATION_PROMPT if self.in_multiline else self.PROMPT

            try:
                line = input(prompt)
            except EOFError:
                lang = self._get_language()
                bye = "Hoşçakalın!" if lang == "tr" else "Goodbye!"
                self.console.print(f"\n{bye}", style="bold green")
                self.running = False
                return
            except KeyboardInterrupt:
                self.console.print("\n^C", style="yellow")
                self.multiline_buffer = []
                self.in_multiline = False
                return

            self._handle_input_line(line)

        except Exception as e:
            logger.exception("Shell error: %s", e)
            self.console.print(f"[red]Error: {e}[/red]")

    def _handle_input_line(self, line: str) -> None:
        """Process the raw input line, handling multiline logic."""
        # Handle multi-line input
        if self.in_multiline:
            if line.strip() == "":
                # Empty line ends multi-line input
                full_input = "\n".join(self.multiline_buffer)
                self.multiline_buffer = []
                self.in_multiline = False
                self._process_input(full_input)
            else:
                self.multiline_buffer.append(line)
            return

        # Check for multi-line start
        if line.strip().endswith(":") or line.strip().endswith("\\"):
            self.multiline_buffer = [line.rstrip("\\")]
            self.in_multiline = True
            return

        # Process single-line input
        self._process_input(line)

    def _save_history(self) -> None:
        """Save command history on exit."""
        if self.enable_history and READLINE_AVAILABLE and readline_mod is not None:
            with contextlib.suppress(Exception):
                readline_mod.write_history_file(self.history_file)

    def _get_language(self) -> str:
        """Get current language from config."""
        if self.config and hasattr(self.config, "config"):
            return getattr(self.config.config, "language", "en")
        return "en"

    def _show_banner(self) -> None:
        """Show welcome banner."""
        lang = self._get_language()

        if lang == "tr":
            banner = """
╔═══════════════════════════════════════════════════════════╗
║     DRAKBEN Etkileşimli Kabuk                              ║
║     Yapay Zeka Destekli Sızma Testi Çerçevesi              ║
╠═══════════════════════════════════════════════════════════╣
║  Komutlar için /help yazın                                 ║
║  Otomatik tamamlama için Tab kullanın                      ║
║  Çıkmak için /exit veya Ctrl+D yazın                       ║
╚═══════════════════════════════════════════════════════════╝
"""
        else:
            banner = """
╔═══════════════════════════════════════════════════════════╗
║     DRAKBEN Interactive Shell                              ║
║     AI-Powered Penetration Testing Framework               ║
╠═══════════════════════════════════════════════════════════╣
║  Type /help for available commands                         ║
║  Use Tab for auto-completion                               ║
║  Type /exit or Ctrl+D to quit                              ║
╚═══════════════════════════════════════════════════════════╝
"""
        self.console.print(Panel(banner.strip(), style="cyan"))

    def _process_input(self, line: str) -> None:
        """Process a line of input."""
        line = line.strip()

        if not line:
            return

        # Add to history
        self.command_history.append(line)

        # Check for slash command
        if line.startswith("/"):
            self._execute_command(line[1:])
            return

        # Natural language processing - delegate to agent
        if self.agent:
            self._process_natural_language(line)
        else:
            # Try to interpret as command
            self._execute_command(line)

    def _execute_command(self, command_line: str) -> None:
        """Execute a slash command."""
        try:
            parts = shlex.split(command_line)
        except ValueError:
            parts = command_line.split()

        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        handler = self.command_handlers.get(cmd)
        if handler:
            self._run_handler(handler, args)
        else:
            self._show_unknown_command(cmd)

    def _run_handler(self, handler: Callable, args: list[str]) -> None:
        """Run a resolved command handler and display its results."""
        try:
            result = handler(args)
            if result and result.output:
                self.console.print(result.output)
            if result and result.error:
                self.console.print(f"[red]{result.error}[/red]")
        except Exception as e:
            logger.exception("Command error: %s", e)
            lang = self._get_language()
            err = "Komut hatası" if lang == "tr" else "Command failed"
            self.console.print(f"[red]{err}: {e}[/red]")

    def _show_unknown_command(self, cmd: str) -> None:
        """Display unknown command message with help hint."""
        lang = self._get_language()
        unknown = "Bilinmeyen komut" if lang == "tr" else "Unknown command"
        hint = "Komutlar için /help yazın" if lang == "tr" else "Type /help for available commands"
        self.console.print(f"[yellow]{unknown}: {cmd}[/yellow]")
        self.console.print(hint)

    def _process_natural_language(self, text: str) -> None:
        """Process natural language input through the agent."""
        from core.ui.unified_display import (
            ConfirmationRequest,
            RiskLevel,
            ThinkingDisplay,
            UnifiedConfirmation,
        )

        thinking_display = ThinkingDisplay(console=self.console, language="en")

        try:
            thinking_display.start_thinking(
                target=self.current_target or "",
                phase="",
                model="",
            )

            result = self.agent.brain.think(text, target=self.current_target)

            thinking_display.finish_thinking(success=True)

            # Show response
            if result.get("reply"):
                self.console.print(
                    Panel(result["reply"], title="DRAKBEN", border_style="green"),
                )

            # Show command if generated with unified confirmation
            if result.get("command"):
                command = result["command"]
                self.console.print(
                    f"[cyan]Suggested command:[/cyan] {command}",
                )

                # Use unified confirmation
                confirmation = UnifiedConfirmation(console=self.console, language="en")
                request = ConfirmationRequest(
                    command=command,
                    risk_level=RiskLevel.MEDIUM,
                    reason="AI suggested command",
                    allow_auto=False,
                )

                if confirmation.ask(request):
                    self._cmd_shell([command])

            # Show steps if multi-step plan
            if result.get("steps") and len(result["steps"]) > 1:
                self.console.print("\n[bold]Proposed steps:[/bold]")
                for i, step in enumerate(result["steps"], 1):
                    self.console.print(f"  {i}. {step.get('action', 'unknown')}")

        except Exception as e:
            thinking_display.finish_thinking(success=False)
            logger.exception("NLP processing error: %s", e)
            self.console.print(f"[red]Could not process: {e}[/red]")

    # ==================== COMMAND HANDLERS ====================

    def _cmd_help(self, args: list[str]) -> CommandResult:
        """Show help message."""
        lang = self._get_language()
        title = "Mevcut Komutlar" if lang == "tr" else "Available Commands"
        table = Table(title=title)
        table.add_column("Komut" if lang == "tr" else "Command", style="cyan")
        table.add_column("Açıklama" if lang == "tr" else "Description")

        for cmd, desc in sorted(self.BUILTIN_COMMANDS.items()):
            table.add_row(f"/{cmd}", desc)

        self.console.print(table)
        hint = "Doğal dilde de komut yazabilirsiniz." if lang == "tr" else "You can also type natural language commands."
        self.console.print(f"\n[dim]{hint}[/dim]")

        return CommandResult(success=True, output="")

    def _cmd_exit(self, args: list[str]) -> CommandResult:
        """Exit the shell."""
        self.running = False
        lang = self._get_language()
        bye = "Hoşçakalın!" if lang == "tr" else "Goodbye!"
        self.console.print(bye, style="bold green")
        return CommandResult(success=True, output="")

    def _cmd_clear(self, args: list[str]) -> CommandResult:
        """Clear the screen."""
        os.system("cls" if os.name == "nt" else "clear")  # nosec B605
        return CommandResult(success=True, output="")

    def _cmd_history(self, args: list[str]) -> CommandResult:
        """Show command history."""
        count = 20
        if args:
            with contextlib.suppress(ValueError):
                count = int(args[0])

        history = self.command_history[-count:]
        for i, cmd in enumerate(history, 1):
            self.console.print(f"  {i:3d}  {cmd}")

        return CommandResult(success=True, output="")

    def _cmd_target(self, args: list[str]) -> CommandResult:
        """Set or show target."""
        if args:
            self.current_target = args[0]
            self.console.print(f"[green]Target set to: {self.current_target}[/green]")

            # Initialize agent if available
            if self.agent:
                self.agent.initialize(self.current_target)
        elif self.current_target:
            self.console.print(
                f"Current target: [cyan]{self.current_target}[/cyan]",
            )
        else:
            self.console.print(
                "[yellow]No target set. Use /target <ip/domain>[/yellow]",
            )

        return CommandResult(success=True, output="")

    def _cmd_status(self, args: list[str]) -> CommandResult:
        """Show current status."""
        table = Table(title="Session Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value")

        table.add_row("Target", self.current_target or "Not set")
        table.add_row("Commands Run", str(len(self.command_history)))

        if self.agent and self.agent.state:
            state = self.agent.state
            table.add_row("Phase", state.phase.value)
            table.add_row("Services Found", str(len(state.open_services)))
            table.add_row("Vulnerabilities", str(len(state.vulnerabilities)))
            table.add_row("Has Foothold", "Yes" if state.has_foothold else "No")

        self.console.print(table)
        return CommandResult(success=True, output="")

    def _cmd_run(self, args: list[str]) -> CommandResult:
        """Run a specific action."""
        if not args:
            self.console.print("[yellow]Usage: /run <action> [args...][/yellow]")
            self.console.print("Actions: scan, exploit, recon, payload")
            return CommandResult(success=False, error="No action specified")

        action = args[0]
        action_args = args[1:]

        # Delegate to agent or specific modules
        if self.agent:
            if action == "scan":
                return self._cmd_scan(action_args)
            if action == "exploit":
                return self._cmd_exploit(action_args)

        return CommandResult(success=False, error=f"Unknown action: {action}")

    def _cmd_scan(self, args: list[str]) -> CommandResult:
        """Run a scan."""
        target = args[0] if args else self.current_target

        if not target:
            return CommandResult(
                success=False,
                error="No target specified. Use /target first or /scan <target>",
            )

        self.console.print(f"[cyan]Starting scan on {target}...[/cyan]")

        if self.agent:
            # Use agent's execution
            result = self.agent._execute_tool("nmap_port_scan", {"target": target})
            if result.get("success"):
                self.console.print("[green]Scan completed![/green]")
                if result.get("stdout"):
                    self.console.print(Syntax(result["stdout"][:1000], "text"))
            else:
                self.console.print(
                    f"[red]Scan failed: {result.get('error', 'Unknown error')}[/red]",
                )
            return CommandResult(success=result.get("success", False), output="")

        return CommandResult(success=False, error="No agent available")

    def _cmd_exploit(self, args: list[str]) -> CommandResult:
        """Run exploit module."""
        if not args:
            self.console.print("[yellow]Usage: /exploit <module> [args...][/yellow]")
            return CommandResult(success=False, error="No exploit specified")

        module = args[0]
        self.console.print(f"[yellow]Running exploit: {module}[/yellow]")

        # Try to execute via agent's tool execution system
        if hasattr(self, "agent") and self.agent:
            target_args: dict = {}
            if len(args) > 1:
                # Parse remaining args as key=value pairs
                for arg in args[1:]:
                    if "=" in arg:
                        k, v = arg.split("=", 1)
                        target_args[k] = v
                    else:
                        target_args["target"] = arg

            # Map common module names to tool_name
            tool_mapping = {
                "sqli": "sqlmap_scan",
                "sqlmap": "sqlmap_scan",
                "nikto": "nikto_web_scan",
                "nuclei": "nuclei_scan",
                "metasploit": "metasploit_exploit",
                "msf": "metasploit_exploit",
            }
            tool_name = tool_mapping.get(module, module)

            try:
                result = self.agent._execute_tool(tool_name, target_args)
                if result.get("success"):
                    self.console.print("[green]Exploit completed successfully![/green]")
                    output = result.get("stdout", result.get("output", ""))
                    if output:
                        from rich.syntax import Syntax
                        self.console.print(Syntax(str(output)[:2000], "text"))
                    return CommandResult(success=True, output=str(output)[:2000])
                else:
                    error_msg = result.get("error", "Unknown error")
                    self.console.print(f"[red]Exploit failed: {error_msg}[/red]")
                    return CommandResult(success=False, error=error_msg)
            except Exception as e:
                self.console.print(f"[red]Exploit error: {e}[/red]")
                return CommandResult(success=False, error=str(e))

        return CommandResult(success=False, error="No agent available for exploit execution")

    def _cmd_shell(self, args: list[str]) -> CommandResult:
        """Execute a system shell command."""
        from core.ui.unified_display import (
            ConfirmationRequest,
            RiskLevel,
            UnifiedConfirmation,
        )

        if not args:
            self.console.print("[yellow]Usage: /shell <command>[/yellow]")
            return CommandResult(success=False, error="No command specified")

        command = " ".join(args)

        # --- UNIFIED RISK WARNING SYSTEM ---
        risk_level = self._assess_shell_risk(command)

        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            confirmation = UnifiedConfirmation(console=self.console, language="en")
            request = ConfirmationRequest(
                command=command,
                risk_level=risk_level,
                reason="Dangerous command detected - may cause system damage or data loss",
                details=[
                    "This command may modify or delete system files",
                    "Consider running in a sandbox environment",
                ],
                allow_auto=False,
            )

            if not confirmation.ask(request):
                return CommandResult(
                    success=False,
                    error="Aborted by user safety check",
                )

        self.console.print(f"[dim]$ {command}[/dim]")

        # Execute with safety checks
        if self.agent:
            result = self.agent.executor.terminal.execute(command, timeout=60)

            if result.stdout:
                self.console.print(result.stdout)
            if result.stderr:
                self.console.print(f"[red]{result.stderr}[/red]")

            return CommandResult(
                success=result.exit_code == 0,
                output="",
                error=result.stderr if result.exit_code != 0 else None,
            )
        # Fallback to direct execution (less safe)
        import subprocess

        try:
            result = subprocess.run(
                command,
                shell=True,  # nosec B602
                capture_output=True,
                text=True,
                timeout=60,
                check=False,  # We handle errors via returncode
            )
            if result.stdout:
                self.console.print(result.stdout)
            if result.stderr:
                self.console.print(f"[red]{result.stderr}[/red]")
            return CommandResult(success=result.returncode == 0, output="")
        except Exception as e:
            return CommandResult(success=False, error=str(e))

    def _assess_shell_risk(self, command: str) -> RiskLevel:
        """Assess risk level of a shell command."""
        from core.ui.unified_display import RiskLevel

        command_lower = command.lower()

        # Critical risk patterns
        critical_patterns = [
            "rm -rf",
            "mkfs",
            "dd if=",
            "> /dev/sda",
            "shutdown",
            "reboot",
            ":(){ :|:& };:",  # Fork bomb
        ]
        if any(rc in command_lower for rc in critical_patterns):
            return RiskLevel.CRITICAL

        # High risk patterns
        high_patterns = [
            "sudo",
            "su ",
            "chmod 777",
            "chown",
            "> /etc/",
            "| sh",
            "| bash",
        ]
        if any(rc in command_lower for rc in high_patterns):
            return RiskLevel.HIGH

        # Medium risk patterns
        medium_patterns = ["curl", "wget", "nc ", "netcat", "python -c"]
        if any(rc in command_lower for rc in medium_patterns):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _cmd_python(self, args: list[str]) -> CommandResult:
        """Execute Python code."""
        if not args:
            self.console.print("[yellow]Usage: /python <code>[/yellow]")
            self.console.print("For multi-line, use /python:")
            return CommandResult(success=False, error="No code specified")

        code = " ".join(args)
        self.console.print(f"[dim]>>> {code}[/dim]")

        try:
            # Safe execution context
            safe_globals = {
                "__builtins__": {
                    "print": print,
                    "len": len,
                    "str": str,
                    "int": int,
                    "float": float,
                    "list": list,
                    "dict": dict,
                    "range": range,
                    "enumerate": enumerate,
                },
                "target": self.current_target,
                "session": self.session_vars,
            }

            if "=" not in code:
                # Expression - use eval but it's already within safe_globals
                # We'll use a local result variable to avoid potential issues
                try:
                    expr_result = eval(code, safe_globals)
                    if expr_result is not None:
                        self.console.print(repr(expr_result))
                except Exception as e:
                    self.console.print(f"[red]Expression error: {e}[/red]")
            else:
                # Statement - use exec
                exec(code, safe_globals)

            return CommandResult(success=True, output="")
        except Exception as e:
            return CommandResult(success=False, error=str(e))

    def _cmd_reset(self, args: list[str]) -> CommandResult:
        """Reset session state."""
        self.current_target = None
        self.session_vars = {}

        if self.agent and self.agent.state:
            from core.agent.state import reset_state

            self.agent.state = reset_state()

        self.console.print("[green]Session reset.[/green]")
        return CommandResult(success=True, output="")

    def _cmd_export(self, args: list[str]) -> CommandResult:
        """Export results."""
        filename = args[0] if args else "drakben_export.json"

        import json

        export_data = {
            "target": self.current_target,
            "session_vars": self.session_vars,
            "command_history": self.command_history[-100:],
        }

        if self.agent and self.agent.state:
            export_data["state"] = self.agent.state.to_dict()

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            self.console.print(f"[green]Exported to {filename}[/green]")
            return CommandResult(success=True, output="")
        except Exception as e:
            return CommandResult(success=False, error=str(e))

    def _config_show(self) -> None:
        """Display current configuration."""
        if not self.config:
            self.console.print("[yellow]No configuration available[/yellow]")
            return

        table = Table(title="Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value")

        table.add_row("Language", getattr(self.config, "language", "tr"))
        table.add_row("LLM Available", str(bool(getattr(self.config, "llm_client", None))))

        if hasattr(self.config, "llm_client") and self.config.llm_client:
            info = self.config.llm_client.get_provider_info()
            table.add_row("LLM Provider", info.get("provider", "unknown"))
            table.add_row("LLM Model", info.get("model", "unknown"))

        self.console.print(table)

    def _config_set(self, key: str, value: str) -> CommandResult:
        """Set a configuration value with type inference."""
        if not hasattr(self.config, key):
            self.console.print(f"[red]Unknown config key: {key}[/red]")
            return CommandResult(success=True, output="")

        current_val = getattr(self.config, key)
        converted = self._convert_config_value(current_val, value, key)
        if converted is None:
            return CommandResult(success=False, error="Invalid type")

        setattr(self.config, key, converted)
        self.console.print(f"[green]Set {key} = {converted}[/green]")
        return CommandResult(success=True, output="")

    def _convert_config_value(self, current_val: Any, value: str, key: str) -> Any:
        """Convert string value to appropriate type based on current value."""
        if isinstance(current_val, bool):
            return value.lower() in ("true", "1", "yes", "on")
        if isinstance(current_val, int):
            try:
                return int(value)
            except ValueError:
                self.console.print(f"[red]Invalid integer for {key}[/red]")
                return None
        if isinstance(current_val, float):
            try:
                return float(value)
            except ValueError:
                self.console.print(f"[red]Invalid float for {key}[/red]")
                return None
        return value

    def _cmd_config(self, args: list[str]) -> CommandResult:
        """Show or edit configuration."""
        if not args:
            self._config_show()
        elif len(args) >= 2:
            return self._config_set(args[0], args[1])
        return CommandResult(success=True, output="")


def start_interactive_shell(config_manager=None, agent=None) -> None:
    """Convenience function to start the interactive shell."""
    shell = InteractiveShell(config_manager=config_manager, agent=agent)
    shell.start()


if __name__ == "__main__":
    # Standalone mode for testing
    shell = InteractiveShell()
    shell.start()
