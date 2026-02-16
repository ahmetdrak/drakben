"""Tool runner mixin for RefactoredDrakbenAgent.

Handles tool dispatch, system-tool execution, argument enrichment,
and result formatting.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.agent._agent_protocol import AgentProtocol
    from core.execution.tool_selector import ToolSpec

    _MixinBase = AgentProtocol
else:
    _MixinBase = object

logger: logging.Logger = logging.getLogger(__name__)

# Error message constant (SonarCloud compliance)
_ERR_UNKNOWN = "Unknown error"


class RAToolRunnerMixin(_MixinBase):
    """Mixin: tool execution, arg enrichment, and result formatting."""

    def _execute_tool_with_progress(self, tool_name: str, args: dict) -> dict:
        """Execute tool with progress indicator and timeout handling."""
        result_container: dict = {}
        execution_done = threading.Event()

        def run_execution():
            try:
                result_container["result"] = self._execute_tool(tool_name, args)
            except Exception as exc:
                result_container["result"] = {
                    "success": False,
                    "error": f"Thread exception: {exc}",
                    "args": args,
                }
            finally:
                execution_done.set()

        # Start execution in thread
        exec_thread = threading.Thread(target=run_execution, daemon=True)
        exec_thread.start()

        # Dynamic timeout based on tool type
        slow_tools = {"nmap_port_scan", "nmap_service_scan", "nmap_vuln_scan", "sqlmap_scan", "nikto_web_scan"}
        max_display_wait = 600 if tool_name in slow_tools else 180  # 10min for scanners, 3min for others
        feedback_interval = 30 if tool_name in slow_tools else 15
        wait_start = time.time()
        last_feedback = wait_start

        while not execution_done.is_set():
            elapsed = time.time() - wait_start

            # Periodic feedback to user
            if time.time() - last_feedback >= feedback_interval:
                self.console.print(
                    f"   [~] Running... ({int(elapsed)}s)",
                    style="dim",
                )
                last_feedback = time.time()

            # Check for very long execution
            if elapsed > max_display_wait:
                self.console.print(
                    f"\n   [!] [yellow]Tool {tool_name} taking too long ({int(elapsed)}s)[/yellow]",
                    style="yellow",
                )
                self.console.print(
                    "   [?] Is target reachable? Check network.",
                    style="dim",
                )
                # Wait a bit more but don't spam
                execution_done.wait(timeout=30)
                if not execution_done.is_set():
                    logger.warning(
                        "Tool %s timed out after %ss \u2014 daemon thread may still be running",
                        tool_name, int(elapsed),
                    )
                    self.console.print(
                        f"   [!] [red]Timeout: {tool_name} not responding.[/red]",
                        style="red",
                    )
                    return {
                        "success": False,
                        "error": f"Execution timeout after {int(elapsed)}s",
                        "timeout": True,
                        "args": args,
                    }
                break

            execution_done.wait(timeout=0.5)

        return result_container.get("result", {"success": False, "error": _ERR_UNKNOWN})

    def _execute_tool(self, tool_name: str, args: dict) -> dict:
        """Execute tool via Strategy Pattern dispatcher.

        Uses ToolDispatcher for O(1) dispatch instead of if/elif chains.
        Custom tool types can be registered at runtime.
        """
        if not hasattr(self, "_dispatcher"):
            from core.agent.tool_dispatch import ToolDispatcher
            self._dispatcher = ToolDispatcher(self)

        return self._dispatcher.dispatch(tool_name, args)

    def _handle_system_evolution(self, args: dict) -> dict:
        """Handle the system_evolution meta-tool."""
        action = args.get("action")
        target = args.get("target")  # file path or tool name
        instruction = args.get("instruction")
        if not action:
            return {"success": False, "error": "Missing 'action' parameter"}

        if action == "create_tool":
            return self._handle_create_tool(target, instruction)
        if action == "modify_file":
            return self._handle_modify_file(target, instruction)

        return {"success": False, "error": f"Unknown evolution action: {action}"}

    def _handle_create_tool(self, target: str | None, instruction: str | None) -> dict:
        """Create a new tool via the AI coder."""
        from core.agent.state import AttackPhase

        if not target or not isinstance(target, str):
            return {
                "success": False,
                "error": "Missing or invalid 'target' (tool name)",
            }

        desc: str = (
            instruction if isinstance(instruction, str) else "No description provided"
        )

        # Dynamic tool creation via Coder
        result = self.coder.create_tool(
            tool_name=target,
            description=desc,
            requirements="",  # Mypy Fix: Missing required argument
        )

        if result["success"]:
            # Register new tool dynamically
            self.tool_selector.register_dynamic_tool(
                name=target,
                phase=AttackPhase.EXPLOIT,
                command_template=f"python3 modules/{target}.py {{target}}",
            )
            return {"success": True, "output": f"Tool {target} created and registered."}

        return result

    def _handle_modify_file(self, target: str | None, instruction: str | None) -> dict:
        """Modify a file using the AI coder (with security checks)."""
        if not target or not isinstance(target, str):
            return {
                "success": False,
                "error": "Missing or invalid 'target' (file path)",
            }

        # Security: Validate path is within project directory
        from pathlib import Path
        try:
            target_path = Path(target).resolve()
            project_root = Path.cwd().resolve()
            if not target_path.is_relative_to(project_root):
                return {
                    "success": False,
                    "error": "Security: File path outside project directory",
                }
        except (ValueError, OSError):
            return {"success": False, "error": "Invalid file path"}

        # Read file first
        try:
            with open(target_path) as f:
                content: str = f.read()
        except Exception as e:
            return {"success": False, "error": f"Read failed: {e}"}

        # Ask LLM for modification
        if not hasattr(self, "brain") or not hasattr(self.brain, "ask_coder"):
            return {"success": False, "error": "Brain/Coder not attached"}

        modification = self.brain.ask_coder(
            f"Modify this file:\n{target}\n\nInstruction:\n{instruction}\n\nContent:\n{content}",
        )

        if modification.get("code"):
            new_content = modification["code"]
            # C-3 FIX: Verify syntax AND security before writing
            import ast

            from core.intelligence.coder import ASTSecurityChecker

            try:
                ast.parse(new_content)
            except SyntaxError:
                return {
                    "success": False,
                    "error": "Generated code had syntax errors. Change rejected.",
                }

            # Security check \u2014 block dangerous patterns
            checker = ASTSecurityChecker()
            violations = checker.check(new_content)
            if violations:
                return {
                    "success": False,
                    "error": f"Security check failed: {violations[:3]}",
                }

            try:
                with open(target_path, "w") as f:
                    f.write(new_content)
                return {
                    "success": True,
                    "output": f"File {target} modified successfully.",
                }
            except OSError as e:
                return {"success": False, "error": f"Write failed: {e}"}

        return {"success": False, "error": "No code generated"}

    def _enrich_tool_args(self, tool_name: str, tool_spec: ToolSpec, args: dict) -> dict:
        """Auto-fill missing command template params from agent state.

        Resolves the common issue where plan steps have empty params but the
        command template requires {ports}, {port}, {url}, etc.
        """
        args = dict(args)  # Don't mutate original
        template = tool_spec.command_template or ""
        self._fill_ports_arg(template, args)
        self._fill_port_arg(template, args)
        self._fill_url_arg(template, args)
        return args

    def _fill_ports_arg(self, template: str, args: dict) -> None:
        """Auto-fill {ports} \u2014 comma-separated list of discovered open ports."""
        if "{ports}" not in template or "ports" in args:
            return
        if self.state and self.state.open_services:
            args["ports"] = ",".join(str(p) for p in sorted(self.state.open_services.keys()))
        else:
            args["ports"] = "1-1000"  # Fallback: scan common range

    def _fill_port_arg(self, template: str, args: dict) -> None:
        """Auto-fill {port} \u2014 single port (first open, or 80 fallback)."""
        if "{port}" not in template or "port" in args:
            return
        if self.state and self.state.open_services:
            for preferred in [80, 443, 8080, 8443]:
                if preferred in self.state.open_services:
                    args["port"] = str(preferred)
                    return
            args["port"] = str(next(iter(sorted(self.state.open_services.keys()))))
        else:
            args["port"] = "80"

    def _fill_url_arg(self, template: str, args: dict) -> None:
        """Auto-fill {url} \u2014 full URL for web scanners."""
        if "{url}" not in template or "url" in args:
            return
        target = self.state.target if self.state else "localhost"
        port = args.get("port", "80")
        scheme = "https" if port in ("443", "8443") else "http"
        args["url"] = f"{scheme}://{target}:{port}"

    def _run_system_tool(self, tool_name: str, tool_spec: ToolSpec, args: dict) -> dict:
        """Run a standard system tool."""
        from rich.panel import Panel


        # Auto-fill missing template parameters from agent state
        args = self._enrich_tool_args(tool_name, tool_spec, args)

        target = self.state.target if self.state else "localhost"

        # Build command from template
        try:
            command = tool_spec.command_template.format(
                target=target,
                **args,
            )
        except KeyError as e:
            return {"success": False, "error": f"Missing argument: {e}", "args": args}

        # ====== KOMUTU KULLANICIYA G\u00d6STER ======
        self.console.print(
            Panel(
                f"[bold cyan]{command}[/bold cyan]",
                title=f"\U0001f4bb {tool_name}",
                border_style="cyan",
                padding=(0, 1),
            ),
        )

        # Execute via execution engine
        result = self.executor.terminal.execute(command, timeout=300)

        # ====== OUTPUT'U KULLANICIYA G\u00d6STER ======
        if result.stdout and result.stdout.strip():
            # Truncate very long output
            output_display = result.stdout[:2000]
            if len(result.stdout) > 2000:
                output_display += f"\n... ({len(result.stdout) - 2000} karakter daha)"
            self.console.print(
                Panel(
                    output_display,
                    title="\U0001f4c4 Output",
                    border_style="green" if result.exit_code == 0 else "red",
                    padding=(0, 1),
                ),
            )

        if result.stderr and result.stderr.strip() and result.exit_code != 0:
            self.console.print(
                Panel(
                    result.stderr[:1000],
                    title="\u26a0\ufe0f Stderr",
                    border_style="yellow",
                    padding=(0, 1),
                ),
            )

        # Execution time feedback
        self.console.print(
            f"   [dim]\u23f1\ufe0f S\u00fcre: {result.duration:.1f}s | Exit: {result.exit_code}[/dim]",
        )

        # Track tool failures globally
        if result.exit_code != 0:
            return self._handle_tool_failure(tool_name, command, result, args)

        return self._format_tool_result(result, args, tool_name=tool_name)

    def _format_tool_result(self, result: Any, args: dict, tool_name: str = "unknown") -> dict:
        """Format execution result dictionary with standardized errors."""
        from core.tools.tool_parsers import normalize_error_message

        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        exit_code = result.exit_code

        # New: Standardize error
        error_msg: str = normalize_error_message(stdout_str, stderr_str, exit_code)

        # Fallback raw error if normalize returns nothing but exit code non-zero
        if exit_code != 0 and not error_msg:
            if stderr_str.strip():
                error_msg = f"Tool Error: {stderr_str.strip()[:200]}"
            else:
                error_msg = f"Command failed with exit code {exit_code}"

        final_result = {
            "success": result.status.value == "success",
            "stdout": stdout_str,
            "stderr": stderr_str,
            "error_summary": error_msg,  # New standardized field
            "exit_code": exit_code,
            "args": args,
        }

        # Log to structured log
        self.logger.log_action(
            tool=tool_name,
            args=args,
            result=final_result,
        )

        return final_result
