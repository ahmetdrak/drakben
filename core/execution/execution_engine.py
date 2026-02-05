"""DRAKBEN Execution Engine
Author: @drak_ben
Description: 5 modules for intelligent command execution and monitoring.
"""

import contextlib
import logging
import os
import platform
import queue
import re
import shlex
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from core.execution.sandbox_manager import ContainerInfo, SandboxManager

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)


# Sandbox support (lazy import to avoid circular dependency)
_sandbox_manager = None


def _get_sandbox_manager() -> SandboxManager | None:
    """Lazy load sandbox manager to avoid import issues."""
    global _sandbox_manager
    if _sandbox_manager is None:
        try:
            from core.execution.sandbox_manager import get_sandbox_manager

            _sandbox_manager = get_sandbox_manager()
        except ImportError:
            logger.debug("Sandbox manager not available")
            _sandbox_manager = None
    return _sandbox_manager


class SecurityError(Exception):
    """Raised when a security violation is detected."""


class CommandSanitizer:
    """Security layer for command sanitization.
    Prevents shell injection and blocks dangerous commands.
    """

    # Patterns that indicate shell injection attempts
    SHELL_INJECTION_PATTERNS: list[str] = [
        r";",  # Command separator
        r"\|",  # Pipe
        r"&&",  # AND operator
        r"\|\|",  # OR operator
        r"&",  # Background execution or redirect
        r"`[^`]*`",  # Command substitution with backticks
        r"\$\([^)]+\)",  # Command substitution with $()
        r">",  # Redirection
        r"<",  # Input redirection
    ]

    # Commands that are completely forbidden
    FORBIDDEN_COMMANDS: list[str] = [
        # Linux Destructive
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf ~/*",
        "mkfs",
        "dd if=/dev/zero",
        "dd if=/dev/random",
        ":(){ :|:& };:",  # Fork bomb
        "chmod -R 777 /",
        "chown -R",
        "wget -O- | sh",
        "curl | sh",
        "curl | bash",
        "wget -O- | bash",
        # Windows Destructive (VILLAGER KILLER UPDATE)
        "format c:",
        "format d:",
        "rd /s /q",
        "rd /s/q",
        "del /f /s /q",
        "del /f/s/q",
        "powershell -enc",  # Encoded commands are suspicious
        "powershell -encodedcommand",
        "reg delete",
        "bcdedit /delete",
        "vssadmin delete shadows",
        "wbadmin delete catalog",
        "cipher /w",  # Wipe free space
        "drop database",  # SQL destruction
        # System State
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "init 0",
        "init 6",
        # Sensitive file access
        "cat /etc/shadow",
        "cat /etc/passwd",
        "cat /etc/sudoers",
        "type C:\\Windows\\System32\\config\\SAM",
        "type C:\\Windows\\System32\\config\\SYSTEM",
    ]

    # Commands that require explicit confirmation
    HIGH_RISK_PATTERNS: list[str] = [
        r"rm\s+-[rf]+",  # rm with -r or -f flags
        r"chmod\s+[0-7]{3,4}\s+/(etc|bin|usr|var|boot|sbin)",  # Forbidden system chmod
        r"chown\s+.*?\s+/(etc|bin|usr|var|boot|sbin)",  # Forbidden system chown
        r"mv\s+.*?\s+/(etc|bin|usr|var|boot|sbin)",  # Forbidden system mv
        r">\s*/(etc|bin|usr|var|boot|sbin)",  # Forbidden redirection to system
        r"sudo\s+",  # sudo commands
        r"su\s+",  # su commands
        # Windows High Risk
        r"net\s+user\s+.*?\s+/add",  # Adding users
        r"net\s+localgroup\s+.*?\s+/add",  # Adding to groups
        r"taskkill\s+/f",  # Force killing processes
        r"attrib\s+\+h",  # Hiding files
        r"sc\s+delete",  # Deleting services
        r"reg\s+add",  # Modifying registry
    ]

    # Regex patterns for more complex forbidden commands
    FORBIDDEN_REGEX: list[str] = [
        r"powershell.*-e(nc|ncod|ncoded)",  # Catch all encoded powershell variants
        r"format\s+[a-z]:",  # Format drive
        r"rd\s+/s\s+/q",  # Force delete dir
        r"del\s+/f\s+/s\s+/q",  # Force delete files
        r"reg\s+delete\s+HKLM",  # Delete system registry
        r"net\s+user\s+.*\s+/add",  # Add user (Forbidden, not just high risk)
        # Linux Cleanups (Final Polish)
        r"rm\s+-[rf]+\s+\*",  # rm -rf *
        r"chmod\s+(?:-R\s+)?777",  # chmod 777 (anywhere)
        r"chown\s+(?:-R\s+)?root:root",  # chown root:root (generic)
    ]

    @classmethod
    def sanitize(cls, command: str, allow_shell: bool = False) -> str:
        """Sanitize command for safe execution.

        Args:
            command: The command to sanitize
            allow_shell: Whether shell features are explicitly allowed

        Returns:
            Sanitized command

        Raises:
            SecurityError: If command contains forbidden patterns

        """
        # Check for forbidden commands (Substring Match)
        command_lower: str = command.lower().strip()
        for forbidden in cls.FORBIDDEN_COMMANDS:
            if forbidden.lower() in command_lower:
                msg = f"Forbidden command detected: {forbidden}"
                raise SecurityError(msg)

        # Check for forbidden regex patterns (Complex Match)
        for pattern in cls.FORBIDDEN_REGEX:
            if re.search(pattern, command, re.IGNORECASE):
                msg = f"Forbidden command pattern detected: {pattern}"
                raise SecurityError(msg)

        # Check for shell injection patterns (only if shell mode is disabled)
        if not allow_shell:
            for pattern in cls.SHELL_INJECTION_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    msg = f"Potential shell injection detected: pattern '{pattern}'"
                    raise SecurityError(
                        msg,
                    )

        return command

    @classmethod
    def requires_confirmation(cls, command: str) -> tuple[bool, str]:
        """Check if command requires user confirmation before execution.

        Returns:
            Tuple of (requires_confirmation: bool, reason: str)

        """
        command_lower: str = command.lower().strip()

        # Check for high-risk patterns
        for pattern in cls.HIGH_RISK_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return True, f"High-risk pattern detected: {pattern}"

        # Check for sudo/su
        if "sudo " in command_lower or command_lower.startswith("su "):
            return True, "Elevated privilege command"

        # Check for network operations that could be dangerous
        if any(x in command_lower for x in ["curl", "wget", "nc ", "netcat"]):
            if any(y in command_lower for y in ["| sh", "| bash", "-O-", "exec"]):
                return True, "Network command with execution"

        # Check for file modifications in sensitive areas
        if any(x in command for x in ["/etc/", "/usr/", "/bin/", "/sbin/"]):
            if any(y in command_lower for y in ["rm ", "mv ", "cp ", "> ", ">>"]):
                return True, "File modification in system directory"

        return False, ""

    @classmethod
    def is_high_risk(cls, command: str) -> bool:
        """Check if command is high-risk and needs confirmation."""
        return any(
            re.search(pattern, command, re.IGNORECASE)
            for pattern in cls.HIGH_RISK_PATTERNS
        )

    @classmethod
    def get_risk_level(cls, command: str) -> str:
        """Get risk level of a command.

        Returns:
            'low', 'medium', 'high', or 'critical'

        """
        command_lower: str = command.lower()

        # Check for forbidden (critical)
        for forbidden in cls.FORBIDDEN_COMMANDS:
            if forbidden.lower() in command_lower:
                return "critical"

        # Check for high-risk patterns
        if cls.is_high_risk(command):
            return "high"

        # Check for medium-risk commands
        medium_risk: list[str] = [
            "curl",
            "wget",
            "nc",
            "netcat",
            "ncat",
            "python -c",
            "perl -e",
            "ruby -e",
        ]
        if any(cmd in command_lower for cmd in medium_risk):
            return "medium"

        return "low"


class ExecutionStatus(Enum):
    """Status of command execution."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """Result of command execution."""

    command: str
    status: ExecutionStatus
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timestamp: float


# ====================
# MODULE 1: SmartTerminal
# ====================
# History size limit to prevent memory leaks
MAX_EXECUTION_HISTORY = 1000


class SmartTerminal:
    """Intelligent command executor with safety, monitoring, and user confirmation."""

    def __init__(
        self,
        confirmation_callback: Callable[[str, str], bool] | None = None,
    ) -> None:
        """Initialize SmartTerminal.

        Args:
            confirmation_callback: Optional callback for user confirmation.
                                   Takes (command, reason) and returns True to allow, False to deny.
                                   If None, high-risk commands are blocked by default.

        """
        self.execution_history: list[ExecutionResult] = []
        self.current_process: subprocess.Popen | None = None
        self.sanitizer = CommandSanitizer()
        self._history_lock = threading.Lock()  # Thread safety for history
        self._confirmation_callback: Callable[[str, str], bool] | None = (
            confirmation_callback
        )
        self._auto_approve = False  # Set True to skip confirmations (dangerous!)
        self._sandbox_container_id: str | None = None  # Active sandbox container

    def set_confirmation_callback(
        self,
        callback: Callable[[str, str], bool] | None,
    ) -> None:
        """Set or update the confirmation callback."""
        self._confirmation_callback: Callable[[str, str], bool] | None = callback

    def set_auto_approve(self, auto: bool) -> None:
        """Enable/disable auto-approval for high-risk commands.
        WARNING: Only use in controlled environments!
        """
        self._auto_approve: bool = auto
        if auto:
            logger.warning("SECURITY: Auto-approve enabled for high-risk commands!")

    def _request_confirmation(self, command: str, reason: str) -> bool:
        """Request user confirmation for high-risk command.

        Returns:
            True if approved, False if denied

        """
        if self._auto_approve:
            logger.info("Auto-approved: %s...", command[:50])
            return True

        if self._confirmation_callback:
            return self._confirmation_callback(command, reason)

        # No callback and no auto-approve = deny by default
        logger.warning(
            f"High-risk command blocked (no confirmation): {command[:50]}...",
        )
        return False

    def _add_to_history(self, result: ExecutionResult) -> None:
        """Add result to history with rotation to prevent memory leak."""
        with self._history_lock:
            self.execution_history.append(result)
            # Rotate history if too large
            if len(self.execution_history) > MAX_EXECUTION_HISTORY:
                # Keep last MAX_EXECUTION_HISTORY entries
                self.execution_history = self.execution_history[-MAX_EXECUTION_HISTORY:]

    def clear_history(self) -> None:
        """Clear execution history to free memory."""
        with self._history_lock:
            self.execution_history.clear()

    def execute(
        self,
        command: str,
        timeout: int = 300,
        capture_output: bool = True,
        shell: bool = False,
        callback: Callable[[ExecutionResult], None] | None = None,
        skip_sanitization: bool = False,
        skip_confirmation: bool = False,
    ) -> ExecutionResult:
        """Execute command with monitoring, security checks, and user confirmation.

        Args:
            command: Command string to execute
            timeout: Maximum execution time in seconds (default: 300)
            capture_output: Whether to capture stdout/stderr (default: True)
            shell: Whether to use shell execution (default: False, security risk if True)
            callback: Optional callback function called with ExecutionResult
            skip_sanitization: Skip security sanitization (USE WITH CAUTION!)
            skip_confirmation: If True, bypass user confirmation (use with caution!)

        Returns:
            ExecutionResult object with:
                - command: str - Executed command
                - status: ExecutionStatus - SUCCESS, FAILED, TIMEOUT, etc.
                - stdout: str - Standard output
                - stderr: str - Error output
                - exit_code: int - Process exit code
                - duration: float - Execution time in seconds
                - timestamp: float - Execution timestamp

        Raises:
            SecurityError: If command contains forbidden patterns

        """
        start_time: float = time.time()

        try:
            # 1. Prepare Command (Sanitize & Parse)
            try:
                sanitized_cmd, cmd_args = self._prepare_command(
                    command,
                    shell,
                    skip_sanitization,
                )
            except SecurityError as e:
                logger.warning("Security violation blocked: %s", e)
                return ExecutionResult(
                    command=command,
                    status=ExecutionStatus.FAILED,
                    stdout="",
                    stderr=f"SECURITY ERROR: {e!s}",
                    exit_code=-1,
                    duration=0.0,
                    timestamp=start_time,
                )

            # 2. Check if user confirmation is required
            if not skip_confirmation:
                needs_confirm, reason = CommandSanitizer.requires_confirmation(
                    sanitized_cmd,
                )
                if needs_confirm:
                    if not self._request_confirmation(sanitized_cmd, reason):
                        return ExecutionResult(
                            command=sanitized_cmd,
                            status=ExecutionStatus.FAILED,
                            stdout="",
                            stderr=f"CONFIRMATION DENIED: {reason}",
                            exit_code=-2,
                            duration=0.0,
                            timestamp=start_time,
                        )

            # 3. Execute process
            process = self._create_process(cmd_args, shell, capture_output)
            self.current_process = process

            # 3. Wait for result
            stdout, stderr, exit_code, status = self._wait_for_process(
                process,
                timeout,
                sanitized_cmd,
            )

            duration: float = time.time() - start_time
            result = ExecutionResult(
                command=sanitized_cmd,
                status=status,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration=duration,
                timestamp=start_time,
            )

            self._add_to_history(result)  # Use thread-safe method with rotation
            if callback:
                callback(result)
            return result

        except Exception as e:
            return self._handle_execution_error(command, e, start_time)
        finally:
            self.current_process = None

    def execute_sandboxed(
        self,
        command: str,
        timeout: int = 300,
        sandbox_name: str | None = None,
    ) -> ExecutionResult:
        """Execute command in an isolated Docker sandbox.

        Falls back to regular execution if Docker is unavailable.

        Args:
            command: Command string to execute
            timeout: Maximum execution time in seconds
            sandbox_name: Optional name for the sandbox container

        Returns:
            ExecutionResult with stdout, stderr, and exit code

        """
        start_time: float = time.time()
        sandbox: SandboxManager | None = _get_sandbox_manager()

        # Fallback to regular execution if sandbox unavailable
        if sandbox is None or not sandbox.is_available():
            logger.info("Sandbox unavailable, falling back to regular execution")
            return self.execute(command, timeout=timeout)

        try:
            # Create sandbox if not exists
            if self._sandbox_container_id is None:
                name: str = sandbox_name or f"exec-{int(time.time())}"
                container: ContainerInfo | None = sandbox.create_sandbox(name)
                if container is None:
                    logger.warning("Failed to create sandbox, falling back")
                    return self.execute(command, timeout=timeout)
                self._sandbox_container_id = container.container_id

            # Execute in sandbox
            sandbox_result: ExecutionResult = sandbox.execute_in_sandbox(
                self._sandbox_container_id,
                command,
                timeout=timeout,
            )

            # Convert to our ExecutionResult format
            status: ExecutionStatus = (
                ExecutionStatus.SUCCESS
                if sandbox_result.success
                else ExecutionStatus.FAILED
            )
            result = ExecutionResult(
                command=command,
                status=status,
                stdout=sandbox_result.stdout,
                stderr=sandbox_result.stderr,
                exit_code=sandbox_result.exit_code,
                duration=sandbox_result.duration,
                timestamp=start_time,
            )

            self._add_to_history(result)
            return result

        except Exception as e:
            logger.exception("Sandboxed execution failed: %s", e)
            return self._handle_execution_error(command, e, start_time)

    def cleanup_sandbox(self) -> bool:
        """Clean up the active sandbox container.

        Returns:
            True if cleanup successful or no sandbox active

        """
        if self._sandbox_container_id is None:
            return True

        sandbox: SandboxManager | None = _get_sandbox_manager()
        if sandbox is None:
            return False

        success: bool = sandbox.cleanup_sandbox(self._sandbox_container_id)
        if success:
            self._sandbox_container_id = None
        return success

    def _prepare_command(
        self,
        command: str,
        shell: bool,
        skip_sanitization: bool,
    ) -> tuple[str, list[str]]:
        """Prepare command for execution: sanitize and split."""
        # SECURITY: Sanitize command before execution
        if not skip_sanitization:
            command = CommandSanitizer.sanitize(command, allow_shell=shell)

        # Log high-risk commands
        risk_level: str = CommandSanitizer.get_risk_level(command)
        if risk_level in ("high", "critical"):
            logger.warning("Executing %s risk command: %s...", risk_level, command[:100])

        if shell:
            logger.warning("Shell execution enabled - this is a security risk")
            cmd_args: str = command
        else:
            cmd_args: list[str] = shlex.split(command)

        return command, cmd_args

    def _create_process(
        self,
        cmd_args: str | list[str],
        shell: bool,
        capture_output: bool,
    ) -> subprocess.Popen:
        """Create and start the subprocess."""
        popen_kwargs: dict[str, bool] = {
            "shell": shell,
            "text": bool(capture_output),
        }

        # Use process groups for better cleanup (Unix/Linux)
        if platform.system() != "Windows":
            popen_kwargs["start_new_session"] = True

        if capture_output:
            popen_kwargs["stdout"] = subprocess.PIPE
            popen_kwargs["stderr"] = subprocess.PIPE
        else:
            popen_kwargs["stdout"] = subprocess.DEVNULL
            popen_kwargs["stderr"] = subprocess.DEVNULL

        process = subprocess.Popen(cmd_args, **popen_kwargs)

        # Register with global stop controller
        try:
            from core.stop_controller import stop_controller
            stop_controller.register_process(process)
        except ImportError:
            pass

        return process

    def _wait_for_process(
        self,
        process: subprocess.Popen,
        timeout: int,
        command_preview: str,
    ) -> tuple[str, str, int, ExecutionStatus]:
        """Wait for process completion with DEADLOCK PREVENTION.
        Uses explicit communication handling and process group cleanup.
        """
        try:
            # COMMUNICATION: Use communicate to prevent buffer deadlocks
            # This reads stdout/stderr until EOF, strictly respecting timeout
            stdout, stderr = process.communicate(timeout=timeout)

            # Process finished naturally
            exit_code: int | Any = process.returncode
            status: ExecutionStatus = (
                ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
            )
            return stdout or "", stderr or "", exit_code, status

        except subprocess.TimeoutExpired:
            # TIMEOUT HANDLER
            logger.warning(
                f"Timeout reached ({timeout}s). Terminating process: {command_preview[:50]}...",
            )

            # 1. Kill the process group to ensure children die too
            self._terminate_process_group(process)

            # 2. Try to salvage partial output after kill
            try:
                # Give it a split second to flush buffers after kill signal
                stdout, stderr = process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", "Command timed out and output buffer was lost"
            except (OSError, ValueError) as e:
                logger.debug("Error capturing output during timeout: %s", e)
                stdout, stderr = "", "Command timed out (output capture failed)"

            return stdout or "", stderr or "", -1, ExecutionStatus.TIMEOUT

        except Exception as e:
            # UNEXPECTED ERROR (e.g., OS errors)
            logger.exception("Error waiting for process: %s", e)
            self._terminate_process_group(process)
            return "", str(e), -1, ExecutionStatus.FAILED

    def _terminate_process_group(self, process: subprocess.Popen) -> None:
        """Terminate process and all children."""
        try:
            if platform.system() != "Windows":
                try:
                    # pylint: disable=no-member
                    pgid = os.getpgid(process.pid)  # type: ignore
                    os.killpg(pgid, signal.SIGTERM)  # type: ignore
                    time.sleep(0.5)
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(pgid, signal.SIGKILL)  # type: ignore
                    # pylint: enable=no-member
                except OSError:
                    process.terminate()
                    time.sleep(0.5)
                    process.kill()
            else:
                # Windows
                try:
                    process.terminate()
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                        capture_output=True,
                        timeout=2,
                        check=False,  # taskkill may fail if process already dead
                    )
        except Exception as e:
            logger.warning("Error during process cleanup: %s", e)
            try:
                process.kill()
            except OSError as e:
                logger.debug("Error killing process: %s", e)

    def _handle_execution_error(
        self,
        command: str,
        error: Exception,
        start_time: float,
    ) -> ExecutionResult:
        """Handle generic execution error."""
        duration: float = time.time() - start_time
        logger.error("Command execution failed: %s", error)
        result = ExecutionResult(
            command=command,
            status=ExecutionStatus.FAILED,
            stdout="",
            stderr=str(error),
            exit_code=-1,
            duration=duration,
            timestamp=start_time,
        )
        self._add_to_history(result)  # Use thread-safe method with rotation
        return result

    def execute_async(
        self,
        command: str,
        shell: bool = False,
        skip_sanitization: bool = False,
    ) -> subprocess.Popen:
        """Execute command asynchronously with security checks.

        Args:
            command: Command to execute
            shell: Whether to use shell execution (SECURITY RISK if True)
            skip_sanitization: Skip security checks (USE WITH CAUTION)

        Returns:
            subprocess.Popen object for the running process

        """
        # SECURITY: Sanitize command before execution
        if not skip_sanitization:
            command = CommandSanitizer.sanitize(command, allow_shell=shell)

        if shell:
            logger.warning("Async shell execution enabled - this is a security risk")
            cmd_args: Any = command
        else:
            cmd_args = shlex.split(command)

        # Security Policy: Shell is allowed ONLY if explicitly requested and sanitized above
        process: subprocess.Popen = subprocess.Popen(
            cmd_args,
            shell=shell,  # nosec B602 - Controlled by shell parameter, sanitized above
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.current_process = process
        return process

    def cancel_current(self) -> bool:
        """Cancel currently running command."""
        if self.current_process:
            self.current_process.kill()
            return True
        return False

    def get_last_result(self) -> ExecutionResult | None:
        """Get last execution result."""
        return self.execution_history[-1] if self.execution_history else None


# ====================
# MODULE 2: CommandGenerator
# ====================
class CommandGenerator:
    """Generates optimized commands for different tools."""

    def generate_nmap_command(
        self,
        target: str,
        scan_type: str = "full",
        ports: str | None = None,
        script: str | None = None,
    ) -> str:
        """Generate optimized nmap command."""
        if scan_type == "quick":
            cmd: str = f"nmap -T4 -F {target}"
        elif scan_type == "stealth":
            cmd: str = f"nmap -sS -T2 {target}"
        elif scan_type == "aggressive":
            cmd: str = f"nmap -A -T4 {target}"
        elif scan_type == "version":
            cmd: str = f"nmap -sV -T4 {target}"
        else:  # full
            cmd: str = f"nmap -sV -sC -T4 {target}"

        if ports:
            cmd += f" -p {ports}"

        if script:
            cmd += f" --script={script}"

        cmd += " -oN nmap_scan.txt"

        return cmd

    def _sanitize_url(self, url: str) -> str:
        """Sanitize URL to prevent command injection."""
        # Remove dangerous characters that could break shell commands
        dangerous_chars: list[str] = [
            "'",
            '"',
            ";",
            "|",
            "&",
            "$",
            "`",
            "\\",
            "\n",
            "\r",
        ]
        sanitized: str = url
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")
        # Also validate URL format
        if not sanitized.startswith(("http://", "https://")):
            logger.warning("URL doesn't start with http(s)://: %s", sanitized[:50])
        return sanitized

    def generate_sqlmap_command(
        self,
        url: str,
        level: int = 1,
        risk: int = 1,
        dbs: bool = False,
        tables: bool = False,
        dump: bool = False,
    ) -> str:
        """Generate sqlmap command with URL sanitization."""
        # SECURITY: Sanitize URL to prevent command injection
        safe_url: str = self._sanitize_url(url)
        # Validate level and risk are within bounds
        level = max(1, min(5, int(level)))
        risk = max(1, min(3, int(risk)))

        cmd: str = f"sqlmap -u '{safe_url}' --batch --level={level} --risk={risk}"

        if dbs:
            cmd += " --dbs"
        elif tables:
            cmd += " --tables"
        elif dump:
            cmd += " --dump"

        return cmd

    def generate_gobuster_command(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str | None = None,
    ) -> str:
        """Generate gobuster command with URL sanitization."""
        # SECURITY: Sanitize URL
        safe_url: str = self._sanitize_url(url)
        # Sanitize wordlist path
        safe_wordlist: str = wordlist.replace("'", "").replace('"', "").replace(";", "")

        cmd: str = f"gobuster dir -u {safe_url} -w {safe_wordlist}"

        if extensions:
            # Sanitize extensions
            safe_ext: str = (
                extensions.replace("'", "").replace('"', "").replace(";", "")
            )
            cmd += f" -x {safe_ext}"

        cmd += " -o gobuster_results.txt"

        return cmd

    def generate_payload_command(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
    ) -> str:
        """Generate payload generation command."""
        if payload_type == "reverse_shell":
            return f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf"
        if payload_type == "bind_shell":
            return (
                f"msfvenom -p linux/x64/shell_bind_tcp LPORT={lport} -f elf -o bind.elf"
            )
        if payload_type == "web_shell":
            return (
                f"msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -o shell.php"
            )
        return f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f raw"

    def optimize_command(self, command: str) -> str:
        """Optimize command for better performance."""
        # Add timeouts
        if "curl" in command and "--connect-timeout" not in command:
            command += " --connect-timeout 10"

        # Add output redirection if missing
        if any(tool in command for tool in ["nmap", "gobuster", "nikto"]):
            if "-o" not in command and ">" not in command:
                command += " -oN scan_output.txt"

        return command


# ====================
# MODULE 3: OutputAnalyzer
# ====================
class OutputAnalyzer:
    """Analyzes and parses command output intelligently."""

    def analyze(self, result: ExecutionResult) -> dict:
        """Analyze execution result and extract insights."""
        analysis = {
            "success": result.status == ExecutionStatus.SUCCESS,
            "duration": result.duration,
            "exit_code": result.exit_code,
            "has_errors": bool(result.stderr),
            "insights": [],
        }

        # Detect tool type from command
        if "nmap" in result.command:
            analysis.update(self._analyze_nmap(result.stdout))
        elif "sqlmap" in result.command:
            analysis.update(self._analyze_sqlmap(result.stdout))
        elif "gobuster" in result.command:
            analysis.update(self._analyze_gobuster(result.stdout))
        elif "nikto" in result.command:
            analysis.update(self._analyze_nikto(result.stdout))

        # Check for common errors
        analysis["error_type"] = self._detect_error_type(result.stderr)

        return analysis

    def _analyze_nmap(self, output: str) -> dict:
        """Analyze nmap output."""
        insights = []
        open_ports = []

        # Find open ports
        port_pattern = r"(\d+)/tcp\s+open\s+(\w+)"
        matches: list[Any] = re.findall(port_pattern, output)

        for port, service in matches:
            open_ports.append({"port": port, "service": service})
            insights.append(f"Found open port {port} ({service})")

        return {
            "tool": "nmap",
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "insights": insights,
        }

    def _analyze_sqlmap(self, output: str) -> dict:
        """Analyze sqlmap output."""
        insights = []
        vulnerable = False

        if "is vulnerable" in output.lower():
            vulnerable = True
            insights.append("SQL injection vulnerability found!")

        if "available databases" in output.lower():
            insights.append("Database enumeration successful")

        return {"tool": "sqlmap", "vulnerable": vulnerable, "insights": insights}

    def _analyze_gobuster(self, output: str) -> dict:
        """Analyze gobuster output."""
        insights = []
        found_dirs = []

        # Find discovered directories
        dir_pattern = r"(/.+?)\s+\(Status:\s+(\d+)\)"
        matches: list[Any] = re.findall(dir_pattern, output)

        for path, status in matches:
            found_dirs.append({"path": path, "status": status})
            if status == "200":
                insights.append(f"Found accessible directory: {path}")

        return {
            "tool": "gobuster",
            "found_directories": found_dirs,
            "total_found": len(found_dirs),
            "insights": insights,
        }

    def _analyze_nikto(self, output: str) -> dict:
        """Analyze nikto output."""
        insights = []

        if "0 host(s) tested" not in output:
            insights.append("Web server scan completed")

        return {"tool": "nikto", "insights": insights}

    def _detect_error_type(self, stderr: str) -> str | None:
        """Detect type of error from stderr."""
        if not stderr:
            return None

        stderr_lower: str = stderr.lower()

        if "command not found" in stderr_lower or "not recognized" in stderr_lower:
            return "missing_tool"
        if "permission denied" in stderr_lower:
            return "permission_error"
        if "no route to host" in stderr_lower or "network unreachable" in stderr_lower:
            return "network_error"
        if "timeout" in stderr_lower:
            return "timeout_error"
        if "connection refused" in stderr_lower:
            return "connection_error"
        return "unknown_error"


# ====================
# MODULE 4: StreamingMonitor
# ====================
class StreamingMonitor:
    """Monitors command execution in real-time."""

    def __init__(self) -> None:
        self.output_queue: queue.Queue[str] = queue.Queue()
        self.monitoring = False

    def monitor_process(
        self,
        process: subprocess.Popen,
        callback: Callable | None = None,
        timeout: float = 300.0,
    ) -> tuple[str, str]:
        """Monitor process output in real-time with timeout protection."""
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        stop_event = threading.Event()

        stdout_thread, stderr_thread = self._start_monitor_threads(
            process,
            stop_event,
            stdout_lines,
            stderr_lines,
            callback,
        )

        self._wait_for_process_with_timeout(process, timeout, stop_event)
        self._join_monitor_threads(stdout_thread, stderr_thread, stop_event)

        return "".join(stdout_lines), "".join(stderr_lines)

    def _start_monitor_threads(
        self,
        process: subprocess.Popen,
        stop_event: threading.Event,
        stdout_lines: list[str],
        stderr_lines: list[str],
        callback: Callable | None,
    ) -> tuple[threading.Thread, threading.Thread]:
        """Start monitoring threads for stdout and stderr."""
        stdout_thread = threading.Thread(
            target=self._read_stdout,
            args=(process, stop_event, stdout_lines, callback),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._read_stderr,
            args=(process, stop_event, stderr_lines, callback),
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()
        return stdout_thread, stderr_thread

    def _read_stdout(
        self,
        process: subprocess.Popen,
        stop_event: threading.Event,
        stdout_lines: list[str],
        callback: Callable | None,
    ) -> None:
        """Read stdout from process."""
        try:
            if process.stdout:
                for line in process.stdout:
                    if stop_event.is_set():
                        break
                    stdout_lines.append(line)
                    if callback:
                        callback("stdout", line)
        except Exception as e:
            logger.debug("Stdout reader exception: %s", e)

    def _read_stderr(
        self,
        process: subprocess.Popen,
        stop_event: threading.Event,
        stderr_lines: list[str],
        callback: Callable | None,
    ) -> None:
        """Read stderr from process."""
        try:
            if process.stderr:
                for line in process.stderr:
                    if stop_event.is_set():
                        break
                    stderr_lines.append(line)
                    if callback:
                        callback("stderr", line)
        except Exception as e:
            logger.debug("Stderr reader exception: %s", e)

    def _wait_for_process_with_timeout(
        self,
        process: subprocess.Popen,
        timeout: float,
        stop_event: threading.Event,
    ) -> None:
        """Wait for process with timeout and handle termination."""
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Process timed out after %ss, terminating...", timeout)
            stop_event.set()
            self._terminate_process(process)

    def _terminate_process(self, process: subprocess.Popen) -> None:
        """Terminate process gracefully, kill if needed."""
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    def _join_monitor_threads(
        self,
        stdout_thread: threading.Thread,
        stderr_thread: threading.Thread,
        stop_event: threading.Event,
    ) -> None:
        """Join monitor threads with timeout."""
        stop_event.set()
        join_timeout = 5.0

        stdout_thread.join(timeout=join_timeout)
        if stdout_thread.is_alive():
            logger.warning("Stdout thread did not terminate in time")

        stderr_thread.join(timeout=join_timeout)
        if stderr_thread.is_alive():
            logger.warning("Stderr thread did not terminate in time")

    def stream_output(self, line_type: str, line: str) -> None:
        """Stream output to queue."""
        self.output_queue.put((line_type, line, time.time()))

    def get_latest_output(self) -> list[tuple[str, str, float]]:
        """Get all queued output."""
        output = []
        while not self.output_queue.empty():
            output.append(self.output_queue.get())
        return output


# ====================
# MODULE 5: ExecutionValidator
# ====================
class ExecutionValidator:
    """Validates execution results and checks success criteria."""

    def validate(self, result: ExecutionResult, expected: dict) -> dict:
        """Validate execution result against expectations."""
        validation = {"valid": True, "checks": [], "failures": []}

        # Validate each expected criterion
        self._validate_exit_code(result, expected, validation)
        self._validate_output_contains(result, expected, validation)
        self._validate_no_errors(result, expected, validation)
        self._validate_duration(result, expected, validation)

        return validation

    def _validate_exit_code(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate exit code matches expected value."""
        if expected.get("exit_code") is None:
            return

        if result.exit_code == expected["exit_code"]:
            validation["checks"].append("Exit code matches")
        else:
            validation["valid"] = False
            validation["failures"].append(
                f"Exit code {result.exit_code} != {expected['exit_code']}",
            )

    def _validate_output_contains(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate output contains expected patterns."""
        output_patterns = expected.get("output_contains")
        if not output_patterns:
            return

        for pattern in output_patterns:
            if pattern in result.stdout:
                validation["checks"].append(f"Output contains '{pattern}'")
            else:
                validation["valid"] = False
                validation["failures"].append(f"Output missing '{pattern}'")

    def _validate_no_errors(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate no errors in stderr."""
        if not expected.get("no_errors", False):
            return

        if not result.stderr:
            validation["checks"].append("No errors in stderr")
        else:
            validation["valid"] = False
            validation["failures"].append("Stderr contains errors")

    def _validate_duration(
        self,
        result: ExecutionResult,
        expected: dict,
        validation: dict,
    ) -> None:
        """Validate execution duration within limit."""
        max_duration = expected.get("max_duration")
        if not max_duration:
            return

        if result.duration <= max_duration:
            validation["checks"].append("Duration within limit")
        else:
            validation["valid"] = False
            validation["failures"].append(
                f"Duration {result.duration}s > {max_duration}s",
            )

    def is_successful(self, result: ExecutionResult) -> bool:
        """Quick check if execution was successful."""
        return result.status == ExecutionStatus.SUCCESS and result.exit_code == 0

    def extract_error_message(self, result: ExecutionResult) -> str | None:
        """Extract meaningful error message."""
        if result.stderr:
            # Get first meaningful line
            lines: list[str] = result.stderr.strip().split("\n")
            for line in lines:
                if line.strip() and not line.startswith("#"):
                    return line.strip()
        return None


# ====================
# UNIFIED FACADE
# ====================
class ExecutionEngine:
    """Main facade combining all 5 execution modules."""

    def __init__(self) -> None:
        self.terminal = SmartTerminal()
        self.generator = CommandGenerator()
        self.analyzer = OutputAnalyzer()
        self.monitor = StreamingMonitor()
        self.validator = ExecutionValidator()

    def execute_smart(
        self,
        command: str,
        timeout: int = 300,
        optimize: bool = True,
        callback: Callable | None = None,
    ) -> dict:
        """Execute command with full intelligence."""
        # Optimize if requested
        if optimize:
            command = self.generator.optimize_command(command)

        # Execute
        result: ExecutionResult = self.terminal.execute(
            command,
            timeout=timeout,
            callback=callback,
        )

        # Analyze
        analysis = self.analyzer.analyze(result)

        # Validate
        validation = self.validator.validate(result, {"exit_code": 0})

        return {
            "result": result,
            "analysis": analysis,
            "validation": validation,
            "success": self.validator.is_successful(result),
        }

    def execute_with_monitoring(
        self,
        command: str,
        progress_callback: Callable | None = None,
    ) -> dict:
        """Execute command with real-time monitoring."""
        process = self.terminal.execute_async(command)

        stdout, stderr = self.monitor.monitor_process(process, progress_callback)

        result = ExecutionResult(
            command=command,
            status=(
                ExecutionStatus.SUCCESS
                if process.returncode == 0
                else ExecutionStatus.FAILED
            ),
            stdout=stdout,
            stderr=stderr,
            exit_code=process.returncode,
            duration=0.0,
            timestamp=time.time(),
        )

        analysis = self.analyzer.analyze(result)

        return {
            "result": result,
            "analysis": analysis,
            "success": self.validator.is_successful(result),
        }

    def get_execution_summary(self) -> dict:
        """Get summary of all executions."""
        history: list[ExecutionResult] = self.terminal.execution_history

        return {
            "total_executions": len(history),
            "successful": sum(
                1 for r in history if r.status == ExecutionStatus.SUCCESS
            ),
            "failed": sum(1 for r in history if r.status == ExecutionStatus.FAILED),
            "average_duration": (
                sum(r.duration for r in history) / len(history) if history else 0
            ),
            "last_command": history[-1].command if history else None,
        }
