"""DRAKBEN Execution Engine
Author: @drak_ben
Description: 5 modules for intelligent command execution and monitoring.
"""

import contextlib
import logging
import os
import platform
import shlex
import signal
import subprocess
import threading
import time
from collections.abc import Callable

# Backward-compatible re-exports — these classes now live in dedicated files
# but external code still imports them from execution_engine.
from core.execution.command_sanitizer import CommandSanitizer, SecurityError
from core.execution.command_tools import (
    CommandGenerator,
    ExecutionValidator,
    OutputAnalyzer,
    StreamingMonitor,
)
from core.execution.sandbox_manager import ContainerInfo, SandboxManager
from core.security.security_utils import audit_command

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


# Types are defined in types.py; re-exported here for backward compatibility
from core.execution.types import ExecutionResult, ExecutionStatus  # noqa: E402

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
        self._confirmation_callback: Callable[[str, str], bool] | None = confirmation_callback
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

            # Audit trail — must never break execution
            try:
                audit_command(
                    command=sanitized_cmd,
                    target="",
                    success=(status == ExecutionStatus.SUCCESS),
                    details={"exit_code": exit_code, "duration": duration},
                )
            except Exception:
                logger.debug("Audit trail write failed for: %s", sanitized_cmd, exc_info=True)

            return result

        except (subprocess.SubprocessError, OSError) as e:
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
            logger.warning(
                "SECURITY: Docker sandbox unavailable — executing command "
                "WITHOUT isolation. Install Docker for sandboxed execution.",
            )
            return self.execute(command, timeout=timeout)

        try:
            # Create sandbox if not exists
            if self._sandbox_container_id is None:
                name: str = sandbox_name or f"exec-{int(time.time())}"
                container: ContainerInfo | None = sandbox.create_sandbox(name)
                if container is None:
                    logger.warning(
                        "SECURITY: Failed to create sandbox container — falling back to unsandboxed execution.",
                    )
                    return self.execute(command, timeout=timeout)
                self._sandbox_container_id = container.container_id

            # Execute in sandbox
            sandbox_result: ExecutionResult = sandbox.execute_in_sandbox(  # type: ignore[assignment]
                self._sandbox_container_id,
                command,
                timeout=timeout,
            )

            # Convert to our ExecutionResult format
            status: ExecutionStatus = ExecutionStatus.SUCCESS if sandbox_result.success else ExecutionStatus.FAILED
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

        except (OSError, RuntimeError) as e:
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
    ) -> tuple[str, str | list[str]]:
        """Prepare command for execution: sanitize and split."""
        # SECURITY: Sanitize command before execution
        if not skip_sanitization:
            command = CommandSanitizer.sanitize(command, allow_shell=shell)

        # Log high-risk commands
        risk_level: str = CommandSanitizer.get_risk_level(command)
        if risk_level in ("high", "critical"):
            logger.warning("Executing %s risk command: %s...", risk_level, command[:100])

        cmd_args: str | list[str]
        if shell:
            logger.warning("Shell execution enabled - this is a security risk")
            cmd_args = command
        else:
            cmd_args = shlex.split(command)

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
            popen_kwargs["stdout"] = subprocess.PIPE  # type: ignore[assignment]
            popen_kwargs["stderr"] = subprocess.PIPE  # type: ignore[assignment]
        else:
            popen_kwargs["stdout"] = subprocess.DEVNULL  # type: ignore[assignment]
            popen_kwargs["stderr"] = subprocess.DEVNULL  # type: ignore[assignment]

        process = subprocess.Popen(cmd_args, **popen_kwargs)  # type: ignore[call-overload]

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
            exit_code: int = process.returncode  # type: ignore[assignment]
            status: ExecutionStatus = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
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

        except OSError as e:
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
        except OSError as e:
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

    def cancel_current(self) -> bool:
        """Cancel currently running command."""
        if self.current_process:
            self.current_process.kill()
            return True
        return False

    def get_last_result(self) -> ExecutionResult | None:
        """Get last execution result."""
        return self.execution_history[-1] if self.execution_history else None


class ExecutionEngine:
    """Main facade combining all 5 execution modules."""

    def __init__(self) -> None:
        self.terminal = SmartTerminal()
        self.generator = CommandGenerator()
        self.analyzer = OutputAnalyzer()
        self.monitor = StreamingMonitor()
        self.validator = ExecutionValidator()
