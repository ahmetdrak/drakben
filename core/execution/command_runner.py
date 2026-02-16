# core/execution/command_runner.py
# DRAKBEN — Unified Command Runner
# Single abstraction for ALL subprocess calls across the codebase.
# Replaces 11+ scattered subprocess invocation patterns with one consistent API.

"""Unified command execution with timeout, output capture, and error handling.

Usage::

    from core.execution.command_runner import CommandRunner

    runner = CommandRunner()
    result = runner.run(["nmap", "-sV", "10.0.0.1"], timeout=120)
    if result.success:
        print(result.stdout)
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import IO, Any

from core.config import TIMEOUTS

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    """Result of a command execution."""

    success: bool
    exit_code: int
    stdout: str
    stderr: str
    command: str
    duration_ms: float
    timed_out: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for tool registry compatibility."""
        return {
            "success": self.success,
            "output": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "command": self.command,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "error": self.error,
        }


class CommandRunner:
    """Centralized subprocess execution with consistent behavior.

    Features:
    - Configurable timeout with graceful kill
    - Live output streaming (optional)
    - Platform-aware execution
    - Thread-safe
    - Integrates with StopController
    """

    def __init__(
        self,
        default_timeout: int = TIMEOUTS.SUBPROCESS_TIMEOUT,
        working_dir: str | None = None,
    ) -> None:
        self._default_timeout = default_timeout
        self._working_dir = working_dir
        self._lock = threading.Lock()

    @staticmethod
    def _is_stopped() -> bool:
        """Check if stop controller requests cancellation."""
        try:
            from core.stop_controller import check_stop

            return check_stop()
        except ImportError:
            return False

    @staticmethod
    def _register_process(process: subprocess.Popen) -> None:
        """Register process with stop controller for cleanup."""
        try:
            from core.stop_controller import stop_controller

            stop_controller.register_process(process)
        except (ImportError, AttributeError):
            pass

    def run(
        self,
        command: list[str] | str,
        *,
        timeout: int | None = None,
        live_output: bool = False,
        env: dict[str, str] | None = None,
        input_data: str | None = None,
        shell: bool = False,
        working_dir: str | None = None,
    ) -> CommandResult:
        """Execute a command and return structured result.

        Args:
            command: Command as list of args or string (if shell=True)
            timeout: Seconds before kill (None = default)
            live_output: If True, stream stdout/stderr in real-time
            env: Additional environment variables
            input_data: Data to send to stdin
            shell: Execute via shell (use with caution)
            working_dir: Override working directory

        Returns:
            CommandResult with success, stdout, stderr, timing
        """
        effective_timeout = timeout if timeout is not None else self._default_timeout
        cwd = working_dir or self._working_dir
        cmd_str = command if isinstance(command, str) else " ".join(command)

        # Merge environment
        run_env = {**os.environ, **env} if env else None

        start_time = time.monotonic()

        try:
            # Check stop controller
            if self._is_stopped():
                return CommandResult(
                    success=False,
                    exit_code=-1,
                    stdout="",
                    stderr="",
                    command=cmd_str,
                    duration_ms=0,
                    error="Operation cancelled by stop controller",
                )

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_data else None,
                cwd=cwd,
                env=run_env,
                shell=shell,
                text=True,
                errors="replace",
            )

            # Register with stop controller for cleanup
            self._register_process(process)

            if live_output:
                stdout, stderr = self._read_live(process, effective_timeout)
            else:
                stdout, stderr = process.communicate(
                    input=input_data,
                    timeout=effective_timeout,
                )

            elapsed = (time.monotonic() - start_time) * 1000
            return CommandResult(
                success=process.returncode == 0,
                exit_code=process.returncode,
                stdout=stdout or "",
                stderr=stderr or "",
                command=cmd_str,
                duration_ms=elapsed,
            )

        except subprocess.TimeoutExpired:
            elapsed = (time.monotonic() - start_time) * 1000
            self._kill_process(process)
            return CommandResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                command=cmd_str,
                duration_ms=elapsed,
                timed_out=True,
                error=f"Command timed out after {effective_timeout}s",
            )

        except FileNotFoundError:
            elapsed = (time.monotonic() - start_time) * 1000
            return CommandResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                command=cmd_str,
                duration_ms=elapsed,
                error=f"Command not found: {command[0] if isinstance(command, list) else command}",
            )

        except OSError as e:
            elapsed = (time.monotonic() - start_time) * 1000
            return CommandResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="",
                command=cmd_str,
                duration_ms=elapsed,
                error=f"OS error: {e}",
            )

    def run_shell(self, command: str, **kwargs: Any) -> CommandResult:
        """Convenience: run a shell command string."""
        return self.run(command, shell=True, **kwargs)

    @staticmethod
    def _kill_process(process: subprocess.Popen) -> None:  # type: ignore[type-arg]
        """Gracefully terminate, then force kill a process."""
        try:
            process.terminate()
            process.wait(timeout=TIMEOUTS.PROCESS_TERMINATE_TIMEOUT)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=TIMEOUTS.PROCESS_CLEANUP_TIMEOUT)
            except OSError:
                pass
        except OSError:
            pass

    @staticmethod
    def _read_live(
        process: subprocess.Popen,  # type: ignore[type-arg]
        timeout: int,
    ) -> tuple[str, str]:
        """Read stdout/stderr with live streaming and timeout."""
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []

        def _read_stream(stream: IO[str] | None, parts: list[str]) -> None:
            if stream is None:
                return
            parts.extend(stream)

        t_out = threading.Thread(target=_read_stream, args=(process.stdout, stdout_parts))
        t_err = threading.Thread(target=_read_stream, args=(process.stderr, stderr_parts))
        t_out.start()
        t_err.start()

        t_out.join(timeout=timeout)
        t_err.join(timeout=max(1, timeout - 5))

        if process.poll() is None:
            # Still running after timeout
            CommandRunner._kill_process(process)

        return "".join(stdout_parts), "".join(stderr_parts)
