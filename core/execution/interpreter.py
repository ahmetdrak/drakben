# core/interpreter.py
# DRAKBEN Universal Interpreter
# General Purpose Code Execution Engine (Python/Shell) with Computer Tool Integration

import io
import logging
import threading as _interp_threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from typing import Any

# Global references with proper typing for Mypy
_computer_obj: Any = None
_CommandSanitizer_cls: Any = None


class _FallbackSecurityError(Exception):
    """Fallback SecurityError that won't be caught by generic handlers."""


_SecurityError_cls: type[Exception] = _FallbackSecurityError

# Import Computer integration
try:
    from core.tools.computer import computer as _comp

    _computer_obj = _comp
    COMPUTER_AVAILABLE = True
except ImportError:
    COMPUTER_AVAILABLE = False

# Import CommandSanitizer for security
try:
    from core.execution.execution_engine import CommandSanitizer as _CS
    from core.execution.execution_engine import SecurityError as _SE

    _CommandSanitizer_cls = _CS
    _SecurityError_cls = _SE
    SANITIZER_AVAILABLE = True
except ImportError:
    SANITIZER_AVAILABLE = False

# Re-expose for module level access if needed
computer = _computer_obj
CommandSanitizer = _CommandSanitizer_cls
SecurityError = _SecurityError_cls

logger = logging.getLogger(__name__)

# Restricted builtins for safe Python execution
SAFE_BUILTINS = {
    "print",
    "range",
    "len",
    "list",
    "dict",
    "set",
    "str",
    "int",
    "float",
    "bool",
    "enumerate",
    "zip",
    "min",
    "max",
    "sum",
    "sorted",
    "reversed",
    "help",
    "dir",
    "abs",
    "round",
    "pow",
    "divmod",
    "hex",
    "oct",
    "bin",
    "chr",
    "ord",
    "repr",
    "hash",
    "id",
    "isinstance",
    "issubclass",
    "callable",
    "iter",
    "next",
    "slice",
    "map",
    "filter",
    "any",
    "all",
    "format",
    "vars",
    "getattr",
    "hasattr",
    "input",
}

# Dangerous modules that should not be imported
BLOCKED_MODULES = {
    "subprocess",
    "os.system",
    "commands",
    "pty",
    "popen",
    "ctypes",
    "pickle",
    "marshal",
    "code",
    "codeop",
}


class InterpreterResult:
    """Result of code execution in the sandbox interpreter.

    Attributes:
        output: Standard output from execution
        error: Error message if execution failed
        files: List of files created during execution
        success: True if no errors occurred
    """

    def __init__(self, output: str, error: str, files: list[str] | None = None) -> None:
        self.output = output
        self.error = error
        self.files = files or []
        self.success = not bool(error)

    def __repr__(self) -> str:
        return f"Result(success={self.success}, output_len={len(self.output)})"


class UniversalInterpreter:
    """Stateful Code Interpreter.
    Maintains variables between executions (like a REPL).
    """

    def __init__(self) -> None:
        self.locals: dict[str, Any] = {}
        self._initialize_context()

    def _initialize_context(self) -> None:
        """Setup initial context with tools and utilities (SECURITY HARDENED)."""

        # Create safe file opener that validates paths
        def safe_open(path, mode="r", *args, **kwargs) -> Any:
            """Restricted file open - blocks dangerous paths."""
            import os as _os

            dangerous_paths = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/root/",
                "C:\\Windows\\System32",
                "C:\\Windows\\System",
            ]
            # Resolve to real path to prevent symlink/traversal bypass
            path_str = str(_os.path.realpath(path))
            for dp in dangerous_paths:
                if dp.lower() in path_str.lower():
                    msg = f"Access to {path} is blocked for security"
                    raise PermissionError(msg)
            # Block write to system directories
            if any(c in mode for c in "wa+") and any(
                path_str.startswith(p) for p in ["/etc", "/usr", "/bin", "/sbin", "C:\\Windows"]
            ):
                msg = "Write access to system directories is blocked"
                raise PermissionError(msg)
            return open(path, mode, *args, **kwargs)

        self.locals = {
            "print": print,
            "range": range,
            "len": len,
            "list": list,
            "dict": dict,
            "set": set,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "type": type,
            "enumerate": enumerate,
            "zip": zip,
            "min": min,
            "max": max,
            "sum": sum,
            "sorted": sorted,
            "reversed": reversed,
            "open": safe_open,  # Use safe_open instead of raw open
            "help": help,
            "dir": dir,
            "abs": abs,
            "round": round,
            "isinstance": isinstance,
            "hasattr": hasattr,
            "getattr": getattr,
            # Tools
            "computer": computer,  # Give access to computer tool
        }

        # Import SAFE standard libs only (no os, no sys)
        # C-1 FIX: Direct assignment instead of exec() for module imports
        import base64
        import datetime
        import hashlib
        import json
        import math
        import random
        import re
        import time

        self.locals["math"] = math
        self.locals["json"] = json
        self.locals["time"] = time
        self.locals["datetime"] = datetime
        self.locals["random"] = random
        self.locals["re"] = re
        self.locals["hashlib"] = hashlib
        self.locals["base64"] = base64

        # Provide restricted os module with only safe functions
        import os as _os

        self.locals["os"] = type(
            "SafeOS",
            (),
            {
                "path": _os.path,
                "getcwd": _os.getcwd,
                "sep": _os.sep,
                "linesep": _os.linesep,
            },
        )()

        logger.info("Interpreter context initialized with SECURITY HARDENED settings")

    def run(self, code: str, language: str = "python") -> InterpreterResult:
        """Run code in the persistent context."""
        if language.lower() in ["python", "py"]:
            return self._run_python(code)
        if language.lower() in ["shell", "bash", "sh", "cmd", "powershell"]:
            return self._run_shell(code)
        return InterpreterResult("", f"Unsupported language: {language}")

    def _check_code_security(self, code: str) -> None:
        """Check code for blocked introspection attributes (sandbox escape prevention)."""
        _BLOCKED_ATTRS = frozenset(
            {
                "__class__",
                "__bases__",
                "__subclasses__",
                "__mro__",
                "__globals__",
                "__code__",
                "__builtins__",
                "__import__",
            }
        )
        # AST-based check to prevent string concatenation bypass
        try:
            import ast as _ast

            tree = _ast.parse(code)
            for node in _ast.walk(tree):
                if isinstance(node, _ast.Attribute) and node.attr in _BLOCKED_ATTRS:
                    msg = f"Blocked introspection attribute: {node.attr}"
                    raise SecurityError(msg)
                if isinstance(node, _ast.Name) and node.id in ("__import__", "__builtins__"):
                    msg = f"Blocked introspection name: {node.id}"
                    raise SecurityError(msg)
        except SyntaxError:
            pass  # Will be caught by compile() below
        # Also do a basic string check as defense in depth
        for _blocked in _BLOCKED_ATTRS:
            if _blocked in code:
                msg = f"Blocked introspection attribute: {_blocked}"
                raise SecurityError(msg)

    def _run_python(self, code: str) -> InterpreterResult:
        """Execute Python code statefully."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                try:
                    self._check_code_security(code)
                    compiled = compile(code, "<string>", "exec")
                    exec(compiled, self.locals)  # nosec B102
                except (SyntaxError, NameError, TypeError, ValueError) as e:
                    # Capture traceback to stderr and return error
                    traceback.print_exc()
                    logger.debug("Code execution error: %s", e)

            output = stdout_capture.getvalue()
            error = stderr_capture.getvalue()

            # If error output exists and no stdout, report as failed execution
            if error and not output:
                return InterpreterResult("", error)

            return InterpreterResult(output, error)

        except Exception as e:
            partial_output = stdout_capture.getvalue() if stdout_capture else ""
            return InterpreterResult(partial_output, str(e))

    def _run_shell(self, command: str) -> InterpreterResult:
        """Execute shell command with SECURITY SANITIZATION."""
        try:
            sanitized = self._sanitize_command(command)
            if not sanitized:
                return InterpreterResult("", "Command blocked by security policy")

            return self._execute_sanitized_command(sanitized)
        except (OSError, ValueError, TypeError) as e:
            logger.exception("Shell execution error: %s", e)
            return InterpreterResult("", str(e))

    def _sanitize_command(self, command: str) -> str | None:
        """Sanitize command using CommandSanitizer or fallback."""
        if SANITIZER_AVAILABLE and CommandSanitizer:
            return self._sanitize_with_sanitizer(command)
        return self._sanitize_fallback(command)

    def _sanitize_with_sanitizer(self, command: str) -> str | None:
        """Sanitize using CommandSanitizer."""
        sanitizer = CommandSanitizer()
        risk = sanitizer.get_risk_level(command)

        if risk == "critical":
            blocked_msg = f"CRITICAL: Command '{command[:50]}...' is forbidden by security policy"
            logger.warning("SECURITY BLOCKED: %s", blocked_msg)
            return None

        if risk == "high" and sanitizer.is_high_risk(command):
            logger.warning("HIGH RISK command blocked: %s", command[:50])
            return None

        try:
            return sanitizer.sanitize(command)
        except SecurityError as e:
            logger.warning("Security violation: %s", e)
            return None

    def _sanitize_fallback(self, command: str) -> str | None:
        """Fallback sanitization without CommandSanitizer."""
        dangerous_patterns = [
            "rm -rf /",
            "rm -rf /*",
            "mkfs",
            "dd if=/dev",
            ":(){ :|:& };:",
            "chmod -R 777 /",
            "/etc/shadow",
            "/etc/passwd",
            "wget -O- | sh",
            "curl | sh",
            "curl | bash",
            "shutdown",
            "reboot",
            "halt",
            "poweroff",
            "init 0",
            "init 6",
        ]
        cmd_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in cmd_lower:
                logger.warning("SECURITY: Blocked dangerous pattern: %s", pattern)
                return None
        return command

    def _execute_sanitized_command(self, sanitized: str) -> InterpreterResult:
        """Execute sanitized command."""
        import shlex
        import subprocess

        try:
            # SECURITY FIX: Use shlex to split and shell=False
            args = shlex.split(sanitized)
            process = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,  # We handle errors via returncode
            )
            return InterpreterResult(process.stdout, process.stderr)

        except subprocess.TimeoutExpired:
            return InterpreterResult("", "Command timed out after 60 seconds")
        except (OSError, ValueError) as e:
            logger.exception("Shell execution error: %s", e)
            return InterpreterResult("", str(e))

    def reset(self) -> None:
        """Reset the variable context."""
        self._initialize_context()


# Global instance (use threading.Lock to prevent concurrent access to shared locals)
_interpreter_lock = _interp_threading.Lock()
_interpreter_instance: UniversalInterpreter | None = None


def _get_interpreter() -> UniversalInterpreter:
    """Get thread-safe interpreter instance."""
    global _interpreter_instance
    if _interpreter_instance is None:
        with _interpreter_lock:
            if _interpreter_instance is None:
                _interpreter_instance = UniversalInterpreter()
    return _interpreter_instance


# Keep backward compatibility — use the thread-safe singleton
def __getattr__(name: str) -> Any:
    if name == "interpreter":
        return _get_interpreter()
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
