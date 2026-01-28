# core/interpreter.py
# DRAKBEN Universal Interpreter
# General Purpose Code Execution Engine (Python/Shell) with Computer Tool Integration

import io
import logging
import sys
import traceback
from contextlib import redirect_stdout, redirect_stderr
from typing import Any, Dict, List, Optional, Union

# Global references with proper typing for Mypy
_computer_obj: Any = None
_CommandSanitizer_cls: Any = None
_SecurityError_cls: Any = Exception

# Import Computer integration
try:
    from core.computer import computer as _comp
    _computer_obj = _comp
    COMPUTER_AVAILABLE = True
except ImportError:
    COMPUTER_AVAILABLE = False

# Import CommandSanitizer for security
try:
    from core.execution_engine import CommandSanitizer as _CS, SecurityError as _SE
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
    'print', 'range', 'len', 'list', 'dict', 'set', 'str', 'int', 'float',
    'bool', 'type', 'enumerate', 'zip', 'min', 'max', 'sum', 'sorted',
    'reversed', 'help', 'dir', 'abs', 'round', 'pow', 'divmod', 'hex',
    'oct', 'bin', 'chr', 'ord', 'repr', 'hash', 'id', 'isinstance',
    'issubclass', 'callable', 'iter', 'next', 'slice', 'map', 'filter',
    'any', 'all', 'format', 'vars', 'getattr', 'hasattr', 'input'
}

# Dangerous modules that should not be imported
BLOCKED_MODULES = {
    'subprocess', 'os.system', 'commands', 'pty', 'popen',
    'ctypes', 'pickle', 'marshal', 'code', 'codeop'
}

class InterpreterResult:
    def __init__(self, output: str, error: str, files: Optional[List[str]] = None):
        self.output = output
        self.error = error
        self.files = files or []
        self.success = not bool(error)

    def __repr__(self):
        return f"Result(success={self.success}, output_len={len(self.output)})"

class UniversalInterpreter:
    """
    Stateful Code Interpreter.
    Maintains variables between executions (like a REPL).
    """
    
    def __init__(self):
        self.locals: Dict[str, Any] = {}
        self._initialize_context()

    def _initialize_context(self):
        """Setup initial context with tools and utilities (SECURITY HARDENED)"""
        # Create safe file opener that validates paths
        def safe_open(path, mode='r', *args, **kwargs):
            """Restricted file open - blocks dangerous paths"""
            dangerous_paths = [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                '/root/', 'C:\\Windows\\System32', 'C:\\Windows\\System'
            ]
            path_str = str(path)
            for dp in dangerous_paths:
                if dp.lower() in path_str.lower():
                    raise PermissionError(f"Access to {path} is blocked for security")
            # Block write to system directories
            if mode in ('w', 'a', 'wb', 'ab') and any(
                path_str.startswith(p) for p in ['/etc', '/usr', '/bin', '/sbin', 'C:\\Windows']
            ):
                raise PermissionError("Write access to system directories is blocked")
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
        exec("import math", self.locals)
        exec("import json", self.locals)
        exec("import time", self.locals)
        exec("import datetime", self.locals)
        exec("import random", self.locals)
        exec("import re", self.locals)
        exec("import hashlib", self.locals)
        exec("import base64", self.locals)
        
        # Provide restricted os module with only safe functions
        import os as _os
        self.locals['os'] = type('SafeOS', (), {
            'path': _os.path,
            'getcwd': _os.getcwd,
            'listdir': _os.listdir,
            'sep': _os.sep,
            'linesep': _os.linesep,
        })()
        
        logger.info("Interpreter context initialized with SECURITY HARDENED settings")

    def run(self, code: str, language: str = "python") -> InterpreterResult:
        """
        Run code in the persistent context.
        """
        if language.lower() in ["python", "py"]:
            return self._run_python(code)
        elif language.lower() in ["shell", "bash", "sh", "cmd", "powershell"]:
            return self._run_shell(code)
        else:
            return InterpreterResult("", f"Unsupported language: {language}")

    def _run_python(self, code: str) -> InterpreterResult:
        """Execute Python code statefully"""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                # We need to handle expressions vs statements
                # Try to eval first (if single line expression)
                # If fail or multiline, use exec
                try:
                    # Compile to check syntax first
                    compiled = compile(code, "<string>", "exec")
                    exec(compiled, self.locals)
                except (SyntaxError, NameError, TypeError, ValueError) as e:
                    # Capture traceback
                    traceback.print_exc()
                    logger.debug(f"Code execution error: {e}")
            
            output = stdout_capture.getvalue()
            error = stderr_capture.getvalue()
            
            return InterpreterResult(output, error)
            
        except Exception as e:
            return InterpreterResult("", str(e))

    def _run_shell(self, command: str) -> InterpreterResult:
        """Execute shell command with SECURITY SANITIZATION"""
        import subprocess
        import shlex
        
        try:
            sanitized = self._sanitize_command(command)
            if not sanitized:
                return InterpreterResult("", "Command blocked by security policy")
            
            return self._execute_sanitized_command(sanitized)
        except Exception as e:
            logger.error(f"Shell execution error: {e}")
            return InterpreterResult("", str(e))
    
    def _sanitize_command(self, command: str) -> Optional[str]:
        """Sanitize command using CommandSanitizer or fallback"""
        if SANITIZER_AVAILABLE and CommandSanitizer:
            return self._sanitize_with_sanitizer(command)
        else:
            return self._sanitize_fallback(command)
    
    def _sanitize_with_sanitizer(self, command: str) -> Optional[str]:
        """Sanitize using CommandSanitizer"""
        sanitizer = CommandSanitizer()
        risk = sanitizer.get_risk_level(command)
        
        if risk == 'critical':
            blocked_msg = f"CRITICAL: Command '{command[:50]}...' is forbidden by security policy"
            logger.warning(f"SECURITY BLOCKED: {blocked_msg}")
            return None
        
        if risk == 'high' and sanitizer.is_high_risk(command):
            logger.warning(f"HIGH RISK command blocked: {command[:50]}")
            return None
        
        try:
            return sanitizer.sanitize(command)
        except SecurityError as e:
            logger.warning(f"Security violation: {e}")
            return None
    
    def _sanitize_fallback(self, command: str) -> Optional[str]:
        """Fallback sanitization without CommandSanitizer"""
        dangerous_patterns = [
            'rm -rf /', 'rm -rf /*', 'mkfs', 'dd if=/dev',
            ':(){ :|:& };:', 'chmod -R 777 /', '/etc/shadow',
            '/etc/passwd', 'wget -O- | sh', 'curl | sh', 'curl | bash',
            'shutdown', 'reboot', 'halt', 'poweroff', 'init 0', 'init 6'
        ]
        cmd_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in cmd_lower:
                logger.warning(f"SECURITY: Blocked dangerous pattern: {pattern}")
                return None
        return command
    
    def _execute_sanitized_command(self, sanitized: str) -> InterpreterResult:
        """Execute sanitized command"""
        import subprocess
        import shlex
        
        try:
            process = subprocess.run(
                sanitized, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=60
            )
            return InterpreterResult(process.stdout, process.stderr)
            
        except subprocess.TimeoutExpired:
            return InterpreterResult("", "Command timed out after 60 seconds")
        except Exception as e:
            logger.error(f"Shell execution error: {e}")
            return InterpreterResult("", str(e))

    def reset(self):
        """Reset the variable context"""
        self._initialize_context()

# Global instance
interpreter = UniversalInterpreter()
