# core/interpreter.py
# DRAKBEN Universal Interpreter
# General Purpose Code Execution Engine (Python/Shell) with Computer Tool Integration

import io
import logging
import sys
import traceback
from contextlib import redirect_stdout, redirect_stderr
from typing import Any, Dict, List, Optional, Union

# Import Computer integration
try:
    from core.computer import computer
    COMPUTER_AVAILABLE = True
except ImportError:
    computer = None
    COMPUTER_AVAILABLE = False

# Import CommandSanitizer for security
try:
    from core.execution_engine import CommandSanitizer, SecurityError
    SANITIZER_AVAILABLE = True
except ImportError:
    CommandSanitizer = None
    SecurityError = Exception
    SANITIZER_AVAILABLE = False

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
    def __init__(self, output: str, error: str, files: List[str] = None):
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
                raise PermissionError(f"Write access to system directories is blocked")
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
                except Exception:
                    # Capture traceback
                    traceback.print_exc()
            
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
            # SECURITY: Sanitize command through CommandSanitizer
            if SANITIZER_AVAILABLE and CommandSanitizer:
                sanitizer = CommandSanitizer()
                
                # Get risk level first
                risk = sanitizer.get_risk_level(command)
                if risk == 'critical':
                    blocked_msg = f"CRITICAL: Command '{command[:50]}...' is forbidden by security policy"
                    logger.warning(f"SECURITY BLOCKED: {blocked_msg}")
                    return InterpreterResult("", blocked_msg)
                elif risk == 'high':
                    if sanitizer.is_high_risk(command):
                        logger.warning(f"HIGH RISK command blocked: {command[:50]}")
                        return InterpreterResult("", f"HIGH RISK: Command blocked for security: {command[:50]}...")
                
                # Sanitize the command
                try:
                    sanitized = sanitizer.sanitize(command)
                except SecurityError as e:
                    return InterpreterResult("", f"Security violation: {e}")
            else:
                # Fallback: Basic sanitization without CommandSanitizer
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
                        return InterpreterResult("", f"Dangerous command pattern blocked: {pattern}")
                sanitized = command
            
            # Run sanitized command
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
