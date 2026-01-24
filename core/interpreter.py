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

logger = logging.getLogger(__name__)

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
        """Setup initial context with tools and utilities"""
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
            "open": open,
            "help": help,
            "dir": dir,
            # Tools
            "computer": computer,  # Give access to computer tool
        }
        
        # Import useful standard libs
        exec("import os", self.locals)
        exec("import sys", self.locals)
        exec("import math", self.locals)
        exec("import json", self.locals)
        exec("import time", self.locals)
        exec("import datetime", self.locals)
        exec("import random", self.locals)
        exec("import re", self.locals)
        
        logger.info("Interpreter context initialized with Computer tool")

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
        """Execute shell command"""
        import subprocess
        
        try:
            # Run command
            process = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=60
            )
            return InterpreterResult(process.stdout, process.stderr)
        except Exception as e:
            return InterpreterResult("", str(e))

    def reset(self):
        """Reset the variable context"""
        self._initialize_context()

# Global instance
interpreter = UniversalInterpreter()
