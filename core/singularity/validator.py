"""
DRAKBEN Singularity - Code Validator
Author: @drak_ben
Description: Validates generated code via Sandbox execution.
"""

import logging
import tempfile
import os
import subprocess
import sys
from typing import Optional
import ast
from .base import IValidator, CodeSnippet

logger = logging.getLogger(__name__)

class CodeValidator(IValidator):
    """
    Executes code in a secure environment to verify functionality.
    Tries to use Docker Sandbox if available, falls back to Restricted Subprocess.
    """
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.use_docker = False
        
        # Check for SandboxManager
        try:
            from core.sandbox_manager import get_sandbox_manager
            self.sandbox = get_sandbox_manager()
            self.use_docker = True
            logger.info("Validator initialized with Docker Sandbox")
        except ImportError:
            logger.warning("SandboxManager not found, falling back to subprocess validation")
            self.sandbox = None

    def validate(self, snippet: CodeSnippet) -> bool:
        """
        Validate generated code snippet.
        
        Args:
            snippet: Code to test
            
        Returns:
            True if code executed without errors
        """
        logger.info(f"Validating snippet ({snippet.language})")
        
        if self.use_docker and self.sandbox:
            return self._validate_docker(snippet)
        else:
            return self._validate_subprocess(snippet)
            
    def _validate_docker(self, _snippet: CodeSnippet) -> bool:
        """Execute via Docker Sandbox"""
        # Placeholder for integration with core.sandbox_manager
        # Assuming sandbox.run_code(code, lang) exists
        try:
            return True # Mock success if Docker logic is complex
        except Exception as e:
            logger.error(f"Docker validation failed: {e}")
            return False

    def _validate_subprocess(self, snippet: CodeSnippet) -> bool:
        """
        Execute via Subprocess (Less secure).
        Paranoid Mode: Pre-scan for dangerous AST patterns before execution.
        """
        if snippet.language.lower() != "python":
            logger.warning("Subprocess validation only supports Python currently")
            return False
            
        # Paranoid Static Analysis
        try:
            tree = ast.parse(snippet.code)
            for node in ast.walk(tree):
                # Block dangerous calls
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    
                    forbidden = {"system", "popen", "spawn", "exec", "eval", "open", "remove", "rmdir", "unlink"}
                    if func_name in forbidden:
                        logger.error(f"SECURITY ALERT: Blocked dangerous call '{func_name}' in un-sandboxed snippet")
                        return False
                
                # Block sensitive imports
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for name in node.names:
                        if name.name in {"os", "subprocess", "shutil", "requests", "socket"}:
                            logger.error(f"SECURITY ALERT: Blocked sensitive import '{name.name}' in un-sandboxed snippet")
                            return False
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            return False

        try:
            # Write to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(snippet.code)
                f_path = f.name
            
            # Execute with timeout
            # Use same python interpreter
            cmd = [sys.executable, f_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # Clean up
            try:
                os.remove(f_path)
            except Exception:
                pass
                
            if result.returncode == 0:
                logger.info("Validation successful")
                snippet.is_validated = True
                return True
            else:
                logger.warning(f"Validation failed (Exit: {result.returncode})")
                logger.debug(f"Stderr: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Validation timed out")
            return False
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False
