"""DRAKBEN Singularity - Code Validator
Author: @drak_ben
Description: Validates generated code via Sandbox execution.
"""

from __future__ import annotations

import ast
import logging
import os
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING

from .base import CodeSnippet, IValidator

if TYPE_CHECKING:
    from core.execution.sandbox_manager import SandboxManager

logger = logging.getLogger(__name__)


class CodeValidator(IValidator):
    """Executes code in a secure environment to verify functionality.
    Tries to use Docker Sandbox if available, falls back to Restricted Subprocess.
    """

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout
        self.use_docker = False

        # Check for SandboxManager
        try:
            from core.execution.sandbox_manager import get_sandbox_manager

            self.sandbox: SandboxManager | None = get_sandbox_manager()
            self.use_docker = True
            logger.info("Validator initialized with Docker Sandbox")
        except ImportError:
            logger.warning(
                "SandboxManager not found, falling back to subprocess validation",
            )
            self.sandbox = None

    def validate(self, snippet: CodeSnippet) -> bool:
        """Validate generated code snippet.

        Args:
            snippet: Code to test

        Returns:
            True if code executed without errors

        """
        logger.info("Validating snippet (%s)", snippet.language)

        if self.use_docker and self.sandbox:
            return self._validate_docker(snippet)
        return self._validate_subprocess(snippet)

    def _validate_docker(self, snippet: CodeSnippet) -> bool:
        """Execute via Docker Sandbox.

        Uses SandboxManager to run code in isolated container.
        Validates both syntax and runtime execution.
        """
        if not self.sandbox:
            logger.warning("Docker sandbox not available, falling back to subprocess")
            return self._validate_subprocess(snippet)

        try:
            # Step 1: Syntax validation first (fast fail)
            if snippet.language.lower() == "python":
                try:
                    ast.parse(snippet.code)
                except SyntaxError as e:
                    logger.error("Syntax error in code: %s", e)
                    return False

            # Step 2: Execute in sandbox
            result = self.sandbox.execute_in_sandbox(  # type: ignore[call-arg]
                code=snippet.code,
                language=snippet.language,
                timeout=self.timeout,
            )

            # Step 3: Check execution result
            if result is None:
                logger.warning("Sandbox returned None result")
                return False

            # Handle different result types
            if isinstance(result, dict):
                success = result.get("success", False)
                if not success:
                    error = result.get("error", "Unknown error")
                    logger.error("Docker validation failed: %s", error)
                return success
            elif isinstance(result, bool):
                return result
            else:
                # Assume string output means success
                return True

        except TimeoutError:
            logger.error("Docker validation timed out after %ss", self.timeout)
            return False
        except Exception as e:
            logger.exception("Docker validation failed: %s", e)
            return False

    def _validate_subprocess(self, snippet: CodeSnippet) -> bool:
        """Execute via Subprocess (Less secure)."""
        if snippet.language.lower() != "python":
            logger.warning("Subprocess validation only supports Python currently")
            return False

        # Paranoid Static Analysis
        if not self._is_safe_code(snippet.code):
            return False

        return self._run_code_safety(snippet)

    def _is_safe_code(self, code: str) -> bool:
        """Perform paranoid static analysis on the code."""
        try:
            tree = ast.parse(code)
            return all(self._check_ast_node(node) for node in ast.walk(tree))
        except Exception as e:
            logger.exception("Static analysis failed: %s", e)
            return False

    def _check_ast_node(self, node: ast.AST) -> bool:
        """Check a single AST node for dangerous patterns."""
        # Block dangerous calls
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            forbidden = {
                "system",
                "popen",
                "spawn",
                "exec",
                "eval",
                "open",
                "remove",
                "rmdir",
                "unlink",
            }
            if func_name in forbidden:
                logger.error("SECURITY ALERT: Blocked dangerous call '%s'", func_name)
                return False

        # Block sensitive imports
        if isinstance(node, ast.Import | ast.ImportFrom):
            for name in node.names:
                if name.name in {"os", "subprocess", "shutil", "requests", "socket"}:
                    logger.error(
                        f"SECURITY ALERT: Blocked sensitive import '{name.name}'",
                    )
                    return False
        return True

    def _run_code_safety(self, snippet: CodeSnippet) -> bool:
        """Write code to temp file and execute it."""
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
                f.write(snippet.code)
                f_path = f.name

            result = subprocess.run(
                [sys.executable, f_path],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,  # We handle errors via returncode
            )

            self._cleanup_temp_file(f_path)

            if result.returncode == 0:
                logger.info("Validation successful")
                snippet.is_validated = True
                return True
            logger.warning("Validation failed (Exit: %s)", result.returncode)
            return False

        except subprocess.TimeoutExpired:
            logger.exception("Validation timed out")
            return False
        except Exception as e:
            logger.exception("Validation error: %s", e)
            return False

    def _cleanup_temp_file(self, f_path: str) -> None:
        """Clean up temporary validation file."""
        try:
            if os.path.exists(f_path):
                os.remove(f_path)
        except Exception as e:
            logger.debug("Failed to cleanup temp file: %s", e)
