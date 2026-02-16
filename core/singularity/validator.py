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

            # Step 2: Create a sandbox container
            container_info = self.sandbox.create_sandbox(
                name=f"validate-{os.getpid()}",
            )
            if container_info is None:
                logger.warning("Could not create sandbox container, falling back")
                return self._validate_subprocess(snippet)

            container_id = container_info.container_id

            try:
                # Step 3: Build the execution command based on language
                import shlex
                lang = snippet.language.lower()
                if lang == "python":
                    # Use python -c with the code (safely quoted for shell)
                    command = f"python3 -c {shlex.quote(snippet.code)}"
                elif lang == "bash":
                    command = f"bash -c {shlex.quote(snippet.code)}"
                else:
                    logger.warning("Unsupported language for docker validation: %s", lang)
                    return self._validate_subprocess(snippet)

                # Step 4: Execute in sandbox with correct API
                result = self.sandbox.execute_in_sandbox(
                    container_id=container_id,
                    command=command,
                    timeout=self.timeout,
                )

                # Step 5: Check execution result
                if result is None:
                    logger.warning("Sandbox returned None result")
                    return False

                success = getattr(result, "success", False)
                if not success:
                    stderr = getattr(result, "stderr", "Unknown error")
                    logger.error("Docker validation failed: %s", stderr)
                return success

            finally:
                # Always clean up the container
                self.sandbox.cleanup_sandbox(container_id)

        except TimeoutError:
            logger.error("Docker validation timed out after %ss", self.timeout)
            return False
        except (OSError, RuntimeError, ValueError) as e:
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
        except (SyntaxError, ValueError, TypeError) as e:
            logger.exception("Static analysis failed: %s", e)
            return False

    def _check_ast_node(self, node: ast.AST) -> bool:
        """Check a single AST node for dangerous patterns."""
        if isinstance(node, ast.Call):
            return self._check_call_node(node)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return self._check_import_node(node)
        return True

    def _check_call_node(self, node: ast.Call) -> bool:
        """Block dangerous function calls."""
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        forbidden = {
            "system", "popen", "spawn", "exec", "eval",
            "open", "remove", "rmdir", "unlink",
        }
        if func_name in forbidden:
            logger.error("SECURITY ALERT: Blocked dangerous call '%s'", func_name)
            return False
        return True

    def _check_import_node(self, node: ast.Import | ast.ImportFrom) -> bool:
        """Block sensitive imports."""
        _blocked_modules = {"os", "subprocess", "shutil", "requests", "socket"}
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.name in _blocked_modules:
                    logger.error(
                        "SECURITY ALERT: Blocked sensitive import '%s'",
                        name.name,
                    )
                    return False
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _blocked_modules:
                logger.error(
                    "SECURITY ALERT: Blocked sensitive 'from %s' import",
                    node.module,
                )
                return False
        return True

    def _run_code_safety(self, snippet: CodeSnippet) -> bool:
        """Write code to temp file and execute it."""
        f_path = None
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

            if result.returncode == 0:
                logger.info("Validation successful")
                snippet.is_validated = True
                return True
            logger.warning("Validation failed (Exit: %s)", result.returncode)
            return False

        except subprocess.TimeoutExpired:
            logger.exception("Validation timed out")
            return False
        except (OSError, ValueError) as e:
            logger.exception("Validation error: %s", e)
            return False
        finally:
            # H-7 FIX: Always cleanup temp file, even on exceptions
            if f_path:
                self._cleanup_temp_file(f_path)

    def _cleanup_temp_file(self, f_path: str) -> None:
        """Clean up temporary validation file."""
        try:
            if os.path.exists(f_path):
                os.remove(f_path)
        except OSError as e:
            logger.debug("Failed to cleanup temp file: %s", e)
