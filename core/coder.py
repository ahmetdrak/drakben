# core/coder.py
# DRAKBEN Self-Coding Module - FULLY INTEGRATED
# Agent writes its own code when tool not found or fails
# Enhanced: AST-based security check, logging, better validation

import ast
from importlib.machinery import ModuleSpec
import importlib.util
import logging
import time
from pathlib import Path

from types import ModuleType
from typing import Any, Dict, List, Optional

from core.llm_utils import format_llm_prompt

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)

DYNAMIC_MODULES_PATH = Path("modules/dynamic")


class SecurityViolation(Exception):
    """Raised when generated code fails security check"""

    pass


class ASTSecurityChecker(ast.NodeVisitor):
    """
    AST-based security checker for generated code.
    Analyzes the Abstract Syntax Tree to detect dangerous patterns.
    """

    # Dangerous function names that should never be called
    DANGEROUS_FUNCTIONS: set[str] = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "delattr",  # Can be used for attribute manipulation
        "globals",
        "locals",  # Scope manipulation
        "open",  # File operations (checked separately with context)
    }

    # Dangerous module imports
    DANGEROUS_IMPORTS: set[str] = {
        "ctypes",  # Low-level memory manipulation
        "pickle",  # Arbitrary code execution
        "marshal",  # Code object manipulation
        "code",  # Code object manipulation
        "codeop",  # Code compilation
    }

    # Restricted module.function combinations
    RESTRICTED_CALLS: set[tuple[str, str]] = {
        ("os", "system"),
        ("os", "popen"),
        ("os", "spawn"),
        ("os", "spawnl"),
        ("os", "spawnle"),
        ("os", "spawnlp"),
        ("os", "spawnlpe"),
        ("os", "spawnv"),
        ("os", "spawnve"),
        ("os", "spawnvp"),
        ("os", "spawnvpe"),
        ("os", "execl"),
        ("os", "execle"),
        ("os", "execlp"),
        ("os", "execlpe"),
        ("os", "execv"),
        ("os", "execve"),
        ("os", "execvp"),
        ("os", "execvpe"),
        ("os", "remove"),
        ("os", "unlink"),
        ("os", "rmdir"),
        ("subprocess", "call"),
        ("subprocess", "run"),
        ("subprocess", "Popen"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("shutil", "rmtree"),
        ("shutil", "move"),
        ("shutil", "copy"),
        ("shutil", "copy2"),
        ("builtins", "eval"),
        ("builtins", "exec"),
    }

    # Allowed subprocess calls for security tools (with strict conditions)
    ALLOWED_SUBPROCESS_FOR_TOOLS: set[str] = {
        "nmap",
        "nikto",
        "gobuster",
        "sqlmap",
        "whatweb",
        "curl",
        "wget",
    }

    # Dangerous file paths
    DANGEROUS_PATHS: set[str] = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/",
        "/home/",
        "~/",
        "C:\\Windows\\System32",
        "C:\\Windows\\System",
    }

    def __init__(self, allow_subprocess_tools: bool = False) -> None:
        self.violations: List[str] = []
        self.imported_modules: Dict[str, str] = {}  # alias -> module name
        self.allow_subprocess_tools: bool = allow_subprocess_tools

    def check(self, code: str) -> List[str]:
        """
        Check code for security violations.

        Args:
            code: Python source code

        Returns:
            List of violation descriptions
        """
        self.violations = []
        self.imported_modules = {}

        try:
            tree: ast.Module = ast.parse(code)
            self.visit(tree)
        except SyntaxError as e:
            self.violations.append(f"Syntax error: {e}")

        return self.violations

    def visit_Import(self, node: ast.Import) -> None:
        """Check import statements"""
        for alias in node.names:
            module_name: str = alias.name.split(".")[0]
            import_alias: str = alias.asname or alias.name
            self.imported_modules[import_alias] = module_name

            if module_name in self.DANGEROUS_IMPORTS:
                self.violations.append(f"Dangerous import: {module_name}")

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Check from ... import statements"""
        if node.module:
            module_name: str = node.module.split(".")[0]

            if module_name in self.DANGEROUS_IMPORTS:
                self.violations.append(f"Dangerous import from: {module_name}")

            for alias in node.names:
                import_alias: str = alias.asname or alias.name
                self.imported_modules[import_alias] = module_name

                # Check specific function imports
                if (module_name, alias.name) in self.RESTRICTED_CALLS:
                    self.violations.append(
                        f"Restricted function import: {module_name}.{alias.name}"
                    )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls"""
        func_name: str | None = self._get_call_name(node)

        if func_name:
            if func_name in self.DANGEROUS_FUNCTIONS:
                self._handle_dangerous_function(node, func_name)
            elif "." in func_name:
                self._handle_module_function(node, func_name)

        self.generic_visit(node)

    def _handle_dangerous_function(self, node: ast.Call, func_name: str) -> None:
        """Handle calls to known dangerous functions"""
        if func_name == "open":
            # open() is allowed with safe paths
            self._check_open_call(node)
        else:
            self.violations.append(f"Dangerous function call: {func_name}")

    def _handle_module_function(self, node: ast.Call, func_name: str) -> None:
        """Handle calls to module functions"""
        parts: List[str] = func_name.split(".")
        if len(parts) >= 2:
            module_alias: str = parts[0]
            func: str = parts[1]

            # Resolve module alias
            module_name: str = self.imported_modules.get(module_alias, module_alias)

            if (module_name, func) in self.RESTRICTED_CALLS:
                self._check_restricted_call(node, module_name, func)

    def _check_restricted_call(
        self, node: ast.Call, module_name: str, func: str
    ) -> None:
        """Check if a restricted call is allowed under specific conditions"""
        # Allow subprocess for specific security tools
        if module_name == "subprocess" and self.allow_subprocess_tools:
            if not self._is_allowed_subprocess_call(node):
                self.violations.append("Subprocess call with non-whitelisted command")
        else:
            self.violations.append(f"Restricted call: {module_name}.{func}")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Check attribute access for dangerous patterns"""
        # Check for __class__, __bases__, __mro__ etc.
        if node.attr.startswith("__") and node.attr.endswith("__"):
            if node.attr not in (
                "__init__",
                "__name__",
                "__doc__",
                "__str__",
                "__repr__",
            ):
                self.violations.append(f"Suspicious dunder access: {node.attr}")

        self.generic_visit(node)

    # NOTE: visit_Str removed - was deprecated in Python 3.8, removed in 3.14
    # All string literals are now handled by visit_Constant (Python 3.8+)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Check constant values for dangerous paths (Python 3.8+)"""
        if isinstance(node.value, str):
            self._check_dangerous_path(node.value)
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from Call node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current: ast.Attribute = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current: ast.expr = current.value  # type: ignore
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def _check_open_call(self, node: ast.Call) -> None:
        """Check if open() call is safe"""
        if node.args:
            first_arg: ast.expr = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                path: str = first_arg.value
                self._check_dangerous_path(path)
            elif isinstance(first_arg, ast.Str):
                self._check_dangerous_path(str(first_arg.s))

    def _check_dangerous_path(self, path: str) -> None:
        """Check if path is dangerous"""
        path_lower: str = path.lower()
        for dangerous in self.DANGEROUS_PATHS:
            if dangerous.lower() in path_lower:
                self.violations.append(f"Access to sensitive path: {path}")
                return

    def _is_allowed_subprocess_call(self, node: ast.Call) -> bool:
        """Check if subprocess call uses whitelisted tool AND forbids shell=True"""
        # BAN SHELL=TRUE
        for keyword in node.keywords:
            if keyword.arg == "shell":
                if (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    self.violations.append(
                        "Shell usage (shell=True) is FORBIDDEN in generated code"
                    )
                    return False

        if not node.args:
            return False

        first_arg: ast.expr = node.args[0]

        # Check if it's a list like ['nmap', '-p', ...]
        if isinstance(first_arg, ast.List) and first_arg.elts:
            first_element: ast.expr = first_arg.elts[0]
            if isinstance(first_element, ast.Constant):
                cmd: str = str(first_element.value).lower()
                return any(tool in cmd for tool in self.ALLOWED_SUBPROCESS_FOR_TOOLS)
            elif isinstance(first_element, ast.Str):
                cmd: str = str(first_element.s).lower()
                return any(tool in cmd for tool in self.ALLOWED_SUBPROCESS_FOR_TOOLS)

        # Check if it's a string like "nmap -p ..."
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            cmd: str = first_arg.value.lower()
            return any(tool in cmd for tool in self.ALLOWED_SUBPROCESS_FOR_TOOLS)
        elif isinstance(first_arg, ast.Str):
            cmd: str = str(getattr(first_arg, "s", "")).lower()
            return any(tool in cmd for tool in self.ALLOWED_SUBPROCESS_FOR_TOOLS)

        return False


class AICoder:
    """
    AI Self-Coding Module

    Ajan şu durumlarda yeni tool yazar:
    1. Mevcut tool'lar 3+ kez başarısız olduğunda
    2. İstenen işlev için tool bulunamadığında
    3. Planner alternatif tool bulamadığında
    """

    MAX_CREATED_TOOLS = 20  # Limit to prevent unbounded growth
    INIT_PY = "__init__.py"
    ERR_NO_LLM = "No LLM client available"
    ERR_SYNTAX = "Generated code has syntax errors"

    def __init__(self, brain) -> None:
        self.brain: Any = brain
        self.created_tools: List[str] = []
        self.security_checker = ASTSecurityChecker(allow_subprocess_tools=True)

        # Create directory if not exists
        if not DYNAMIC_MODULES_PATH.exists():
            DYNAMIC_MODULES_PATH.mkdir(parents=True)
            logger.info(f"Created dynamic modules directory: {DYNAMIC_MODULES_PATH}")

        # Create __init__.py if not exists
        init_file: Path = DYNAMIC_MODULES_PATH / self.INIT_PY
        if not init_file.exists():
            init_file.write_text("# Dynamic tools generated by AI\n")

    def should_create_tool(
        self, failed_tool: str, failure_count: int, action: str
    ) -> bool:
        """
        Should a new tool be created?

        Conditions:
        - Tool failed 3+ times
        - No alternative tool found
        - Tool not already written for this action
        - Max tool limit not exceeded
        """
        if failure_count < 3:
            return False

        # Max tool limit
        if len(self.created_tools) >= self.MAX_CREATED_TOOLS:
            logger.warning(
                f"Max created tools limit reached ({self.MAX_CREATED_TOOLS})"
            )
            return False

        # Did we already create a tool for this action?
        generated_name: str = f"auto_{action}_{failed_tool.replace('_', '')}"
        if generated_name in self.created_tools:
            return False

        logger.info(f"Tool creation approved for action: {action}")
        return True

    def create_alternative_tool(
        self, failed_tool: str, action: str, target: str, error_message: str
    ) -> Dict:
        """
        Write alternative for failed tool.

        Args:
            failed_tool: Başarısız olan tool adı
            action: Yapılmak istenen aksiyon (scan, exploit, etc.)
            target: Hedef
            error_message: Önceki hata mesajı

        Returns:
            {"success": bool, "tool_name": str, "file_path": str} veya {"success": False, "error": str}
        """
        logger.info(
            f"Creating alternative tool for failed: {failed_tool}, action: {action}"
        )

        tool_name: str = f"auto_{action}_{int(time.time()) % 10000}"

        # LLM'den kod iste
        system_msg = """You are an expert Python security tool developer.
Write a COMPLETE, WORKING Python script for the requested task.
The script MUST:
1. Have a function named 'run(target, args=None)'
2. Return a dict: {'success': bool, 'output': str, 'error': str or None}
3. Use ONLY standard library or requests (no heavy deps)
4. Handle all exceptions gracefully
5. Actually perform the security task (not a mock)
6. NOT use dangerous functions like eval(), exec(), os.system()

Output ONLY the Python code, no explanations."""

        user_msg: str = f"""The tool '{failed_tool}' failed with error: {error_message}

Create an ALTERNATIVE tool that performs: {action}
Target: {target}

Requirements:
- Must work without requiring external tools (pure Python)
- If it's a scan: use socket library
- If it's web-related: use requests or urllib
- If it's exploit: be careful and require confirmation
- Do NOT use os.system(), subprocess.call(), eval(), or exec()

Structure:
```python
import socket
# other imports...

def run(target, args=None):
    try:
        # Your implementation
        result = "..."
        return {{"success": True, "output": result, "error": None}}
    except Exception as e:
        return {{"success": False, "output": "", "error": str(e)}}
```
"""

        try:
            # Fail if no LLM available
            if not self.brain or not self.brain.llm_client:
                logger.warning(self.ERR_NO_LLM)
                return {"success": False, "error": self.ERR_NO_LLM}

            prompt: str = format_llm_prompt(system_msg, user_msg)
            response = self.brain.llm_client.query(prompt)
            code: str = self._extract_code(response)

            if not code:
                logger.warning("No code generated by LLM")
                return {"success": False, "error": "No code generated by LLM"}

            # Syntax check
            if not self._validate_syntax(code):
                logger.warning(self.ERR_SYNTAX)
                return {"success": False, "error": self.ERR_SYNTAX}

            # AST-based security check
            security_result: Dict[str, Any] = self._security_check_ast(code)
            if not security_result["safe"]:
                logger.warning(
                    f"Security check failed: {security_result['violations']}"
                )
                return {
                    "success": False,
                    "error": f"Security check failed: {', '.join(security_result['violations'])}",
                }

            # Save to file
            file_path: Path = DYNAMIC_MODULES_PATH / f"{tool_name}.py"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"# Auto-generated tool for: {action}\n")
                f.write(f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Alternative for failed tool: {failed_tool}\n\n")
                f.write(code)

            self.created_tools.append(tool_name)
            logger.info(f"Successfully created tool: {tool_name}")

            return {
                "success": True,
                "tool_name": tool_name,
                "file_path": str(file_path),
                "module_name": f"modules.dynamic.{tool_name}",
            }

        except Exception as e:
            logger.exception(f"Tool creation failed: {e}")
            return {"success": False, "error": str(e)}

    def create_tool(self, tool_name: str, description: str, requirements: str) -> Dict:
        """
        Manual tool creation (legacy method, for backward compatibility)
        """
        logger.info(f"Creating tool: {tool_name}")

        system_msg = """You are an expert Python Security Tool Developer.
You must write a complete, standalone Python script that performs the requested security task.
The script must function as a standalone module with a main function named 'run(target, args)'.
It must return a dictionary: {'success': bool, 'output': str, 'error': str}.
Do not use external heavy libraries if possible, stick to standard library or requests/scapy.
Do NOT use dangerous functions like eval(), exec(), os.system().
Output ONLY the Python code block."""

        user_msg: str = f"""Create a tool named '{tool_name}'.
Description: {description}
Requirements: {requirements}

Structure your code like this:
```python
import sys
# imports...

def run(target, args=None):
    # logic here...
    return {{"success": True, "output": "...", "error": None}}
```
"""

        try:
            if not self.brain or not self.brain.llm_client:
                logger.warning(self.ERR_NO_LLM)
                return {"success": False, "error": self.ERR_NO_LLM}

            prompt: str = format_llm_prompt(system_msg, user_msg)
            response = self.brain.llm_client.query(prompt)
            code: str = self._extract_code(response)

            if not code:
                return {"success": False, "error": "No code generated"}

            if not self._validate_syntax(code):
                return {"success": False, "error": self.ERR_SYNTAX}

            security_result: Dict[str, Any] = self._security_check_ast(code)
            if not security_result["safe"]:
                return {
                    "success": False,
                    "error": f"Security check failed: {', '.join(security_result['violations'])}",
                }

            file_path: Path = DYNAMIC_MODULES_PATH / f"{tool_name}.py"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)

            self.created_tools.append(tool_name)
            logger.info(f"Successfully created tool: {tool_name}")

            return {
                "success": True,
                "file_path": str(file_path),
                "module_name": f"modules.dynamic.{tool_name}",
            }

        except Exception as e:
            logger.exception(f"Tool creation failed: {e}")
            return {"success": False, "error": str(e)}

    def _extract_code(self, response: str) -> str:
        """Markdown code block içinden kodu çıkar"""
        if "```python" in response:
            start: int = response.find("```python") + 9
            end: int = response.find("```", start)
            return response[start:end].strip()
        elif "```" in response:
            start: int = response.find("```") + 3
            end: int = response.find("```", start)
            return response[start:end].strip()
        return response.strip()

    def _validate_syntax(self, code: str) -> bool:
        """Python syntax kontrolü"""
        try:
            ast.parse(code)
            return True
        except SyntaxError as e:
            logger.warning(f"Syntax error in generated code: {e}")
            return False

    def _security_check_ast(self, code: str) -> Dict[str, Any]:
        """
        AST-based güvenlik kontrolü.
        Pattern matching yerine AST analizi yapar.

        Returns:
            {"safe": bool, "violations": List[str]}
        """
        violations: List[str] = self.security_checker.check(code)

        return {"safe": len(violations) == 0, "violations": violations}

    def _security_check(self, code: str) -> bool:
        """
        Legacy basit güvenlik kontrolü (geriye uyumluluk için).
        Yeni kodda _security_check_ast kullanılıyor.
        """
        result: Dict[str, Any] = self._security_check_ast(code)
        return result["safe"]

    def load_dynamic_tool(self, module_name: str) -> Optional[Any]:
        """Dinamik modülü yükle ve çalıştırmaya hazır hale getir"""
        logger.debug(f"Loading dynamic tool: {module_name}")

        try:
            # modules.dynamic.tool_name -> modules/dynamic/tool_name.py
            parts: List[str] = module_name.split(".")
            if len(parts) >= 3:
                file_path: Path = DYNAMIC_MODULES_PATH / f"{parts[-1]}.py"
            else:
                file_path: Path = DYNAMIC_MODULES_PATH / f"{module_name}.py"

            if not file_path.exists():
                logger.warning(f"Dynamic module not found: {file_path}")
                return None

            spec: ModuleSpec | None = importlib.util.spec_from_file_location(
                module_name, file_path
            )
            if spec is None or spec.loader is None:
                logger.warning(f"Could not create spec for module: {module_name}")
                return None

            module: ModuleType = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            logger.info(f"Successfully loaded dynamic tool: {module_name}")
            return module

        except Exception as e:
            logger.exception(f"Error loading dynamic module {module_name}: {e}")
            return None

    def execute_dynamic_tool(
        self, tool_name: str, target: str, args: Optional[Dict[Any, Any]] = None
    ) -> Dict:
        """Dinamik tool'u çalıştır"""
        logger.info(f"Executing dynamic tool: {tool_name} on {target}")

        module_name: str = f"modules.dynamic.{tool_name}"
        module: Any | None = self.load_dynamic_tool(module_name)

        if module is None:
            return {
                "success": False,
                "output": "",
                "error": f"Could not load module {tool_name}",
            }

        if not hasattr(module, "run"):
            logger.error(f"Module {tool_name} has no 'run' function")
            return {
                "success": False,
                "output": "",
                "error": f"Module {tool_name} has no 'run' function",
            }

        try:
            result = module.run(target, args)
            logger.info(
                f"Dynamic tool {tool_name} completed: success={result.get('success')}"
            )
            return result
        except Exception as e:
            logger.exception(f"Dynamic tool execution failed: {e}")
            return {"success": False, "output": "", "error": str(e)}

    def list_dynamic_tools(self) -> List[str]:
        """Oluşturulmuş tüm dinamik tool'ları listele"""
        tools = []
        if DYNAMIC_MODULES_PATH.exists():
            for f in DYNAMIC_MODULES_PATH.glob("*.py"):
                if f.name != self.INIT_PY:
                    tools.append(f.stem)
        logger.debug(f"Found {len(tools)} dynamic tools")
        return tools

    def cleanup_old_tools(self, max_age_hours: int = 24) -> None:
        """
        Eski dinamik tool'ları temizle.

        Args:
            max_age_hours: Maximum age in hours before deletion
        """
        logger.info(f"Cleaning up tools older than {max_age_hours} hours")

        if not DYNAMIC_MODULES_PATH.exists():
            return

        current_time: float = time.time()
        max_age_seconds: int = max_age_hours * 3600

        for f in DYNAMIC_MODULES_PATH.glob("*.py"):
            if f.name == self.INIT_PY:
                continue

            file_age: float = current_time - f.stat().st_mtime
            if file_age > max_age_seconds:
                try:
                    f.unlink()
                    if f.stem in self.created_tools:
                        self.created_tools.remove(f.stem)
                    logger.info(f"Deleted old tool: {f.name}")
                except Exception as e:
                    logger.warning(f"Could not delete {f.name}: {e}")
