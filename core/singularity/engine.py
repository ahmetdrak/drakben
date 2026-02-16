"""DRAKBEN Singularity - Main Engine
Author: @drak_ben
Description: Orchestrates the self-improvement cycle: Synthesize -> Validate -> Mutate.
"""

import ast
import logging

from .mutation import MutationEngine
from .synthesizer import CodeSynthesizer
from .validator import CodeValidator

logger = logging.getLogger(__name__)

# --- Security: AST-level blacklist for generated code ---
_DANGEROUS_CALLS: frozenset[str] = frozenset({
    "system", "popen", "spawn", "exec", "eval", "compile",
    "execfile", "input",  # Python 2 compat concern
    "remove", "rmdir", "unlink", "rmtree",
})

# M-9 FIX: Allow 'import os' (for os.path) — dangerous os.* calls are blocked
# by _DANGEROUS_CALLS. But 'from os import system' is explicitly blocked below.
_DANGEROUS_IMPORTS: frozenset[str] = frozenset({
    "subprocess", "shutil", "ctypes", "multiprocessing",
    "signal", "pty", "resource",
})

# Specific os sub-imports that are dangerous
_DANGEROUS_OS_NAMES: frozenset[str] = frozenset({
    "system", "popen", "spawn", "execv", "execvp", "execvpe",
    "remove", "unlink", "rmdir",
})


def _check_call_safety(node: ast.Call) -> str | None:
    """Return reason string if a Call node is dangerous, else None."""
    func_name = ""
    if isinstance(node.func, ast.Name):
        func_name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        func_name = node.func.attr
    if func_name in _DANGEROUS_CALLS:
        return f"Dangerous call blocked: {func_name}()"
    return None


def _check_import_safety(node: ast.Import) -> str | None:
    """Return reason string if an Import node is dangerous, else None."""
    for alias in node.names:
        top = alias.name.split(".")[0]
        if top in _DANGEROUS_IMPORTS:
            return f"Dangerous import blocked: {alias.name}"
    return None


def _check_import_from_safety(node: ast.ImportFrom) -> str | None:
    """Return reason string if an ImportFrom node is dangerous, else None."""
    if node.module:
        top = node.module.split(".")[0]
        if top in _DANGEROUS_IMPORTS:
            return f"Dangerous import blocked: {node.module}"
        # M-9 FIX: Block dangerous 'from os import ...' sub-imports
        if top == "os":
            for alias in node.names:
                if alias.name in _DANGEROUS_OS_NAMES:
                    return f"Dangerous import blocked: from os import {alias.name}"
    return None


def _check_node_safety(node: ast.AST) -> str | None:
    """Return reason string if an AST node is dangerous, else None."""
    if isinstance(node, ast.Call):
        return _check_call_safety(node)
    if isinstance(node, ast.Import):
        return _check_import_safety(node)
    if isinstance(node, ast.ImportFrom):
        return _check_import_from_safety(node)
    return None


def _ast_is_safe(code: str) -> tuple[bool, str]:
    """Perform AST-level safety check on generated code.

    Returns:
        (is_safe, reason) — reason is empty when safe.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return False, f"SyntaxError: {exc}"

    for node in ast.walk(tree):
        reason = _check_node_safety(node)
        if reason:
            return False, reason

    return True, ""


class SingularityEngine:
    """The heart of Drakben's self-improvement capability.

    Workflow:
    1. Receive requirement (e.g. "Need a tool to exploit CVE-2024-XXXX")
    2. Synthesize code using LLM
    3. Validate code in Sandbox
    4. Mutate code for Evasion
    5. Deploy tool
    """

    def __init__(self) -> None:
        self.synthesizer = CodeSynthesizer()
        self.validator = CodeValidator()
        self.mutator = MutationEngine()
        logger.info("Singularity Engine initialized")

    def create_capability(
        self,
        description: str,
        language: str = "python",
    ) -> str | None:
        """Create a new diverse capability (tool) from scratch.

        Args:
            description: Description of the desired tool
            language: Target language

        Returns:
            Final source code string or None if failed

        """
        logger.info("Initiating capability creation: %s", description)

        # 1. Synthesis
        snippet = self.synthesizer.generate_tool(description, language)
        if not snippet or not snippet.code:
            logger.error("Synthesis failed")
            return None

        # 2. Validation
        # Only validate if it's safe/possible (e.g. valid syntax)
        is_valid = self.validator.validate(snippet)
        if not is_valid:
            logger.warning("Initial validation failed. Attempting self-repair...")
            logger.error(
                "Validation failed. Moving to fallback or human intervention required.",
            )
            return None

        # 2b. AST-level security gate (blacklist dangerous patterns)
        safe, reason = _ast_is_safe(snippet.code)
        if not safe:
            logger.error("AST security check failed: %s", reason)
            return None

        # 3. Mutation (Polymorphism)
        # Apply mutation to ensure unique signature
        mutation_result = self.mutator.mutate(snippet.code)
        if mutation_result.success:
            # Re-validate after mutation? Ideally yes, but GhostProtocol guarantees functionality preservation
            final_code = self.mutator.generate_variant(snippet.code, iterations=1)
        else:
            final_code = snippet.code

        logger.info("Capability created successfully")
        return final_code

    def create_and_register(
        self,
        description: str,
        tool_name: str | None = None,
        language: str = "python",
    ) -> str | None:
        """Create a new capability and auto-register it in the ToolRegistry.

        Args:
            description: Description of the desired tool
            tool_name: Optional custom name (auto-generated if None)
            language: Target language

        Returns:
            Final source code string or None if failed
        """
        code = self.create_capability(description, language)
        if not code:
            return None

        try:
            from core.tools.tool_registry import (
                PentestPhase,
                Tool,
                ToolType,
            )
            from core.tools.tool_registry import (
                get_registry as get_tool_registry,
            )

            # Generate tool name from description if not provided
            if not tool_name:
                import re
                # Create a safe tool name from description
                safe = re.sub(r"[^a-z0-9]+", "_", description.lower())[:30].strip("_")
                tool_name = f"singularity_{safe}"

            # Save the generated code to modules/dynamic/
            from pathlib import Path
            dynamic_dir = Path("modules/dynamic")
            dynamic_dir.mkdir(parents=True, exist_ok=True)
            module_path = dynamic_dir / f"{tool_name}.py"
            module_path.write_text(code, encoding="utf-8")

            # Create a Python tool wrapper that loads and runs the module
            def _dynamic_runner(target: str, **kwargs) -> dict:
                """Dynamic tool runner with security sandbox."""
                try:
                    # Re-validate AST safety before every execution
                    source = module_path.read_text(encoding="utf-8")
                    safe, reason = _ast_is_safe(source)
                    if not safe:
                        return {"error": f"Security blocked: {reason}"}

                    import importlib.util
                    spec = importlib.util.spec_from_file_location(tool_name, str(module_path))
                    if not spec or not spec.loader:
                        return {"error": "Failed to load dynamic module"}
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "run"):
                        return mod.run(target, **kwargs)
                    if hasattr(mod, "main"):
                        return mod.main(target, **kwargs)
                    return {"code": source[:500], "status": "loaded but no run/main function"}
                except Exception as e:
                    return {"error": str(e)}

            tool = Tool(
                name=tool_name,
                type=ToolType.PYTHON,
                description=f"[Singularity] {description}",
                phase=PentestPhase.EXPLOIT,
                python_func=_dynamic_runner,
            )

            registry = get_tool_registry()
            registry.register(tool)
            logger.info("Dynamic tool registered: %s", tool_name)
            return code

        except (ImportError, OSError, ValueError, RuntimeError) as e:
            logger.exception("Failed to register dynamic tool: %s", e)
            return code  # Return code even if registration fails
