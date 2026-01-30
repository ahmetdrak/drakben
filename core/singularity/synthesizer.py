"""
DRAKBEN Singularity - Code Synthesizer
Author: @drak_ben
Description: Generates functional code using LLM prompts and AST validation.
"""

import ast
import logging
from typing import List
from .base import ISynthesizer, CodeSnippet

logger = logging.getLogger(__name__)


class CodeSynthesizer(ISynthesizer):
    """
    Generates code specific to attack requirements.
    Uses Available LLM (via MCP or API) to write Python/Go/Bash tools.
    """

    def __init__(self, model: str = "gpt-4o"):
        self.model = model
        self.system_prompt = """
        You are Drakben's Code Architect. 
        Your goal is to write highly optimized, stealthy, and functional security tools.
        - Output ONLY pure code (Python, Bash, or Go).
        - No markdown formatting, no explanations.
        - Include error handling and logging.
        """
        logger.info(f"Synthesizer initialized (Target Model: {model})")

    def generate_tool(self, description: str, language: str = "python") -> CodeSnippet:
        """
        Generate a new tool based on description.

        Args:
            description: What the tool should do (e.g. "port scanner with banner grabbing")
            language: Target language

        Returns:
            CodeSnippet object
        """
        logger.info(f"Synthesizing tool: {description} ({language})")

        # 1. Construct Prompt
        prompt = f"Write a {language} script that performs: {description}"

        # 2. Call LLM (Placeholder for actual API call)
        # In a real scenario, this would call UniversalAdapter's LLM Client
        generated_code = self._mock_llm_call(prompt, language)

        # 3. Validate Syntax (Python only)
        if language.lower() == "python":
            if not self._validate_python_syntax(generated_code):
                logger.error("Generated code failed syntax check")
                return CodeSnippet(
                    code="# Syntax Error in generation",
                    language=language,
                    purpose=description,
                    dependencies=[],
                    is_validated=False,
                )

        # 4. Extract Dependencies (Basic parsing)
        deps = self._extract_dependencies(generated_code, language)

        return CodeSnippet(
            code=generated_code,
            language=language,
            purpose=description,
            dependencies=deps,
            is_validated=False,  # Needs Sandbox testing
        )

    def refactor_code(self, code: str) -> CodeSnippet:
        """Refactor code for performance or stealth"""
        # Placeholder for refactoring logic
        return CodeSnippet(
            code=code, language="python", purpose="refactor", dependencies=[]
        )

    def _mock_llm_call(self, prompt: str, _language: str) -> str:
        """Simulate LLM response for testing"""
        if "scanner" in prompt:
            return """
import socket
import sys

def scan(target, ports):
    print(f"Scanning {target}...")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"Port {port}: OPEN")
            s.close()
        except Exception:
            pass

if __name__ == "__main__":
    scan("127.0.0.1", [80, 443, 22])
"""
        return f"# Placeholder code for: {prompt}"

    def _validate_python_syntax(self, code: str) -> bool:
        """Check if Python code is syntactically correct"""
        try:
            ast.parse(code)
            return True
        except SyntaxError as e:
            logger.error(f"Syntax Error: {e}")
            return False

    def _extract_dependencies(self, code: str, language: str) -> List[str]:
        """Extract imports/requirements"""
        if language == "python":
            return self._extract_python_deps(code)
        return []

    def _extract_python_deps(self, code: str) -> List[str]:
        """Helper to extract Python imports"""
        deps = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for n in node.names:
                        deps.append(n.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    deps.append(node.module.split(".")[0])
        except SyntaxError:
            pass
        except Exception as e:
            logger.warning(f"Failed to extract deps: {e}")

        return list(set(deps))
