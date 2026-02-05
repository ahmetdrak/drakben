"""DRAKBEN Singularity - Code Synthesizer
Author: @drak_ben
Description: Generates functional code using LLM prompts and AST validation.
"""

import ast
import logging
from typing import TYPE_CHECKING

from .base import CodeSnippet, ISynthesizer

if TYPE_CHECKING:
    from llm.openrouter_client import OpenRouterClient

logger = logging.getLogger(__name__)


class CodeSynthesizer(ISynthesizer):
    """Generates code specific to attack requirements.
    Uses Available LLM (via OpenRouter/Ollama/OpenAI) to write Python/Go/Bash tools.
    """

    def __init__(self, model: str = "meta-llama/llama-3.1-8b-instruct:free") -> None:
        self.model = model
        self._llm_client: OpenRouterClient | None = None
        self.system_prompt = """You are Drakben's Code Architect.
Your goal is to write highly optimized, stealthy, and functional security tools.
- Output ONLY pure code (Python, Bash, or Go).
- No markdown formatting, no explanations, no code fences.
- Include error handling and logging.
- Use modern Python idioms (type hints, f-strings, pathlib).
"""
        logger.info("Synthesizer initialized (Target Model: %s)", model)

    def generate_tool(self, description: str, language: str = "python") -> CodeSnippet:
        """Generate a new tool based on description.

        Args:
            description: What the tool should do (e.g. "port scanner with banner grabbing")
            language: Target language

        Returns:
            CodeSnippet object

        """
        logger.info("Synthesizing tool: %s (%s)", description, language)

        # 1. Construct Prompt
        prompt = f"Write a {language} script that performs: {description}"

        # 2. Call LLM (Real API call with fallback to mock)
        generated_code = self._call_llm(prompt, language)

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
        """Refactor code for performance or stealth."""
        # Placeholder for refactoring logic
        return CodeSnippet(
            code=code,
            language="python",
            purpose="refactor",
            dependencies=[],
        )

    def _get_llm_client(self) -> "OpenRouterClient":
        """Lazy-load LLM client to avoid circular imports."""
        if self._llm_client is None:
            from llm.openrouter_client import OpenRouterClient
            self._llm_client = OpenRouterClient(enable_cache=True)
        return self._llm_client

    def _call_llm(self, prompt: str, language: str) -> str:
        """Call LLM API to generate code.

        Falls back to mock response if LLM is unavailable.
        """
        try:
            client = self._get_llm_client()

            # Language-specific prompt enhancement
            lang_hints = {
                "python": "Use Python 3.10+ features (type hints, walrus operator, match-case if appropriate).",
                "bash": "Use modern bash (4.0+) with proper quoting and error handling.",
                "go": "Use Go 1.21+ with proper error handling and goroutines where appropriate.",
            }

            enhanced_prompt = f"""{prompt}

Language: {language}
{lang_hints.get(language.lower(), '')}

Remember: Output ONLY the code, no markdown, no explanations."""

            response = client.query(
                prompt=enhanced_prompt,
                system_prompt=self.system_prompt,
                timeout=30,
            )

            # Clean up response (remove markdown code fences if any)
            code = self._clean_code_response(response)

            if code and len(code) > 20:
                logger.info("LLM generated %d bytes of %s code", len(code), language)
                return code

            logger.warning("LLM returned empty/short response, using fallback")
            return self._mock_llm_call(prompt, language)

        except Exception as e:
            logger.warning("LLM call failed (%s), using mock response", e)
            return self._mock_llm_call(prompt, language)

    def _clean_code_response(self, response: str) -> str:
        """Remove markdown code fences and clean up LLM response."""
        lines = response.strip().split('\n')

        # Remove leading/trailing code fences
        if lines and lines[0].startswith('```'):
            lines = lines[1:]
        if lines and lines[-1].strip() == '```':
            lines = lines[:-1]

        return '\n'.join(lines)

    def _mock_llm_call(self, prompt: str, _language: str) -> str:
        """Fallback mock response for testing or when LLM unavailable."""
        if "scanner" in prompt.lower():
            return '''import socket
import logging

logger = logging.getLogger(__name__)

def scan(target: str, ports: list[int]) -> dict[int, bool]:
    """Scan target for open ports."""
    results = {}
    logger.info("Scanning %s...", target)

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                results[port] = (result == 0)
                if result == 0:
                    logger.info("Port %s: OPEN", port)
        except Exception as e:
            logger.debug("Port %s scan error: %s", port, e)
            results[port] = False

    return results

if __name__ == "__main__":
    scan("127.0.0.1", [80, 443, 22, 8080])
'''
        return f"# Placeholder code for: {prompt}"

    def _validate_python_syntax(self, code: str) -> bool:
        """Check if Python code is syntactically correct."""
        try:
            ast.parse(code)
            return True
        except SyntaxError as e:
            logger.exception("Syntax Error: %s", e)
            return False

    def _extract_dependencies(self, code: str, language: str) -> list[str]:
        """Extract imports/requirements."""
        if language == "python":
            return self._extract_python_deps(code)
        return []

    def _extract_python_deps(self, code: str) -> list[str]:
        """Helper to extract Python imports."""
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
            logger.warning("Failed to extract deps: %s", e)

        return list(set(deps))
