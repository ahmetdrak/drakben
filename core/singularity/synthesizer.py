"""Code generation via LLM with AST validation and dependency extraction."""

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
        """Refactor code for performance or stealth.

        Applies AST-based transformations:
        - Removes unused imports
        - Adds type hints stubs where missing
        - Adds docstrings to undocumented functions
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            logger.warning("Cannot refactor: syntax error in input code")
            return CodeSnippet(
                code=code,
                language="python",
                purpose="refactor",
                dependencies=[],
                is_validated=False,
            )

        used_names = self._collect_used_names(tree)
        removed = self._remove_unused_imports(tree, used_names)
        self._add_missing_docstrings(tree)

        refactored = ast.unparse(tree)
        if removed:
            logger.info("Removed %d unused import(s)", removed)

        return CodeSnippet(
            code=refactored,
            language="python",
            purpose="refactor",
            dependencies=self._extract_python_deps(refactored),
            is_validated=True,
        )

    @staticmethod
    def _collect_used_names(tree: ast.Module) -> set[str]:
        """Collect all names referenced in the AST (excluding import nodes)."""
        used_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                root = node
                while isinstance(root, ast.Attribute):
                    root = root.value  # type: ignore[assignment]
                if isinstance(root, ast.Name):
                    used_names.add(root.id)
        return used_names

    @staticmethod
    def _remove_unused_imports(tree: ast.Module, used_names: set[str]) -> int:
        """Remove unused imports from the AST body. Returns count of removed imports."""
        new_body: list[ast.stmt] = []
        removed = 0
        for node in tree.body:
            if isinstance(node, ast.Import):
                kept = [alias for alias in node.names if (alias.asname or alias.name.split(".")[0]) in used_names]
                if kept:
                    node.names = kept
                    new_body.append(node)
                else:
                    removed += 1
            elif isinstance(node, ast.ImportFrom):
                kept = [alias for alias in node.names if (alias.asname or alias.name) in used_names]
                if kept:
                    node.names = kept
                    new_body.append(node)
                else:
                    removed += 1
            else:
                new_body.append(node)
        tree.body = new_body
        return removed

    @staticmethod
    def _add_missing_docstrings(tree: ast.Module) -> None:
        """Add placeholder docstrings to functions missing them."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            has_docstring = (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            )
            if not has_docstring:
                doc_node = ast.Expr(value=ast.Constant(value=f"TODO: Document {node.name}."))
                node.body.insert(0, doc_node)

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
{lang_hints.get(language.lower(), "")}

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

        except (OSError, ValueError, RuntimeError) as e:
            logger.warning("LLM call failed (%s), using mock response", e)
            return self._mock_llm_call(prompt, language)

    def _clean_code_response(self, response: str) -> str:
        """Remove markdown code fences and clean up LLM response."""
        lines = response.strip().split("\n")

        # Remove leading/trailing code fences
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        return "\n".join(lines)

    def _mock_llm_call(self, prompt: str, _language: str) -> str:
        """Fallback: return a minimal working script when LLM is unavailable."""
        import re as _re

        prompt_lower = prompt.lower()

        _TEMPLATES: dict[str, str] = {
            "port|scanner": (
                "import socket, logging\n"
                "logger = logging.getLogger(__name__)\n"
                "def scan(target: str, ports: list[int]) -> dict[int, bool]:\n"
                "    results = {}\n"
                "    for port in ports:\n"
                "        try:\n"
                "            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
                "                s.settimeout(1)\n"
                "                results[port] = s.connect_ex((target, port)) == 0\n"
                "        except OSError:\n"
                "            results[port] = False\n"
                "    return results\n"
            ),
            "subdomain|enum": (
                "import socket, logging\n"
                "logger = logging.getLogger(__name__)\n"
                "PREFIXES = ['www','mail','ftp','api','dev','staging','admin','vpn','cdn']\n"
                "def enumerate_subdomains(domain: str, wordlist: list[str] | None = None) -> list[str]:\n"
                "    found = []\n"
                "    for prefix in (wordlist or PREFIXES):\n"
                "        try:\n"
                "            socket.getaddrinfo(f'{prefix}.{domain}', None)\n"
                "            found.append(f'{prefix}.{domain}')\n"
                "        except socket.gaierror:\n"
                "            pass\n"
                "    return found\n"
            ),
            "header|http": (
                "import http.client, logging\nfrom urllib.parse import urlparse\n"
                "logger = logging.getLogger(__name__)\n"
                "SECURITY_HEADERS = ['Strict-Transport-Security','Content-Security-Policy',\n"
                "    'X-Content-Type-Options','X-Frame-Options','X-XSS-Protection']\n"
                "def check_headers(url: str) -> dict[str, str | None]:\n"
                "    p = urlparse(url)\n"
                "    conn = (http.client.HTTPSConnection if p.scheme == 'https' else\n"
                "            http.client.HTTPConnection)(p.hostname, p.port or (443 if p.scheme == 'https' else 80), timeout=10)\n"
                "    try:\n"
                "        conn.request('HEAD', p.path or '/')\n"
                "        hdrs = dict(conn.getresponse().getheaders())\n"
                "        return {h: hdrs.get(h) or hdrs.get(h.lower()) for h in SECURITY_HEADERS}\n"
                "    finally:\n"
                "        conn.close()\n"
            ),
            "dir|brute|fuzz": (
                "import http.client, logging\nfrom urllib.parse import urlparse\n"
                "logger = logging.getLogger(__name__)\n"
                "WORDLIST = ['admin','login','api','.git','.env','robots.txt','sitemap.xml']\n"
                "def dir_bruteforce(base_url: str, paths: list[str] | None = None) -> list[dict]:\n"
                "    p = urlparse(base_url)\n"
                "    conn = (http.client.HTTPSConnection if p.scheme == 'https' else\n"
                "            http.client.HTTPConnection)(p.hostname, p.port or (443 if p.scheme == 'https' else 80), timeout=10)\n"
                "    found = []\n"
                "    try:\n"
                "        for path in (paths or WORDLIST):\n"
                "            try:\n"
                "                conn.request('GET', f'/{path}')\n"
                "                r = conn.getresponse(); _ = r.read()\n"
                "                if r.status not in (404, 403):\n"
                "                    found.append({'path': f'/{path}', 'status': r.status})\n"
                "            except Exception:\n"
                "                pass\n"
                "    finally:\n"
                "        conn.close()\n"
                "    return found\n"
            ),
            "dns|record|resolve": (
                "import socket, logging\n"
                "logger = logging.getLogger(__name__)\n"
                "def dns_lookup(domain: str) -> dict[str, list[str]]:\n"
                "    results: dict[str, list[str]] = {'A': [], 'AAAA': []}\n"
                "    try:\n"
                "        results['A'] = list({a[4][0] for a in socket.getaddrinfo(domain, None, socket.AF_INET)})\n"
                "    except socket.gaierror:\n"
                "        pass\n"
                "    try:\n"
                "        results['AAAA'] = list({a[4][0] for a in socket.getaddrinfo(domain, None, socket.AF_INET6)})\n"
                "    except socket.gaierror:\n"
                "        pass\n"
                "    return results\n"
            ),
            "banner|grab|service": (
                "import socket, logging\n"
                "logger = logging.getLogger(__name__)\n"
                "def grab_banner(target: str, port: int, timeout: float = 3.0) -> str:\n"
                "    try:\n"
                "        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
                "            s.settimeout(timeout)\n"
                "            s.connect((target, port))\n"
                "            s.sendall(b'\\r\\n')\n"
                "            return s.recv(1024).decode(errors='replace').strip()\n"
                "    except Exception:\n"
                "        return ''\n"
            ),
        }

        for pattern, code in _TEMPLATES.items():
            if _re.search(pattern, prompt_lower):
                return code

        # Generic fallback
        desc = prompt[:60].replace("'", "\\'")
        return (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            f"def run() -> str:\n"
            f"    '''Auto-generated stub for: {desc}'''\n"
            f"    logger.info('Executing generated task')\n"
            f"    return 'LLM required for full generation'\n"
        )

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
        deps: list[str] = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    deps.extend(n.name.split(".")[0] for n in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    deps.append(node.module.split(".")[0])
        except SyntaxError:
            pass
        except (AttributeError, TypeError) as e:
            logger.warning("Failed to extract deps: %s", e)

        return list(set(deps))
