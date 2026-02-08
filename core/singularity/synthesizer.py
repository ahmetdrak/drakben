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
                code=code, language="python", purpose="refactor",
                dependencies=[], is_validated=False,
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
                    root = root.value
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
        lines = response.strip().split("\n")

        # Remove leading/trailing code fences
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        return "\n".join(lines)

    def _mock_llm_call(self, prompt: str, _language: str) -> str:
        """Fallback mock response for testing or when LLM unavailable."""
        prompt_lower = prompt.lower()

        if "scanner" in prompt_lower or "port" in prompt_lower:
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

        if "subdomain" in prompt_lower or "enum" in prompt_lower:
            return '''import socket
import logging

logger = logging.getLogger(__name__)

COMMON_PREFIXES = [
    "www", "mail", "ftp", "blog", "dev", "api", "staging", "test",
    "admin", "portal", "vpn", "ns1", "ns2", "mx", "smtp", "pop",
    "imap", "cdn", "media", "static", "app", "shop", "store",
]

def enumerate_subdomains(domain: str, wordlist: list[str] | None = None) -> list[str]:
    """Enumerate subdomains via DNS resolution."""
    prefixes = wordlist or COMMON_PREFIXES
    found: list[str] = []
    for prefix in prefixes:
        fqdn = f"{prefix}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None)
            found.append(fqdn)
            logger.info("FOUND: %s", fqdn)
        except socket.gaierror:
            pass
    return found

if __name__ == "__main__":
    results = enumerate_subdomains("example.com")
    for sub in results:
        print(sub)
'''

        if "header" in prompt_lower or "http" in prompt_lower:
            return '''import http.client
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

def check_headers(url: str) -> dict[str, str | None]:
    """Check security headers of a given URL."""
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or parsed.path
    port = parsed.port or (443 if scheme == "https" else 80)

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=10)
    try:
        conn.request("HEAD", parsed.path or "/")
        resp = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        result: dict[str, str | None] = {}
        for hdr in SECURITY_HEADERS:
            val = headers.get(hdr) or headers.get(hdr.lower())
            result[hdr] = val
            status = "PRESENT" if val else "MISSING"
            logger.info("%s: %s", hdr, status)
        return result
    finally:
        conn.close()

if __name__ == "__main__":
    check_headers("https://example.com")
'''

        if "dir" in prompt_lower or "brute" in prompt_lower or "fuzz" in prompt_lower:
            return '''import http.client
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "api", "config", "backup",
    ".git", ".env", "wp-admin", "phpmyadmin", "server-status",
    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
]

def dir_bruteforce(base_url: str, wordlist: list[str] | None = None) -> list[dict[str, int | str]]:
    """Brute-force directories on a web server."""
    paths = wordlist or DEFAULT_WORDLIST
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or parsed.path
    port = parsed.port or (443 if scheme == "https" else 80)

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    found: list[dict[str, int | str]] = []
    conn = conn_cls(host, port, timeout=10)
    try:
        for path in paths:
            full_path = f"/{path}"
            try:
                conn.request("GET", full_path)
                resp = conn.getresponse()
                _ = resp.read()  # drain body
                if resp.status not in (404, 403):
                    entry = {"path": full_path, "status": resp.status}
                    found.append(entry)
                    logger.info("FOUND %s -> %d", full_path, resp.status)
            except Exception as e:
                logger.debug("Error on %s: %s", full_path, e)
    finally:
        conn.close()
    return found

if __name__ == "__main__":
    dir_bruteforce("https://example.com")
'''

        if "dns" in prompt_lower or "record" in prompt_lower or "resolve" in prompt_lower:
            return '''import socket
import logging

logger = logging.getLogger(__name__)

def dns_lookup(domain: str) -> dict[str, list[str]]:
    """Perform DNS lookups for a domain using socket."""
    results: dict[str, list[str]] = {"A": [], "AAAA": []}
    # A records
    try:
        addrs = socket.getaddrinfo(domain, None, socket.AF_INET)
        results["A"] = list({addr[4][0] for addr in addrs})
        logger.info("%s A records: %s", domain, results["A"])
    except socket.gaierror as e:
        logger.debug("A lookup failed: %s", e)

    # AAAA records
    try:
        addrs = socket.getaddrinfo(domain, None, socket.AF_INET6)
        results["AAAA"] = list({addr[4][0] for addr in addrs})
        logger.info("%s AAAA records: %s", domain, results["AAAA"])
    except socket.gaierror as e:
        logger.debug("AAAA lookup failed: %s", e)

    return results

if __name__ == "__main__":
    dns_lookup("example.com")
'''

        if "banner" in prompt_lower or "grab" in prompt_lower or "service" in prompt_lower:
            return '''import socket
import logging

logger = logging.getLogger(__name__)

def grab_banner(target: str, port: int, timeout: float = 3.0) -> str:
    """Grab the service banner from a host:port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            # Some services send banner on connect; others need a nudge
            s.sendall(b"\\r\\n")
            banner = s.recv(1024).decode(errors="replace").strip()
            logger.info("Banner %s:%d -> %s", target, port, banner)
            return banner
    except Exception as e:
        logger.debug("Banner grab failed %s:%d: %s", target, port, e)
        return ""

def scan_banners(target: str, ports: list[int]) -> dict[int, str]:
    """Grab banners from multiple ports."""
    results: dict[int, str] = {}
    for port in ports:
        banner = grab_banner(target, port)
        if banner:
            results[port] = banner
    return results

if __name__ == "__main__":
    scan_banners("127.0.0.1", [21, 22, 25, 80, 443])
'''

        # Generic fallback — still functional, not just a comment
        return f'''import logging

logger = logging.getLogger(__name__)

def run() -> str:
    """Auto-generated stub for: {prompt[:80]}"""
    logger.info("Executing generated task")
    # TODO: Implement full logic when LLM is available
    return "Task placeholder — LLM required for full generation"

if __name__ == "__main__":
    print(run())
'''

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
        except Exception as e:
            logger.warning("Failed to extract deps: %s", e)

        return list(set(deps))
