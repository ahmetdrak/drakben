"""DRAKBEN Universal Adapter - MCP Client & Dependency Resolver
Author: @drak_ben
Description: Model Context Protocol integration and automatic tool management.

This module provides:
- MCP (Model Context Protocol) client for LLM integration
- Automatic tool installation and dependency resolution
- REST API server for headless operation
- Plugin system interface
"""

import hashlib
import http.server
import json
import logging
import os
import platform
import shlex
import shutil
import socketserver
import subprocess
import threading
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

TOOLS_DIR = Path("tools")
CACHE_DIR = Path(".cache/drakben")

# Singleton instance
_universal_adapter: "UniversalAdapter | None" = None
_universal_adapter_lock = threading.Lock()


class PackageManager(Enum):
    """Supported package managers."""

    APT = "apt"
    YUM = "yum"
    DNF = "dnf"
    PACMAN = "pacman"
    BREW = "brew"
    CHOCO = "choco"
    PIP = "pip"
    NPM = "npm"
    GO = "go"
    CARGO = "cargo"


class ToolCategory(Enum):
    """Tool categories."""

    RECON = "recon"
    EXPLOIT = "exploit"
    POST = "post"
    UTILITY = "utility"
    NETWORK = "network"
    WEB = "web"
    CRYPTO = "crypto"


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class ToolDefinition:
    """Definition of a tool that can be installed."""

    name: str
    description: str
    category: ToolCategory
    check_command: str  # Command to check if installed
    install_commands: dict[str, str]  # Package manager -> command
    binary_name: str | None = None  # Name of main binary
    version_command: str = "--version"
    dependencies: list[str] = field(default_factory=list)
    url: str | None = None  # Download URL for manual install


@dataclass
class MCPTool:
    """MCP Tool definition for LLM integration."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable


@dataclass
class MCPResource:
    """MCP Resource definition."""

    uri: str
    name: str
    description: str
    mime_type: str = "text/plain"


# =============================================================================
# TOOL REGISTRY
# =============================================================================

TOOL_REGISTRY: dict[str, ToolDefinition] = {
    "nmap": ToolDefinition(
        name="nmap",
        description="Network exploration and security auditing",
        category=ToolCategory.RECON,
        check_command="nmap --version",
        install_commands={
            "apt": "sudo apt-get install -y nmap",
            "yum": "sudo yum install -y nmap",
            "dnf": "sudo dnf install -y nmap",
            "pacman": "sudo pacman -S --noconfirm nmap",
            "brew": "brew install nmap",
            "choco": "choco install nmap -y",
        },
        binary_name="nmap",
    ),
    "nikto": ToolDefinition(
        name="nikto",
        description="Web server scanner",
        category=ToolCategory.WEB,
        check_command="nikto -Version",
        install_commands={
            "apt": "sudo apt-get install -y nikto",
            "brew": "brew install nikto",
        },
        binary_name="nikto",
    ),
    "gobuster": ToolDefinition(
        name="gobuster",
        description="Directory/file & DNS busting tool",
        category=ToolCategory.WEB,
        check_command="gobuster version",
        install_commands={
            "apt": "sudo apt-get install -y gobuster",
            "go": "go install github.com/OJ/gobuster/v3@latest",
            "brew": "brew install gobuster",
        },
        binary_name="gobuster",
    ),
    "sqlmap": ToolDefinition(
        name="sqlmap",
        description="SQL injection automation tool",
        category=ToolCategory.EXPLOIT,
        check_command="sqlmap --version",
        install_commands={
            "apt": "sudo apt-get install -y sqlmap",
            "pip": "pip install sqlmap",
            "brew": "brew install sqlmap",
        },
        binary_name="sqlmap",
    ),
    "hydra": ToolDefinition(
        name="hydra",
        description="Password cracking tool",
        category=ToolCategory.EXPLOIT,
        check_command="hydra -V",
        install_commands={
            "apt": "sudo apt-get install -y hydra",
            "brew": "brew install hydra",
        },
        binary_name="hydra",
    ),
    "john": ToolDefinition(
        name="john",
        description="John the Ripper password cracker",
        category=ToolCategory.CRYPTO,
        check_command="john --version",
        install_commands={
            "apt": "sudo apt-get install -y john",
            "brew": "brew install john",
            "choco": "choco install john -y",
        },
        binary_name="john",
    ),
    "hashcat": ToolDefinition(
        name="hashcat",
        description="Advanced password recovery",
        category=ToolCategory.CRYPTO,
        check_command="hashcat --version",
        install_commands={
            "apt": "sudo apt-get install -y hashcat",
            "brew": "brew install hashcat",
        },
        binary_name="hashcat",
    ),
    "metasploit": ToolDefinition(
        name="metasploit",
        description="Penetration testing framework",
        category=ToolCategory.EXPLOIT,
        check_command="msfconsole -v",
        install_commands={
            "apt": "sudo apt-get install -y metasploit-framework",
        },
        binary_name="msfconsole",
        dependencies=["postgresql"],
    ),
    "impacket": ToolDefinition(
        name="impacket",
        description="Network protocol tools (psexec, secretsdump)",
        category=ToolCategory.POST,
        check_command="python -c 'import impacket'",
        install_commands={
            "pip": "pip install impacket",
        },
        binary_name="psexec.py",
    ),
    "ffuf": ToolDefinition(
        name="ffuf",
        description="Fast web fuzzer",
        category=ToolCategory.WEB,
        check_command="ffuf -V",
        install_commands={
            "apt": "sudo apt-get install -y ffuf",
            "go": "go install github.com/ffuf/ffuf@latest",
            "brew": "brew install ffuf",
        },
        binary_name="ffuf",
    ),
}

# =============================================================================
# DYNAMIC INSTALLER (SKILL ACQUISITION)
# =============================================================================


class DynamicInstaller:
    """Handles discovery and installation of tools not in the registry.
    Searches GitHub/PyPI and requires Explicit User Approval.
    """

    @staticmethod
    def search_tool(tool_name: str) -> dict[str, Any]:
        """Search for a tool on PyPI (safer/easier) and GitHub.
        Returns metadata about the potential tool.
        """
        # 1. Search PyPI (JSON API)
        try:
            url = f"https://pypi.org/pypi/{tool_name}/json"
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    info = data.get("info", {})
                    return {
                        "found": True,
                        "source": "pypi",
                        "name": info.get("name"),
                        "description": info.get("summary"),
                        "url": info.get("package_url"),
                        "version": info.get("version"),
                        "install_cmd": f"pip install {tool_name}",
                        "safety_score": "Unknown (Review Required)",
                    }
        except (OSError, ValueError) as e:
            logger.debug("PyPI search failed: %s", e)

        # 2. Search GitHub (Simulated for this environment without auth token)
        # In a real scenario, use GitHub API. Here we assume manual input or skip.
        # Fallback: Check if tool_name looks like a git URL
        if "github.com" in tool_name:
            return {
                "found": True,
                "source": "github",
                "name": tool_name.split("/")[-1].replace(".git", ""),
                "description": "Direct Git Repository",
                "url": tool_name,
                "version": "HEAD",
                "install_cmd": f"git clone {tool_name} tools/{tool_name.split('/')[-1].replace('.git', '')}",
                "safety_score": "Low (Untrusted Source)",
            }

        return {"found": False}


# =============================================================================
# DEPENDENCY RESOLVER
# =============================================================================


class DependencyResolver:
    """Automatic tool installation and dependency management.

    Features:
    - Detects system package manager
    - Installs missing tools
    - Manages isolated tool installations
    - Handles dependencies
    """

    def __init__(self, tools_dir: Path = TOOLS_DIR) -> None:
        """Initialize dependency resolver.

        Args:
            tools_dir: Directory for isolated tool installations

        """
        self.tools_dir = Path(tools_dir)
        self.tools_dir.mkdir(parents=True, exist_ok=True)

        self.system = platform.system().lower()
        self.package_manager = self._detect_package_manager()

        logger.info(
            f"DependencyResolver initialized (OS: {self.system}, PM: {self.package_manager})",
        )

    def _detect_package_manager(self) -> PackageManager | None:
        """Detect system package manager."""
        if self.system == "linux":
            # Check for various package managers
            if shutil.which("apt-get"):
                return PackageManager.APT
            if shutil.which("dnf"):
                return PackageManager.DNF
            if shutil.which("yum"):
                return PackageManager.YUM
            if shutil.which("pacman"):
                return PackageManager.PACMAN
        elif self.system == "darwin":
            if shutil.which("brew"):
                return PackageManager.BREW
        elif self.system == "windows" and shutil.which("choco"):
            return PackageManager.CHOCO

        return None

    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed.

        Args:
            tool_name: Name of the tool

        Returns:
            True if installed

        """
        tool_def = TOOL_REGISTRY.get(tool_name)

        if not tool_def:
            # Check if binary exists in PATH
            return shutil.which(tool_name) is not None

        try:
            result = subprocess.run(
                shlex.split(tool_def.check_command),
                shell=False,
                capture_output=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def get_tool_version(self, tool_name: str) -> str | None:
        """Get installed tool version.

        Args:
            tool_name: Name of the tool

        Returns:
            Version string or None

        """
        tool_def = TOOL_REGISTRY.get(tool_name)

        if not tool_def:
            return None

        try:
            binary = tool_def.binary_name or tool_name
            cmd = f"{binary} {tool_def.version_command}"
            result = subprocess.run(
                shlex.split(cmd),
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0:
                # Extract version from first line
                output = result.stdout.strip() or result.stderr.strip()
                return output.split("\n")[0][:50]
        except subprocess.SubprocessError as e:
            logger.debug("Version check failed: %s", e)

        return None

    def _install_via_package_manager(
        self,
        tool_name: str,
        install_commands: dict[str, str],
        result: dict[str, Any],
    ) -> bool:
        """Helper to install via system package manager."""
        if self.package_manager and self.package_manager.value in install_commands:
            cmd = install_commands[self.package_manager.value]
            result["method"] = self.package_manager.value

            try:
                logger.info("Installing %s via %s", tool_name, self.package_manager.value)
                proc = subprocess.run(
                    shlex.split(cmd),
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
                if proc.returncode == 0:
                    result["success"] = True
                    result["message"] = f"Installed {tool_name} via {self.package_manager.value}"
                else:
                    result["message"] = f"Installation failed: {proc.stderr[:200]}"
            except subprocess.TimeoutExpired:
                result["message"] = "Installation timed out"
            except (subprocess.SubprocessError, OSError) as e:
                result["message"] = str(e)
            return True
        return False

    def _install_via_pip(
        self,
        tool_name: str,
        install_commands: dict[str, str],
        result: dict[str, Any],
    ) -> bool:
        """Helper to install via pip."""
        if "pip" in install_commands:
            cmd = install_commands["pip"]
            result["method"] = "pip"

            try:
                proc = subprocess.run(
                    shlex.split(cmd),
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                result["success"] = proc.returncode == 0
                result["message"] = f"Installed {tool_name} via pip" if result["success"] else proc.stderr[:200]
            except (subprocess.SubprocessError, OSError) as e:
                result["message"] = str(e)
            return True
        return False

    def _handle_dynamic_discovery(self, tool_name: str, force: bool, result: dict) -> dict | None:
        """Handle dynamic tool discovery. Returns result if handled, None to continue."""
        discovery = DynamicInstaller.search_tool(tool_name)

        if not discovery["found"]:
            result["message"] = f"Unknown tool: {tool_name} (Not found in Registry or Public Sources)"
            return result

        if not force:
            result["success"] = False
            result["requires_approval"] = True
            result["proposal"] = discovery
            result["message"] = (
                f"Tool '{tool_name}' found on {discovery['source']}.\n"
                f"Description: {discovery['description']}\n"
                f"Command: {discovery['install_cmd']}\n"
                f"⚠️ APPROVAL REQUIRED: Re-run with force=True to install."
            )
            return result

        return self._execute_dynamic_install(discovery, result)

    def _execute_dynamic_install(self, discovery: dict, result: dict) -> dict:
        """Execute dynamic installation command."""
        result["message"] = f"Installing discovered tool: {discovery['name']}..."
        try:
            proc = subprocess.run(
                shlex.split(discovery["install_cmd"]),
                shell=False,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
            result["success"] = proc.returncode == 0
            result["message"] = (
                f"Dynamic Installation Success: {discovery['name']}"
                if result["success"]
                else f"Install Failed: {proc.stderr}"
            )
            result["method"] = discovery["source"]
        except (subprocess.SubprocessError, OSError) as e:
            result["message"] = f"Dynamic Install Error: {e}"
        return result

    def install_tool(self, tool_name: str, force: bool = False) -> dict[str, Any]:
        """Install a tool with reduced cognitive complexity."""
        result = {"tool": tool_name, "success": False, "message": "", "method": None}
        tool_def = TOOL_REGISTRY.get(tool_name)

        if not tool_def:
            logger.info("Tool '%s' not in registry. Initiating dynamic search...", tool_name)
            return self._handle_dynamic_discovery(tool_name, force, result) or result

        if not force and self.is_tool_installed(tool_name):
            result["success"] = True
            result["message"] = f"{tool_name} is already installed"
            return result

        # Install dependencies
        for dep in tool_def.dependencies:
            if not self.install_tool(dep)["success"]:
                result["message"] = f"Failed to install dependency: {dep}"
                return result

        # Try installation methods
        if self._install_via_package_manager(tool_name, tool_def.install_commands, result):
            return result
        if self._install_via_pip(tool_name, tool_def.install_commands, result):
            return result

        result["message"] = f"No installation method available for {tool_name} on {self.system}"
        return result

    def list_available_tools(self) -> list[dict[str, Any]]:
        """List all available tools in registry."""
        tools = []
        for name, tool_def in TOOL_REGISTRY.items():
            installed = self.is_tool_installed(name)
            tools.append(
                {
                    "name": name,
                    "description": tool_def.description,
                    "category": tool_def.category.value,
                    "installed": installed,
                    "version": self.get_tool_version(name) if installed else None,
                },
            )
        return tools

    def check_missing_tools(self, required: list[str]) -> list[str]:
        """Check which required tools are missing.

        Args:
            required: List of required tool names

        Returns:
            List of missing tool names

        """
        return [t for t in required if not self.is_tool_installed(t)]


# =============================================================================
# MCP CLIENT
# =============================================================================


class MCPClient:
    """Model Context Protocol client for LLM integration.

    Allows Drakben to:
    - Expose tools to LLMs (Claude, GPT, etc.)
    - Receive tool calls from LLMs
    - Provide resources and context

    Protocol: https://modelcontextprotocol.io/
    """

    def __init__(self, name: str = "drakben") -> None:
        """Initialize MCP client.

        Args:
            name: Client name for identification

        """
        self.name = name
        self.version = "1.0.0"
        self.tools: dict[str, MCPTool] = {}
        self.resources: dict[str, MCPResource] = {}

        # Register built-in tools
        self._register_builtin_tools()

        logger.info("MCP Client initialized (name: %s)", name)

    def _register_builtin_tools(self) -> None:
        """Register built-in Drakben tools for MCP."""
        # Scan tool
        self.register_tool(
            name="scan",
            description="Perform network reconnaissance scan on a target",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "stealth"],
                        "description": "Type of scan to perform",
                    },
                },
                "required": ["target"],
            },
            handler=self._handle_scan,
        )

        # Exploit tool
        self.register_tool(
            name="exploit",
            description="Attempt to exploit a vulnerability",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname",
                    },
                    "vulnerability": {
                        "type": "string",
                        "description": "CVE or vulnerability name",
                    },
                },
                "required": ["target", "vulnerability"],
            },
            handler=self._handle_exploit,
        )

        # Report tool
        self.register_tool(
            name="generate_report",
            description="Generate a security assessment report",
            input_schema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["pdf", "html", "json", "markdown"],
                        "description": "Report format",
                    },
                },
            },
            handler=self._handle_report,
        )

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: Callable,
    ) -> None:
        """Register a new MCP tool.

        Args:
            name: Tool name
            description: Tool description
            input_schema: JSON Schema for input
            handler: Function to handle tool calls

        """
        self.tools[name] = MCPTool(
            name=name,
            description=description,
            input_schema=input_schema,
            handler=handler,
        )

    def register_resource(
        self,
        uri: str,
        name: str,
        description: str,
        mime_type: str = "text/plain",
    ) -> None:
        """Register an MCP resource.

        Args:
            uri: Resource URI
            name: Resource name
            description: Resource description
            mime_type: MIME type

        """
        self.resources[uri] = MCPResource(
            uri=uri,
            name=name,
            description=description,
            mime_type=mime_type,
        )

    def get_capabilities(self) -> dict[str, Any]:
        """Get MCP capabilities response."""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": False, "listChanged": True},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {"name": self.name, "version": self.version},
        }

    def list_tools(self) -> list[dict[str, Any]]:
        """List all registered tools in MCP format."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            }
            for tool in self.tools.values()
        ]

    def list_resources(self) -> list[dict[str, Any]]:
        """List all registered resources in MCP format."""
        return [
            {
                "uri": res.uri,
                "name": res.name,
                "description": res.description,
                "mimeType": res.mime_type,
            }
            for res in self.resources.values()
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a registered tool.

        Args:
            name: Tool name
            arguments: Tool arguments

        Returns:
            Tool result

        """
        if name not in self.tools:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }

        tool = self.tools[name]

        try:
            result = tool.handler(arguments)
            return {
                "content": [{"type": "text", "text": json.dumps(result)}],
                "isError": False,
            }
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error: {e!s}"}],
                "isError": True,
            }

    # Built-in handlers
    def _handle_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle scan tool calls."""
        target = args.get("target", "")
        scan_type = args.get("scan_type", "quick")

        return {
            "status": "success",
            "target": target,
            "scan_type": scan_type,
            "message": f"Scan initiated for {target} ({scan_type})",
        }

    def _handle_exploit(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle exploit tool calls."""
        target = args.get("target", "")
        vuln = args.get("vulnerability", "")

        return {
            "status": "queued",
            "target": target,
            "vulnerability": vuln,
            "message": f"Exploit for {vuln} queued against {target}",
        }

    def _handle_report(self, args: dict[str, Any]) -> dict[str, Any]:
        """Handle report tool calls."""
        fmt = args.get("format", "markdown")

        return {
            "status": "success",
            "format": fmt,
            "message": f"Report generation initiated ({fmt})",
        }


# =============================================================================
# REST API SERVER
# =============================================================================


class APIRequestHandler(http.server.BaseHTTPRequestHandler):
    """Custom request handler for API Enpoints."""

    def _set_headers(self, status=200, content_type="application/json") -> None:
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _validate_auth(self) -> bool:
        """Validate the request API key."""
        api_key = self.headers.get("X-API-KEY")
        adapter = get_universal_adapter()
        if not adapter or not adapter.api_server:
            return False

        if not api_key or not adapter.api_server.validate_key(api_key):
            self._set_headers(401)
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
            return False
        return True

    def do_GET(self) -> None:
        try:
            # SECURITY: Enforce Auth for all endpoints
            if not self._validate_auth():
                return

            parsed = urlparse(self.path)

            if parsed.path == "/api/v1/status":
                self._set_headers()
                # Dynamically get adapter status if possible
                try:
                    adapter = get_universal_adapter()
                    status = adapter.get_status()
                except (AttributeError, ImportError):
                    status = {"status": "running", "agent": "Drakben"}

                self.wfile.write(json.dumps(status).encode())

            elif parsed.path == "/api/v1/tools":
                try:
                    adapter = get_universal_adapter()
                    tools = adapter.list_tools()
                except (AttributeError, ImportError):
                    tools = []
                self._set_headers()
                self.wfile.write(json.dumps(tools).encode())

            else:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Not found"}).encode())

        except Exception:
            logger.exception("do_GET error")
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": "Internal server error"}).encode())

    def do_POST(self) -> None:
        # Placeholder for POST methods
        if not self._validate_auth():
            return
        self._set_headers(501)
        self.wfile.write(
            json.dumps(
                {"error": "POST method not fully implemented in this version"},
            ).encode(),
        )

    def log_message(self, format, *args) -> None:
        """Suppress default logging to stdout."""


class APIServer:
    """REST API server for headless operation.

    Provides:
    - HTTP endpoints for tool management and status
    - Threaded execution

    WARNING: Uses http.server - suitable for development/internal use.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        """Initialize API server.

        Args:
            host: Bind host
            port: Bind port

        """
        self.host = host
        self.port = port
        self.api_keys: dict[str, str] = {}
        self.running = False
        self.server: socketserver.TCPServer | None = None
        self.thread: threading.Thread | None = None

        # Generate default API key
        self.default_key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        self.api_keys[self.default_key] = "admin"  # Default key has admin permissions

        logger.info("API Server initialized (bind: %s:%s)", host, port)

    def add_api_key(self, permissions: str = "read") -> str:
        """Add a new API key."""
        key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        self.api_keys[key] = permissions
        return key

    def validate_key(self, key: str) -> str | None:
        """Validate an API key (timing-safe comparison)."""
        import hmac

        for stored_key, permissions in self.api_keys.items():
            if hmac.compare_digest(stored_key, key):
                return permissions
        return None

    def get_endpoints(self) -> list[dict[str, str]]:
        """Get list of available API endpoints."""
        return [
            {
                "method": "GET",
                "path": "/api/v1/status",
                "description": "Get agent status",
            },
            {
                "method": "GET",
                "path": "/api/v1/tools",
                "description": "List available tools",
            },
            {
                "method": "POST",
                "path": "/api/v1/scan",
                "description": "Start a scan (Not implemented)",
            },
        ]

    def start(self) -> None:
        """Start the API server (threaded)."""
        if self.running:
            return

        try:
            # Allow address reuse
            socketserver.TCPServer.allow_reuse_address = True

            # Initialize server
            self.server = socketserver.TCPServer(
                (self.host, self.port),
                APIRequestHandler,
            )

            # Run in separate thread
            self.thread = threading.Thread(target=self.server.serve_forever)
            self.thread.daemon = True
            self.thread.start()

            self.running = True
            logger.info("API Server started on http://%s:%s", self.host, self.port)

        except (OSError, RuntimeError) as e:
            logger.exception(
                "Failed to start API server on %s:%s: %s",
                self.host,
                self.port,
                e,
            )
            self.running = False

    def stop(self) -> None:
        """Stop the API server."""
        if self.server and self.running:
            try:
                self.server.shutdown()
                self.server.server_close()
                self.running = False
                logger.info("API server stopped")
            except OSError as e:
                logger.exception("Error stopping API server: %s", e)


# =============================================================================
# UNIVERSAL ADAPTER - MAIN ORCHESTRATOR
# =============================================================================


class UniversalAdapter:
    """Main orchestrator for integration and extensibility.

    Combines:
    - MCP client for LLM integration
    - Dependency resolver for tool management
    - API server for remote control

    Usage:
        adapter = UniversalAdapter()
        status = adapter.check_tools(["nmap", "nikto"])
    """

    def __init__(self, api_host: str = "127.0.0.1", api_port: int = 8080) -> None:
        """Initialize Universal Adapter.

        Args:
            api_host: API server host
            api_port: API server port

        """
        self.resolver = DependencyResolver()
        self.mcp = MCPClient()
        self.api_server = APIServer(host=api_host, port=api_port)

        logger.info("Universal Adapter initialized")

    def check_tools(self, tools: list[str]) -> dict[str, bool]:
        """Check if tools are installed.

        Args:
            tools: List of tool names to check

        Returns:
            Dict of tool -> installed status

        """
        return {t: self.resolver.is_tool_installed(t) for t in tools}

    def list_tools(self) -> list[dict[str, Any]]:
        """List all available tools with status."""
        return self.resolver.list_available_tools()

    def get_mcp_manifest(self) -> dict[str, Any]:
        """Get MCP manifest for LLM integration."""
        return {
            "name": self.mcp.name,
            "version": self.mcp.version,
            "capabilities": self.mcp.get_capabilities(),
            "tools": self.mcp.list_tools(),
            "resources": self.mcp.list_resources(),
        }

    def call_mcp_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Call an MCP tool.

        Args:
            tool_name: Name of the tool
            arguments: Tool arguments

        Returns:
            Tool result

        """
        return self.mcp.call_tool(tool_name, arguments)

    def get_api_key(self) -> str:
        """Get the default API key."""
        return self.api_server.default_key

    def get_status(self) -> dict[str, Any]:
        """Get adapter status."""
        return {
            "tools_available": len(TOOL_REGISTRY),
            "tools_installed": sum(1 for t in TOOL_REGISTRY if self.resolver.is_tool_installed(t)),
            "mcp_tools": len(self.mcp.tools),
            "mcp_resources": len(self.mcp.resources),
            "api_running": self.api_server.running,
            "api_endpoints": len(self.api_server.get_endpoints()),
            "package_manager": self.resolver.package_manager.value if self.resolver.package_manager else None,
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================


def get_universal_adapter() -> UniversalAdapter:
    """Get singleton UniversalAdapter instance.

    Returns:
        UniversalAdapter instance

    """
    global _universal_adapter
    if _universal_adapter is None:
        with _universal_adapter_lock:
            if _universal_adapter is None:
                _universal_adapter = UniversalAdapter()
    return _universal_adapter


def is_tool_available(tool_name: str) -> bool:
    """Check if a tool is available.

    Args:
        tool_name: Name of the tool

    Returns:
        True if tool is installed

    """
    adapter = get_universal_adapter()
    return adapter.resolver.is_tool_installed(tool_name)
