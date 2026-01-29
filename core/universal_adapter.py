"""
DRAKBEN Universal Adapter - MCP Client & Dependency Resolver
Author: @drak_ben
Description: Model Context Protocol integration and automatic tool management.

This module provides:
- MCP (Model Context Protocol) client for LLM integration
- Automatic tool installation and dependency resolution
- REST API server for headless operation
- Plugin system interface
"""

import asyncio
import hashlib
import http.server
import json
import logging
import os
import platform
import shutil
import shlex
import socketserver
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

TOOLS_DIR = Path("tools")
CACHE_DIR = Path(".cache/drakben")


class PackageManager(Enum):
    """Supported package managers"""
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
    """Tool categories"""
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
    """Definition of a tool that can be installed"""
    name: str
    description: str
    category: ToolCategory
    check_command: str  # Command to check if installed
    install_commands: Dict[str, str]  # Package manager -> command
    binary_name: Optional[str] = None  # Name of main binary
    version_command: str = "--version"
    dependencies: List[str] = field(default_factory=list)
    url: Optional[str] = None  # Download URL for manual install


@dataclass
class MCPTool:
    """MCP Tool definition for LLM integration"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable


@dataclass
class MCPResource:
    """MCP Resource definition"""
    uri: str
    name: str
    description: str
    mime_type: str = "text/plain"


# =============================================================================
# TOOL REGISTRY
# =============================================================================

TOOL_REGISTRY: Dict[str, ToolDefinition] = {
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
        binary_name="nmap"
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
        binary_name="nikto"
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
        binary_name="gobuster"
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
        binary_name="sqlmap"
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
        binary_name="hydra"
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
        binary_name="john"
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
        binary_name="hashcat"
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
        dependencies=["postgresql"]
    ),
    "impacket": ToolDefinition(
        name="impacket",
        description="Network protocol tools (psexec, secretsdump)",
        category=ToolCategory.POST,
        check_command="python -c 'import impacket'",
        install_commands={
            "pip": "pip install impacket",
        },
        binary_name="psexec.py"
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
        binary_name="ffuf"
    ),
}


# =============================================================================
# DEPENDENCY RESOLVER
# =============================================================================

class DependencyResolver:
    """
    Automatic tool installation and dependency management.
    
    Features:
    - Detects system package manager
    - Installs missing tools
    - Manages isolated tool installations
    - Handles dependencies
    """
    
    def __init__(self, tools_dir: Path = TOOLS_DIR):
        """
        Initialize dependency resolver.
        
        Args:
            tools_dir: Directory for isolated tool installations
        """
        self.tools_dir = Path(tools_dir)
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        
        self.system = platform.system().lower()
        self.package_manager = self._detect_package_manager()
        
        logger.info(f"DependencyResolver initialized (OS: {self.system}, PM: {self.package_manager})")
    
    def _detect_package_manager(self) -> Optional[PackageManager]:
        """Detect system package manager"""
        if self.system == "linux":
            # Check for various package managers
            if shutil.which("apt-get"):
                return PackageManager.APT
            elif shutil.which("dnf"):
                return PackageManager.DNF
            elif shutil.which("yum"):
                return PackageManager.YUM
            elif shutil.which("pacman"):
                return PackageManager.PACMAN
        elif self.system == "darwin":
            if shutil.which("brew"):
                return PackageManager.BREW
        elif self.system == "windows" and shutil.which("choco"):
            return PackageManager.CHOCO
        
        return None
    
    def is_tool_installed(self, tool_name: str) -> bool:
        """
        Check if a tool is installed.
        
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
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_tool_version(self, tool_name: str) -> Optional[str]:
        """
        Get installed tool version.
        
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
                shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Extract version from first line
                output = result.stdout.strip() or result.stderr.strip()
                return output.split('\n')[0][:50]
        except Exception:
            pass
        
        return None
    
    def _install_via_package_manager(self, tool_name: str, install_commands: Dict[str, str], result: Dict[str, Any]):
        """Helper to install via system package manager"""
        if self.package_manager and self.package_manager.value in install_commands:
            cmd = install_commands[self.package_manager.value]
            result["method"] = self.package_manager.value
            
            try:
                logger.info(f"Installing {tool_name} via {self.package_manager.value}")
                proc = subprocess.run(
                    shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=300
                )
                if proc.returncode == 0:
                    result["success"] = True
                    result["message"] = f"Installed {tool_name} via {self.package_manager.value}"
                else:
                    result["message"] = f"Installation failed: {proc.stderr[:200]}"
            except subprocess.TimeoutExpired:
                result["message"] = "Installation timed out"
            except Exception as e:
                result["message"] = str(e)
            return True
        return False

    def _install_via_pip(self, tool_name: str, install_commands: Dict[str, str], result: Dict[str, Any]):
        """Helper to install via pip"""
        if "pip" in install_commands:
            cmd = install_commands["pip"]
            result["method"] = "pip"
            
            try:
                proc = subprocess.run(
                    shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=120
                )
                result["success"] = proc.returncode == 0
                result["message"] = f"Installed {tool_name} via pip" if result["success"] else proc.stderr[:200]
            except Exception as e:
                result["message"] = str(e)
            return True
        return False

    def install_tool(self, tool_name: str, force: bool = False) -> Dict[str, Any]:
        """
        Install a tool with reduced cognitive complexity.
        """
        result = {"tool": tool_name, "success": False, "message": "", "method": None}
        tool_def = TOOL_REGISTRY.get(tool_name)
        
        if not tool_def:
            result["message"] = f"Unknown tool: {tool_name}"
            return result
        
        if not force and self.is_tool_installed(tool_name):
            result["success"] = True
            result["message"] = f"{tool_name} is already installed"
            return result
        
        # 1. Install dependencies
        for dep in tool_def.dependencies:
            if not self.install_tool(dep)["success"]:
                result["message"] = f"Failed to install dependency: {dep}"
                return result
        
        # 2. Try installation methods
        if self._install_via_package_manager(tool_name, tool_def.install_commands, result):
            return result
        elif self._install_via_pip(tool_name, tool_def.install_commands, result):
            return result
        else:
            result["message"] = f"No installation method available for {tool_name} on {self.system}"
        
        return result
    
    def list_available_tools(self) -> List[Dict[str, Any]]:
        """List all available tools in registry"""
        tools = []
        for name, tool_def in TOOL_REGISTRY.items():
            installed = self.is_tool_installed(name)
            tools.append({
                "name": name,
                "description": tool_def.description,
                "category": tool_def.category.value,
                "installed": installed,
                "version": self.get_tool_version(name) if installed else None
            })
        return tools
    
    def check_missing_tools(self, required: List[str]) -> List[str]:
        """
        Check which required tools are missing.
        
        Args:
            required: List of required tool names
            
        Returns:
            List of missing tool names
        """
        return [t for t in required if not self.is_tool_installed(t)]
    
    def install_missing(self, required: List[str]) -> Dict[str, Any]:
        """
        Install all missing required tools.
        
        Args:
            required: List of required tool names
            
        Returns:
            Results for each tool
        """
        missing = self.check_missing_tools(required)
        results = {}
        
        for tool in missing:
            results[tool] = self.install_tool(tool)
        
        return results


# =============================================================================
# MCP CLIENT
# =============================================================================

class MCPClient:
    """
    Model Context Protocol client for LLM integration.
    
    Allows Drakben to:
    - Expose tools to LLMs (Claude, GPT, etc.)
    - Receive tool calls from LLMs
    - Provide resources and context
    
    Protocol: https://modelcontextprotocol.io/
    """
    
    def __init__(self, name: str = "drakben"):
        """
        Initialize MCP client.
        
        Args:
            name: Client name for identification
        """
        self.name = name
        self.version = "1.0.0"
        self.tools: Dict[str, MCPTool] = {}
        self.resources: Dict[str, MCPResource] = {}
        
        # Register built-in tools
        self._register_builtin_tools()
        
        logger.info(f"MCP Client initialized (name: {name})")
    
    def _register_builtin_tools(self) -> None:
        """Register built-in Drakben tools for MCP"""
        # Scan tool
        self.register_tool(
            name="scan",
            description="Perform network reconnaissance scan on a target",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "stealth"],
                        "description": "Type of scan to perform"
                    }
                },
                "required": ["target"]
            },
            handler=self._handle_scan
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
                        "description": "Target IP or hostname"
                    },
                    "vulnerability": {
                        "type": "string",
                        "description": "CVE or vulnerability name"
                    }
                },
                "required": ["target", "vulnerability"]
            },
            handler=self._handle_exploit
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
                        "description": "Report format"
                    }
                }
            },
            handler=self._handle_report
        )
    
    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        handler: Callable
    ) -> None:
        """
        Register a new MCP tool.
        
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
            handler=handler
        )
    
    def register_resource(
        self,
        uri: str,
        name: str,
        description: str,
        mime_type: str = "text/plain"
    ) -> None:
        """
        Register an MCP resource.
        
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
            mime_type=mime_type
        )
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get MCP capabilities response"""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": False, "listChanged": True},
                "prompts": {"listChanged": False}
            },
            "serverInfo": {
                "name": self.name,
                "version": self.version
            }
        }
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools in MCP format"""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema
            }
            for tool in self.tools.values()
        ]
    
    def list_resources(self) -> List[Dict[str, Any]]:
        """List all registered resources in MCP format"""
        return [
            {
                "uri": res.uri,
                "name": res.name,
                "description": res.description,
                "mimeType": res.mime_type
            }
            for res in self.resources.values()
        ]
    
    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a registered tool.
        
        Args:
            name: Tool name
            arguments: Tool arguments
            
        Returns:
            Tool result
        """
        if name not in self.tools:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True
            }
        
        tool = self.tools[name]
        
        try:
            result = tool.handler(arguments)
            return {
                "content": [{"type": "text", "text": json.dumps(result)}],
                "isError": False
            }
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Error: {str(e)}"}],
                "isError": True
            }
    
    # Built-in handlers
    def _handle_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle scan tool calls"""
        target = args.get("target", "")
        scan_type = args.get("scan_type", "quick")
        
        return {
            "status": "success",
            "target": target,
            "scan_type": scan_type,
            "message": f"Scan initiated for {target} ({scan_type})"
        }
    
    def _handle_exploit(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle exploit tool calls"""
        target = args.get("target", "")
        vuln = args.get("vulnerability", "")
        
        return {
            "status": "queued",
            "target": target,
            "vulnerability": vuln,
            "message": f"Exploit for {vuln} queued against {target}"
        }
    
    def _handle_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle report tool calls"""
        fmt = args.get("format", "markdown")
        
        return {
            "status": "success",
            "format": fmt,
            "message": f"Report generation initiated ({fmt})"
        }


# =============================================================================
# REST API SERVER
# =============================================================================

class APIRequestHandler(http.server.BaseHTTPRequestHandler):
    """Custom request handler for API Enpoints"""
    
    def _set_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            
            if parsed.path == "/api/v1/status":
                self._set_headers()
                # Dynamically get adapter status if possible
                try:
                    adapter = get_universal_adapter()
                    status = adapter.get_status()
                except Exception:
                    status = {"status": "running", "agent": "Drakben"}
                
                self.wfile.write(json.dumps(status).encode())
                
            elif parsed.path == "/api/v1/tools":
                try:
                    adapter = get_universal_adapter()
                    tools = adapter.list_tools()
                except Exception:
                    tools = []
                self._set_headers()
                self.wfile.write(json.dumps(tools).encode())
                
            else:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Not found"}).encode())
                
        except Exception as e:
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def do_POST(self):
        # Placeholder for POST methods
        self._set_headers(501)
        self.wfile.write(json.dumps({"error": "POST method not fully implemented in this version"}).encode())

    def log_message(self, format, *args):
        # Suppress default logging to stdout
        pass


class APIServer:
    """
    REST API server for headless operation.
    
    Provides:
    - HTTP endpoints for tool management and status
    - Threaded execution
    
    WARNING: Uses http.server - suitable for development/internal use.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        """
        Initialize API server.
        
        Args:
            host: Bind host
            port: Bind port
        """
        self.host = host
        self.port = port
        self.api_keys: Dict[str, str] = {}
        self.running = False
        self.server = None
        self.thread = None
        
        # Generate default API key
        self.default_key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        self.api_keys[self.default_key] = "admin"  # Default key has admin permissions
        
        logger.info(f"API Server initialized (bind: {host}:{port})")
    
    def add_api_key(self, permissions: str = "read") -> str:
        """Add a new API key"""
        key = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        self.api_keys[key] = permissions
        return key
    
    def validate_key(self, key: str) -> Optional[str]:
        """Validate an API key"""
        return self.api_keys.get(key)
    
    def get_endpoints(self) -> List[Dict[str, str]]:
        """Get list of available API endpoints"""
        return [
            {"method": "GET", "path": "/api/v1/status", "description": "Get agent status"},
            {"method": "GET", "path": "/api/v1/tools", "description": "List available tools"},
            {"method": "POST", "path": "/api/v1/scan", "description": "Start a scan (Not implemented)"},
        ]
    
    def start(self) -> None:
        """Start the API server (threaded)"""
        if self.running:
            return
            
        try:
            # Allow address reuse
            socketserver.TCPServer.allow_reuse_address = True
            
            # Initialize server
            self.server = socketserver.TCPServer((self.host, self.port), APIRequestHandler)
            
            # Run in separate thread
            self.thread = threading.Thread(target=self.server.serve_forever)
            self.thread.daemon = True
            self.thread.start()
            
            self.running = True
            logger.info(f"API Server started on http://{self.host}:{self.port}")
            
        except OSError as e:
            logger.error(f"Failed to bind API server to {self.host}:{self.port} - {e}")
            self.running = False
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")
            self.running = False
    
    def stop(self) -> None:
        """Stop the API server"""
        if self.server and self.running:
            try:
                self.server.shutdown()
                self.server.server_close()
                self.running = False
                logger.info("API server stopped")
            except Exception as e:
                logger.error(f"Error stopping API server: {e}")


# =============================================================================
# UNIVERSAL ADAPTER - MAIN ORCHESTRATOR
# =============================================================================

class UniversalAdapter:
    """
    Main orchestrator for integration and extensibility.
    
    Combines:
    - MCP client for LLM integration
    - Dependency resolver for tool management
    - API server for remote control
    
    Usage:
        adapter = UniversalAdapter()
        adapter.ensure_tools(["nmap", "nikto"])
        adapter.start_api_server()
    """
    
    def __init__(
        self,
        api_host: str = "127.0.0.1",
        api_port: int = 8080
    ):
        """
        Initialize Universal Adapter.
        
        Args:
            api_host: API server host
            api_port: API server port
        """
        self.resolver = DependencyResolver()
        self.mcp = MCPClient()
        self.api = APIServer(host=api_host, port=api_port)
        
        logger.info("Universal Adapter initialized")
    
    def ensure_tools(self, tools: List[str]) -> Dict[str, Any]:
        """
        Ensure required tools are installed.
        
        Args:
            tools: List of required tool names
            
        Returns:
            Installation results
        """
        return self.resolver.install_missing(tools)
    
    def check_tools(self, tools: List[str]) -> Dict[str, bool]:
        """
        Check if tools are installed.
        
        Args:
            tools: List of tool names to check
            
        Returns:
            Dict of tool -> installed status
        """
        return {t: self.resolver.is_tool_installed(t) for t in tools}
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools with status"""
        return self.resolver.list_available_tools()
    
    def get_mcp_manifest(self) -> Dict[str, Any]:
        """Get MCP manifest for LLM integration"""
        return {
            "name": self.mcp.name,
            "version": self.mcp.version,
            "capabilities": self.mcp.get_capabilities(),
            "tools": self.mcp.list_tools(),
            "resources": self.mcp.list_resources()
        }
    
    def call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call an MCP tool.
        
        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
            
        Returns:
            Tool result
        """
        return self.mcp.call_tool(tool_name, arguments)
    
    def start_api_server(self) -> None:
        """Start the REST API server"""
        self.api.start()
    
    def stop_api_server(self) -> None:
        """Stop the REST API server"""
        self.api.stop()
    
    def get_api_key(self) -> str:
        """Get the default API key"""
        return self.api.default_key
    
    def get_status(self) -> Dict[str, Any]:
        """Get adapter status"""
        return {
            "tools_available": len(TOOL_REGISTRY),
            "tools_installed": sum(1 for t in TOOL_REGISTRY if self.resolver.is_tool_installed(t)),
            "mcp_tools": len(self.mcp.tools),
            "mcp_resources": len(self.mcp.resources),
            "api_running": self.api.running,
            "api_endpoints": len(self.api.get_endpoints()),
            "package_manager": self.resolver.package_manager.value if self.resolver.package_manager else None
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================

def get_universal_adapter() -> UniversalAdapter:
    """
    Get singleton UniversalAdapter instance.
    
    Returns:
        UniversalAdapter instance
    """
    global _universal_adapter
    if "_universal_adapter" not in globals() or _universal_adapter is None:
        _universal_adapter = UniversalAdapter()
    return _universal_adapter


def ensure_tool(tool_name: str) -> bool:
    """
    Quick function to ensure a tool is installed.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        True if tool is now available
    """
    adapter = get_universal_adapter()
    result = adapter.resolver.install_tool(tool_name)
    return result["success"]


def is_tool_available(tool_name: str) -> bool:
    """
    Check if a tool is available.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        True if tool is installed
    """
    adapter = get_universal_adapter()
    return adapter.resolver.is_tool_installed(tool_name)
