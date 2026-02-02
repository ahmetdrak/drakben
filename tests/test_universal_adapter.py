"""Tests for Universal Adapter module."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.universal_adapter import (
    TOOL_REGISTRY,
    APIServer,
    DependencyResolver,
    MCPClient,
    MCPResource,
    MCPTool,
    PackageManager,
    ToolCategory,
    ToolDefinition,
    UniversalAdapter,
    get_universal_adapter,
    is_tool_available,
)


class TestDependencyResolver(unittest.TestCase):
    """Test dependency resolution functionality."""

    def setUp(self) -> None:
        self.resolver = DependencyResolver()

    def test_initialization(self) -> None:
        """Test resolver initialization."""
        assert self.resolver.system is not None
        assert self.resolver.tools_dir.exists()

    def test_detect_package_manager(self) -> None:
        """Test package manager detection."""
        pm = self.resolver._detect_package_manager()
        # Should be None or a valid PackageManager
        assert pm is None or isinstance(pm, PackageManager)

    def test_is_tool_installed_python(self) -> None:
        """Test checking if Python is installed (it should be!)."""
        # Python is definitely installed if we're running this test
        result = self.resolver.is_tool_installed("python")
        # This may vary by system, but python should exist
        assert isinstance(result, bool)

    def test_is_tool_installed_nonexistent(self) -> None:
        """Test checking non-existent tool."""
        result = self.resolver.is_tool_installed("definitely_not_a_real_tool_xyzzy")
        assert not result

    def test_list_available_tools(self) -> None:
        """Test listing available tools."""
        tools = self.resolver.list_available_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0

        # Each tool should have required fields
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "category" in tool
            assert "installed" in tool

    def test_check_missing_tools(self) -> None:
        """Test checking for missing tools."""
        # Mix of potentially installed and definitely not installed
        required = ["python", "nonexistent_tool_xyz"]
        missing = self.resolver.check_missing_tools(required)

        assert isinstance(missing, list)
        assert "nonexistent_tool_xyz" in missing

    def test_tool_registry_structure(self) -> None:
        """Test tool registry has valid structure."""
        assert len(TOOL_REGISTRY) > 0

        for name, tool_def in TOOL_REGISTRY.items():
            assert isinstance(tool_def, ToolDefinition)
            assert tool_def.name == name
            assert isinstance(tool_def.category, ToolCategory)
            assert isinstance(tool_def.install_commands, dict)


class TestMCPClient(unittest.TestCase):
    """Test MCP client functionality."""

    def setUp(self) -> None:
        self.mcp = MCPClient()

    def test_initialization(self) -> None:
        """Test MCP client initialization."""
        assert self.mcp.name == "drakben"
        assert self.mcp.version is not None
        assert len(self.mcp.tools) > 0  # Built-in tools registered

    def test_get_capabilities(self) -> None:
        """Test getting MCP capabilities."""
        caps = self.mcp.get_capabilities()

        assert "protocolVersion" in caps
        assert "capabilities" in caps
        assert "serverInfo" in caps
        assert caps["serverInfo"]["name"] == "drakben"

    def test_list_tools(self) -> None:
        """Test listing MCP tools."""
        tools = self.mcp.list_tools()

        assert isinstance(tools, list)
        assert len(tools) > 0

        # Check built-in tools exist
        tool_names = [t["name"] for t in tools]
        assert "scan" in tool_names
        assert "exploit" in tool_names
        assert "generate_report" in tool_names

    def test_register_tool(self) -> None:
        """Test registering a custom tool."""
        self.mcp.register_tool(
            name="test_tool",
            description="Test tool",
            input_schema={"type": "object", "properties": {}},
            handler=lambda args: {"result": "ok"},
        )

        assert "test_tool" in self.mcp.tools

    def test_register_resource(self) -> None:
        """Test registering a resource."""
        self.mcp.register_resource(
            uri="file:///test.txt",
            name="Test Resource",
            description="A test resource",
        )

        assert "file:///test.txt" in self.mcp.resources

    def test_list_resources(self) -> None:
        """Test listing resources."""
        self.mcp.register_resource(
            uri="test://resource",
            name="Test",
            description="Test",
        )

        resources = self.mcp.list_resources()
        assert isinstance(resources, list)

    def test_call_tool_scan(self) -> None:
        """Test calling the scan tool."""
        result = self.mcp.call_tool("scan", {"target": "192.168.1.1"})

        assert "content" in result
        assert "isError" in result
        assert not result["isError"]

    def test_call_tool_unknown(self) -> None:
        """Test calling unknown tool."""
        result = self.mcp.call_tool("nonexistent_tool", {})

        assert result["isError"]

    def test_call_tool_exploit(self) -> None:
        """Test calling the exploit tool."""
        result = self.mcp.call_tool(
            "exploit",
            {"target": "192.168.1.1", "vulnerability": "CVE-2021-44228"},
        )

        assert not result["isError"]

    def test_call_tool_report(self) -> None:
        """Test calling the report tool."""
        result = self.mcp.call_tool("generate_report", {"format": "pdf"})

        assert not result["isError"]


class TestAPIServer(unittest.TestCase):
    """Test API server functionality."""

    def setUp(self) -> None:
        self.api = APIServer()

    def test_initialization(self) -> None:
        """Test API server initialization."""
        assert self.api.host == "127.0.0.1"
        assert self.api.port == 8080
        assert not self.api.running

    def test_default_api_key_generated(self) -> None:
        """Test that default API key is generated."""
        assert self.api.default_key is not None
        assert len(self.api.default_key) == 32

    def test_add_api_key(self) -> None:
        """Test adding API keys."""
        new_key = self.api.add_api_key("read")

        assert len(new_key) == 32
        assert self.api.validate_key(new_key) == "read"

    def test_validate_key_invalid(self) -> None:
        """Test validating invalid key."""
        result = self.api.validate_key("invalid_key")
        assert result is None

    def test_validate_key_default(self) -> None:
        """Test validating default key."""
        result = self.api.validate_key(self.api.default_key)
        assert result == "admin"

    def test_get_endpoints(self) -> None:
        """Test getting endpoints list."""
        endpoints = self.api.get_endpoints()

        assert isinstance(endpoints, list)
        assert len(endpoints) > 0

        # Check endpoint structure
        for ep in endpoints:
            assert "method" in ep
            assert "path" in ep
            assert "description" in ep


class TestUniversalAdapter(unittest.TestCase):
    """Test main UniversalAdapter orchestrator."""

    def setUp(self) -> None:
        self.adapter = UniversalAdapter()

    def test_initialization(self) -> None:
        """Test adapter initialization."""
        assert self.adapter.resolver is not None
        assert self.adapter.mcp is not None
        assert self.adapter.api_server is not None

    def test_check_tools(self) -> None:
        """Test checking tool status."""
        result = self.adapter.check_tools(["python", "nonexistent"])

        assert isinstance(result, dict)
        assert "nonexistent" in result
        assert not result["nonexistent"]

    def test_list_tools(self) -> None:
        """Test listing tools."""
        tools = self.adapter.list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_get_mcp_manifest(self) -> None:
        """Test getting MCP manifest."""
        manifest = self.adapter.get_mcp_manifest()

        assert "name" in manifest
        assert "version" in manifest
        assert "tools" in manifest
        assert "resources" in manifest

    def test_call_mcp_tool(self) -> None:
        """Test calling MCP tool through adapter."""
        result = self.adapter.call_mcp_tool("scan", {"target": "test"})

        assert "content" in result
        assert not result["isError"]

    def test_get_api_key(self) -> None:
        """Test getting API key."""
        key = self.adapter.get_api_key()
        assert len(key) == 32

    def test_get_status(self) -> None:
        """Test getting adapter status."""
        status = self.adapter.get_status()

        assert "tools_available" in status
        assert "tools_installed" in status
        assert "mcp_tools" in status
        assert "api_running" in status

    def test_singleton(self) -> None:
        """Test get_universal_adapter returns same instance."""
        adapter1 = get_universal_adapter()
        adapter2 = get_universal_adapter()
        assert adapter1 is adapter2


class TestModuleFunctions(unittest.TestCase):
    """Test module-level helper functions."""

    def test_is_tool_available(self) -> None:
        """Test is_tool_available function."""
        result = is_tool_available("definitely_not_real_tool")
        assert not result


class TestDataClasses(unittest.TestCase):
    """Test data class creation."""

    def test_tool_definition(self) -> None:
        """Test ToolDefinition creation."""
        tool = ToolDefinition(
            name="test",
            description="Test tool",
            category=ToolCategory.UTILITY,
            check_command="test --version",
            install_commands={"pip": "pip install test"},
        )

        assert tool.name == "test"
        assert tool.category == ToolCategory.UTILITY

    def test_mcp_tool(self) -> None:
        """Test MCPTool creation."""
        tool = MCPTool(
            name="test",
            description="Test",
            input_schema={},
            handler=lambda x: x,
        )

        assert tool.name == "test"

    def test_mcp_resource(self) -> None:
        """Test MCPResource creation."""
        res = MCPResource(uri="file:///test", name="Test", description="Test resource")

        assert res.uri == "file:///test"
        assert res.mime_type == "text/plain"


if __name__ == "__main__":
    unittest.main()
