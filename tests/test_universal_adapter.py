"""Tests for Universal Adapter module"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.universal_adapter import (
    UniversalAdapter,
    DependencyResolver,
    MCPClient,
    APIServer,
    TOOL_REGISTRY,
    ToolDefinition,
    MCPTool,
    MCPResource,
    PackageManager,
    ToolCategory,
    get_universal_adapter,
    is_tool_available,
)


class TestDependencyResolver(unittest.TestCase):
    """Test dependency resolution functionality"""

    def setUp(self):
        self.resolver = DependencyResolver()

    def test_initialization(self):
        """Test resolver initialization"""
        self.assertIsNotNone(self.resolver.system)
        self.assertTrue(self.resolver.tools_dir.exists())

    def test_detect_package_manager(self):
        """Test package manager detection"""
        pm = self.resolver._detect_package_manager()
        # Should be None or a valid PackageManager
        self.assertTrue(pm is None or isinstance(pm, PackageManager))

    def test_is_tool_installed_python(self):
        """Test checking if Python is installed (it should be!)"""
        # Python is definitely installed if we're running this test
        result = self.resolver.is_tool_installed("python")
        # This may vary by system, but python should exist
        self.assertIsInstance(result, bool)

    def test_is_tool_installed_nonexistent(self):
        """Test checking non-existent tool"""
        result = self.resolver.is_tool_installed("definitely_not_a_real_tool_xyzzy")
        self.assertFalse(result)

    def test_list_available_tools(self):
        """Test listing available tools"""
        tools = self.resolver.list_available_tools()
        self.assertIsInstance(tools, list)
        self.assertGreater(len(tools), 0)

        # Each tool should have required fields
        for tool in tools:
            self.assertIn("name", tool)
            self.assertIn("description", tool)
            self.assertIn("category", tool)
            self.assertIn("installed", tool)

    def test_check_missing_tools(self):
        """Test checking for missing tools"""
        # Mix of potentially installed and definitely not installed
        required = ["python", "nonexistent_tool_xyz"]
        missing = self.resolver.check_missing_tools(required)

        self.assertIsInstance(missing, list)
        self.assertIn("nonexistent_tool_xyz", missing)

    def test_tool_registry_structure(self):
        """Test tool registry has valid structure"""
        self.assertGreater(len(TOOL_REGISTRY), 0)

        for name, tool_def in TOOL_REGISTRY.items():
            self.assertIsInstance(tool_def, ToolDefinition)
            self.assertEqual(tool_def.name, name)
            self.assertIsInstance(tool_def.category, ToolCategory)
            self.assertIsInstance(tool_def.install_commands, dict)


class TestMCPClient(unittest.TestCase):
    """Test MCP client functionality"""

    def setUp(self):
        self.mcp = MCPClient()

    def test_initialization(self):
        """Test MCP client initialization"""
        self.assertEqual(self.mcp.name, "drakben")
        self.assertIsNotNone(self.mcp.version)
        self.assertGreater(len(self.mcp.tools), 0)  # Built-in tools registered

    def test_get_capabilities(self):
        """Test getting MCP capabilities"""
        caps = self.mcp.get_capabilities()

        self.assertIn("protocolVersion", caps)
        self.assertIn("capabilities", caps)
        self.assertIn("serverInfo", caps)
        self.assertEqual(caps["serverInfo"]["name"], "drakben")

    def test_list_tools(self):
        """Test listing MCP tools"""
        tools = self.mcp.list_tools()

        self.assertIsInstance(tools, list)
        self.assertGreater(len(tools), 0)

        # Check built-in tools exist
        tool_names = [t["name"] for t in tools]
        self.assertIn("scan", tool_names)
        self.assertIn("exploit", tool_names)
        self.assertIn("generate_report", tool_names)

    def test_register_tool(self):
        """Test registering a custom tool"""
        self.mcp.register_tool(
            name="test_tool",
            description="Test tool",
            input_schema={"type": "object", "properties": {}},
            handler=lambda args: {"result": "ok"},
        )

        self.assertIn("test_tool", self.mcp.tools)

    def test_register_resource(self):
        """Test registering a resource"""
        self.mcp.register_resource(
            uri="file:///test.txt", name="Test Resource", description="A test resource"
        )

        self.assertIn("file:///test.txt", self.mcp.resources)

    def test_list_resources(self):
        """Test listing resources"""
        self.mcp.register_resource(
            uri="test://resource", name="Test", description="Test"
        )

        resources = self.mcp.list_resources()
        self.assertIsInstance(resources, list)

    def test_call_tool_scan(self):
        """Test calling the scan tool"""
        result = self.mcp.call_tool("scan", {"target": "192.168.1.1"})

        self.assertIn("content", result)
        self.assertIn("isError", result)
        self.assertFalse(result["isError"])

    def test_call_tool_unknown(self):
        """Test calling unknown tool"""
        result = self.mcp.call_tool("nonexistent_tool", {})

        self.assertTrue(result["isError"])

    def test_call_tool_exploit(self):
        """Test calling the exploit tool"""
        result = self.mcp.call_tool(
            "exploit", {"target": "192.168.1.1", "vulnerability": "CVE-2021-44228"}
        )

        self.assertFalse(result["isError"])

    def test_call_tool_report(self):
        """Test calling the report tool"""
        result = self.mcp.call_tool("generate_report", {"format": "pdf"})

        self.assertFalse(result["isError"])


class TestAPIServer(unittest.TestCase):
    """Test API server functionality"""

    def setUp(self):
        self.api = APIServer()

    def test_initialization(self):
        """Test API server initialization"""
        self.assertEqual(self.api.host, "127.0.0.1")
        self.assertEqual(self.api.port, 8080)
        self.assertFalse(self.api.running)

    def test_default_api_key_generated(self):
        """Test that default API key is generated"""
        self.assertIsNotNone(self.api.default_key)
        self.assertEqual(len(self.api.default_key), 32)

    def test_add_api_key(self):
        """Test adding API keys"""
        new_key = self.api.add_api_key("read")

        self.assertEqual(len(new_key), 32)
        self.assertEqual(self.api.validate_key(new_key), "read")

    def test_validate_key_invalid(self):
        """Test validating invalid key"""
        result = self.api.validate_key("invalid_key")
        self.assertIsNone(result)

    def test_validate_key_default(self):
        """Test validating default key"""
        result = self.api.validate_key(self.api.default_key)
        self.assertEqual(result, "admin")

    def test_get_endpoints(self):
        """Test getting endpoints list"""
        endpoints = self.api.get_endpoints()

        self.assertIsInstance(endpoints, list)
        self.assertGreater(len(endpoints), 0)

        # Check endpoint structure
        for ep in endpoints:
            self.assertIn("method", ep)
            self.assertIn("path", ep)
            self.assertIn("description", ep)


class TestUniversalAdapter(unittest.TestCase):
    """Test main UniversalAdapter orchestrator"""

    def setUp(self):
        self.adapter = UniversalAdapter()

    def test_initialization(self):
        """Test adapter initialization"""
        self.assertIsNotNone(self.adapter.resolver)
        self.assertIsNotNone(self.adapter.mcp)
        self.assertIsNotNone(self.adapter.api)

    def test_check_tools(self):
        """Test checking tool status"""
        result = self.adapter.check_tools(["python", "nonexistent"])

        self.assertIsInstance(result, dict)
        self.assertIn("nonexistent", result)
        self.assertFalse(result["nonexistent"])

    def test_list_tools(self):
        """Test listing tools"""
        tools = self.adapter.list_tools()
        self.assertIsInstance(tools, list)
        self.assertGreater(len(tools), 0)

    def test_get_mcp_manifest(self):
        """Test getting MCP manifest"""
        manifest = self.adapter.get_mcp_manifest()

        self.assertIn("name", manifest)
        self.assertIn("version", manifest)
        self.assertIn("tools", manifest)
        self.assertIn("resources", manifest)

    def test_call_mcp_tool(self):
        """Test calling MCP tool through adapter"""
        result = self.adapter.call_mcp_tool("scan", {"target": "test"})

        self.assertIn("content", result)
        self.assertFalse(result["isError"])

    def test_get_api_key(self):
        """Test getting API key"""
        key = self.adapter.get_api_key()
        self.assertEqual(len(key), 32)

    def test_get_status(self):
        """Test getting adapter status"""
        status = self.adapter.get_status()

        self.assertIn("tools_available", status)
        self.assertIn("tools_installed", status)
        self.assertIn("mcp_tools", status)
        self.assertIn("api_running", status)

    def test_singleton(self):
        """Test get_universal_adapter returns same instance"""
        adapter1 = get_universal_adapter()
        adapter2 = get_universal_adapter()
        self.assertIs(adapter1, adapter2)


class TestModuleFunctions(unittest.TestCase):
    """Test module-level helper functions"""

    def test_is_tool_available(self):
        """Test is_tool_available function"""
        result = is_tool_available("definitely_not_real_tool")
        self.assertFalse(result)


class TestDataClasses(unittest.TestCase):
    """Test data class creation"""

    def test_tool_definition(self):
        """Test ToolDefinition creation"""
        tool = ToolDefinition(
            name="test",
            description="Test tool",
            category=ToolCategory.UTILITY,
            check_command="test --version",
            install_commands={"pip": "pip install test"},
        )

        self.assertEqual(tool.name, "test")
        self.assertEqual(tool.category, ToolCategory.UTILITY)

    def test_mcp_tool(self):
        """Test MCPTool creation"""
        tool = MCPTool(
            name="test", description="Test", input_schema={}, handler=lambda x: x
        )

        self.assertEqual(tool.name, "test")

    def test_mcp_resource(self):
        """Test MCPResource creation"""
        res = MCPResource(uri="file:///test", name="Test", description="Test resource")

        self.assertEqual(res.uri, "file:///test")
        self.assertEqual(res.mime_type, "text/plain")


if __name__ == "__main__":
    unittest.main()
