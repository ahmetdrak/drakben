# tests/test_tool_registry.py
"""Tests for Tool Registry - Central hub for all pentesting tools."""

from unittest.mock import AsyncMock, patch

import pytest

from core.tools.tool_registry import (
    PentestPhase,
    Tool,
    ToolRegistry,
    ToolType,
)


class TestToolType:
    """Tests for ToolType enum."""

    def test_tool_types_exist(self) -> None:
        """Verify all tool types exist."""
        assert ToolType.SHELL.value == "shell"
        assert ToolType.PYTHON.value == "python"
        assert ToolType.HYBRID.value == "hybrid"

    def test_tool_types_count(self) -> None:
        """Ensure expected number of tool types."""
        assert len(ToolType) == 3


class TestPentestPhase:
    """Tests for PentestPhase enum."""

    def test_pentest_phases_exist(self) -> None:
        """Verify all pentest phases exist."""
        assert PentestPhase.RECON.value == "recon"
        assert PentestPhase.VULN_SCAN.value == "vuln_scan"
        assert PentestPhase.EXPLOIT.value == "exploit"
        assert PentestPhase.POST_EXPLOIT.value == "post_exploit"
        assert PentestPhase.LATERAL.value == "lateral"
        assert PentestPhase.REPORTING.value == "reporting"

    def test_pentest_phases_count(self) -> None:
        """Ensure expected number of phases."""
        assert len(PentestPhase) == 6


class TestTool:
    """Tests for Tool dataclass."""

    def test_tool_creation_minimal(self) -> None:
        """Test minimal tool creation."""
        tool = Tool(
            name="test_tool",
            type=ToolType.SHELL,
            description="A test tool",
            phase=PentestPhase.RECON,
        )
        assert tool.name == "test_tool"
        assert tool.type == ToolType.SHELL
        assert tool.description == "A test tool"
        assert tool.phase == PentestPhase.RECON
        assert tool.command_template is None
        assert tool.python_func is None
        assert tool.requires_root is False
        assert tool.timeout == 300

    def test_tool_creation_shell(self) -> None:
        """Test shell tool creation with command template."""
        tool = Tool(
            name="nmap",
            type=ToolType.SHELL,
            description="Port scanner",
            phase=PentestPhase.RECON,
            command_template="nmap -sV {target}",
            timeout=600,
        )
        assert tool.name == "nmap"
        assert tool.command_template == "nmap -sV {target}"
        assert tool.timeout == 600

    def test_tool_creation_python(self) -> None:
        """Test python tool creation with callable."""

        def mock_func(target: str) -> dict:
            return {"result": target}

        tool = Tool(
            name="recon",
            type=ToolType.PYTHON,
            description="Recon tool",
            phase=PentestPhase.RECON,
            python_func=mock_func,
        )
        assert tool.python_func == mock_func
        assert tool.python_func("test.com") == {"result": "test.com"}

    def test_tool_requires_root(self) -> None:
        """Test root requirement flag."""
        tool = Tool(
            name="stealth_scan",
            type=ToolType.SHELL,
            description="Stealth scan",
            phase=PentestPhase.RECON,
            command_template="nmap -sS {target}",
            requires_root=True,
        )
        assert tool.requires_root is True


class TestToolRegistry:
    """Tests for ToolRegistry class."""

    def test_registry_creation(self) -> None:
        """Test registry initializes with built-in tools."""
        registry = ToolRegistry()
        assert registry._tools is not None
        assert len(registry._tools) > 0

    def test_builtin_tools_registered(self) -> None:
        """Verify built-in tools are registered."""
        registry = ToolRegistry()
        # Shell tools
        assert "nmap" in registry._tools
        assert "nmap_stealth" in registry._tools
        assert "gobuster" in registry._tools
        assert "nikto" in registry._tools
        assert "sqlmap" in registry._tools
        # Python tools
        assert "passive_recon" in registry._tools
        assert "sqli_test" in registry._tools

    def test_register_new_tool(self) -> None:
        """Test registering a new tool."""
        registry = ToolRegistry()
        initial_count = len(registry._tools)

        new_tool = Tool(
            name="custom_scanner",
            type=ToolType.SHELL,
            description="Custom scanner",
            phase=PentestPhase.RECON,
            command_template="./custom_scan {target}",
        )
        registry.register(new_tool)

        assert "custom_scanner" in registry._tools
        assert len(registry._tools) == initial_count + 1
        assert registry._tools["custom_scanner"] == new_tool

    def test_get_tool(self) -> None:
        """Test getting a tool by name."""
        registry = ToolRegistry()
        tool = registry.get("nmap")
        assert tool is not None
        assert tool.name == "nmap"
        assert tool.type == ToolType.SHELL

    def test_get_nonexistent_tool(self) -> None:
        """Test getting a tool that doesn't exist."""
        registry = ToolRegistry()
        tool = registry.get("nonexistent_tool_xyz")
        assert tool is None

    def test_list_tools(self) -> None:
        """Test listing all tools."""
        registry = ToolRegistry()
        tools = registry.list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0
        assert all(isinstance(t, Tool) for t in tools)

    def test_list_tools_by_phase(self) -> None:
        """Test listing tools by phase."""
        registry = ToolRegistry()
        recon_tools = registry.list_by_phase(PentestPhase.RECON)
        assert len(recon_tools) > 0
        assert all(t.phase == PentestPhase.RECON for t in recon_tools)

    def test_list_tools_by_type(self) -> None:
        """Test listing tools by type."""
        registry = ToolRegistry()
        shell_tools = registry.list_by_type(ToolType.SHELL)
        python_tools = registry.list_by_type(ToolType.PYTHON)

        assert len(shell_tools) > 0
        assert len(python_tools) > 0
        assert all(t.type == ToolType.SHELL for t in shell_tools)
        assert all(t.type == ToolType.PYTHON for t in python_tools)


class TestToolExecution:
    """Tests for tool execution methods."""

    @pytest.mark.asyncio
    async def test_run_shell_tool_mock(self) -> None:
        """Test running a shell tool with mocked subprocess."""
        registry = ToolRegistry()

        with patch("asyncio.create_subprocess_shell") as mock_proc:
            mock_instance = AsyncMock()
            mock_instance.communicate = AsyncMock(return_value=(b"PORT   STATE SERVICE\n22/tcp open  ssh", b""))
            mock_instance.returncode = 0
            mock_proc.return_value = mock_instance

            result = await registry.run("nmap", target="127.0.0.1")

            assert result is not None
            assert "success" in result or "output" in result or result.get("returncode") == 0

    @pytest.mark.asyncio
    async def test_run_nonexistent_tool(self) -> None:
        """Test running a tool that doesn't exist."""
        registry = ToolRegistry()
        result = await registry.run("nonexistent_tool_xyz", target="test.com")
        assert result is not None
        assert "error" in result or result.get("success") is False

    @pytest.mark.asyncio
    async def test_run_python_tool_mock(self) -> None:
        """Test running a python tool with mocked function."""
        registry = ToolRegistry()

        # Mock the passive_recon internal method
        mock_result = {
            "dns": {"A": ["1.2.3.4"]},
            "headers": {"Server": "nginx"},
        }

        with patch.object(registry, "_run_passive_recon", return_value=mock_result):
            # Force re-register with mocked function
            tool = registry.get("passive_recon")
            if tool:
                tool.python_func = lambda target: mock_result
                result = await registry.run("passive_recon", target="test.com")
                assert result is not None


class TestToolSecurity:
    """Tests for tool security features."""

    def test_shell_tools_have_templates(self) -> None:
        """All shell tools must have command templates."""
        registry = ToolRegistry()
        for tool in registry.list_by_type(ToolType.SHELL):
            assert tool.command_template is not None, f"{tool.name} missing template"
            assert "{target}" in tool.command_template, f"{tool.name} missing {{target}} placeholder"

    def test_python_tools_have_functions(self) -> None:
        """All python tools must have callable functions."""
        registry = ToolRegistry()
        for tool in registry.list_by_type(ToolType.PYTHON):
            assert tool.python_func is not None, f"{tool.name} missing python_func"
            assert callable(tool.python_func), f"{tool.name} python_func not callable"

    def test_root_required_tools(self) -> None:
        """Test that root-required tools are properly flagged."""
        registry = ToolRegistry()
        root_tools = [t for t in registry.list_tools() if t.requires_root]
        # At least nmap_stealth requires root
        assert any(t.name == "nmap_stealth" for t in root_tools)


class TestToolCoverage:
    """Tests for tool coverage across phases."""

    def test_all_phases_have_tools(self) -> None:
        """Every pentest phase should have at least one tool."""
        registry = ToolRegistry()
        for phase in PentestPhase:
            tools = registry.list_by_phase(phase)
            assert len(tools) > 0, f"Phase {phase.value} has no tools"

    def test_tool_count_minimum(self) -> None:
        """Ensure minimum number of tools are registered."""
        registry = ToolRegistry()
        # We expect at least 15 built-in tools
        assert len(registry._tools) >= 15


class TestToolFormat:
    """Tests for tool output formatting."""

    def test_format_tool_info(self) -> None:
        """Test tool info formatting."""
        registry = ToolRegistry()
        info = registry.format_tool_info("nmap")
        assert info is not None
        assert "nmap" in info
        assert "recon" in info.lower() or "RECON" in info

    def test_format_all_tools(self) -> None:
        """Test formatting all tools list."""
        registry = ToolRegistry()
        formatted = registry.format_all_tools()
        assert formatted is not None
        assert len(formatted) > 0
        # Should contain multiple tool names
        assert "nmap" in formatted
        assert "nikto" in formatted or "sqlmap" in formatted
