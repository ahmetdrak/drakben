# tests/test_plugin_loader.py
"""Tests for core/plugin_loader.py — PluginLoader."""

from pathlib import Path
from unittest.mock import patch

from core.plugin_loader import PluginLoader


class TestPluginLoaderInit:
    """Tests for PluginLoader initialization."""

    def test_default_dir(self, tmp_path: Path) -> None:
        with patch.object(PluginLoader, "_ensure_dir"):
            loader = PluginLoader(str(tmp_path / "plugins"))
        assert loader.plugin_dir == tmp_path / "plugins"

    def test_ensure_dir_creates_directory(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "newplugins"
        PluginLoader(str(plugin_dir))
        assert plugin_dir.exists()

    def test_ensure_dir_creates_readme(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "fresh_plugins"
        PluginLoader(str(plugin_dir))
        readme = plugin_dir / "README.txt"
        assert readme.exists()


class TestLoadPlugins:
    """Tests for plugin loading workflow."""

    def test_empty_dir(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "empty"
        plugin_dir.mkdir()
        loader = PluginLoader(str(plugin_dir))
        result = loader.load_plugins()
        assert result == {}

    def test_skip_underscore_files(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("# skip me")
        (plugin_dir / "_private.py").write_text("# skip me too")
        loader = PluginLoader(str(plugin_dir))
        result = loader.load_plugins()
        assert result == {}

    def test_missing_register_function(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "bad_plugin.py").write_text("x = 1\n")
        loader = PluginLoader(str(plugin_dir))
        result = loader.load_plugins()
        assert result == {}

    def test_register_returns_non_toolspec(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "bad_return.py").write_text(
            "def register():\n    return 'not a ToolSpec'\n",
        )
        loader = PluginLoader(str(plugin_dir))
        result = loader.load_plugins()
        assert result == {}

    def test_syntax_error_plugin(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()
        (plugin_dir / "broken.py").write_text("def register(\n")
        loader = PluginLoader(str(plugin_dir))
        # Should not raise — catches all exceptions
        result = loader.load_plugins()
        assert result == {}

    def test_valid_plugin(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        # ToolSpec is a dataclass: name, category, command_template, phase_allowed
        code = (
            "from core.execution.tool_selector import ToolSpec, ToolCategory\n"
            "from core.agent.state import AttackPhase\n"
            "def register():\n"
            "    return ToolSpec(name='test_tool', category=ToolCategory.RECON, "
            "command_template='echo test', phase_allowed=[AttackPhase.RECON])\n"
        )
        (plugin_dir / "good_plugin.py").write_text(code)
        loader = PluginLoader(str(plugin_dir))
        result = loader.load_plugins()
        assert "test_tool" in result

    def test_duplicate_name_skipped(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir()

        code = (
            "from core.execution.tool_selector import ToolSpec, ToolCategory\n"
            "from core.agent.state import AttackPhase\n"
            "def register():\n"
            "    return ToolSpec(name='dup_tool', category=ToolCategory.RECON, "
            "command_template='echo x', phase_allowed=[AttackPhase.RECON])\n"
        )
        (plugin_dir / "plugin1.py").write_text(code)
        (plugin_dir / "plugin2.py").write_text(code)

        loader = PluginLoader(str(plugin_dir))
        result = loader.load_plugins()
        # Only one of the two should be loaded
        assert len(result) == 1

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        with patch.object(PluginLoader, "_ensure_dir"):
            loader = PluginLoader(str(tmp_path / "nope"))
        result = loader.load_plugins()
        assert result == {}
