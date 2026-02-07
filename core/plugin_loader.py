# core/plugin_loader.py
# DRAKBEN Dynamic Plugin Loader
# Safe loading of external tool definitions

import importlib.util
import logging
import sys
from pathlib import Path

# Type checking imports
from core.execution.tool_selector import ToolSpec

logger = logging.getLogger(__name__)


class PluginLoader:
    """Safely loads external tool plugins from the 'plugins' directory.
    Implements strict error handling to prevent agent crashes from bad plugins.
    """

    def __init__(self, plugin_dir: str = "plugins") -> None:
        self.plugin_dir = Path(plugin_dir)
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Create plugin directory if it doesn't exist."""
        if not self.plugin_dir.exists():
            try:
                self.plugin_dir.mkdir(parents=True, exist_ok=True)
                self._create_example_plugin()
            except Exception as e:
                logger.exception("Failed to create plugin dir: %s", e)

    def _create_example_plugin(self) -> None:
        """Create a template plugin for reference."""
        readme_path = self.plugin_dir / "README.txt"
        with open(readme_path, "w") as f:
            f.write("Drop .py files here.\n")
            f.write(
                "Each file must have a 'register()' function returning a ToolSpec object.\n",
            )

    def load_plugins(self) -> dict[str, ToolSpec]:
        """Scan and load valid plugins.

        Returns:
            Dict[str, ToolSpec]: Dictionary of successfully loaded tools.

        """
        loaded_tools: dict[str, ToolSpec] = {}

        if not self.plugin_dir.exists():
            return loaded_tools

        # Iterate over .py files
        for file_path in self.plugin_dir.glob("*.py"):
            if file_path.name.startswith("_"):
                continue

            tool = self._load_single_plugin(file_path)
            if tool:
                # Check for duplicate names
                if tool.name in loaded_tools:
                    logger.warning(
                        f"Duplicate plugin tool name '{tool.name}' in {file_path.name}. Skipping.",
                    )
                    continue

                loaded_tools[tool.name] = tool
                logger.info("Plugin loaded: %s from %s", tool.name, file_path.name)

        return loaded_tools

    def _load_single_plugin(self, file_path: Path) -> ToolSpec | None:
        """Load a single plugin file safely."""
        module_name = file_path.stem

        try:
            # Dynamic import logic
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            # Namespace isolation: Prevents shadowing standard libraries
            isolated_name = f"drakben_plugins.{module_name}"
            sys.modules[isolated_name] = module
            spec.loader.exec_module(module)

            # Verification: Must have register() function
            if not hasattr(module, "register"):
                sys.modules.pop(isolated_name, None)  # Clean up
                logger.warning(
                    f"Plugin {file_path.name} missing 'register()' function.",
                )
                return None

            # Execute register to get ToolSpec
            tool_spec = module.register()

            # Validation: Must be a ToolSpec instance
            if not isinstance(tool_spec, ToolSpec):
                logger.warning(
                    f"Plugin {file_path.name} register() did not return a ToolSpec.",
                )
                return None

            return tool_spec

        except Exception as e:
            # Catch ALL errors (Syntax, Import, Runtime) so the main execution doesn't stop
            logger.exception("Failed to load plugin %s: %s", file_path.name, e)
            return None
