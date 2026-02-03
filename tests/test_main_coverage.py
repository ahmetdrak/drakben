import contextlib
import os
import sys
from unittest.mock import patch

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_main_menu_launch() -> None:
    """Test main() function launching the menu."""
    # We strip drakben from sys.modules to ensure clean import with mocks active
    if "drakben" in sys.modules:
        del sys.modules["drakben"]

    with patch("core.ui.menu.DrakbenMenu") as MockMenu:
        with patch("core.config.ConfigManager"):
            with patch("core.plugin_loader.PluginLoader"):
                # Setup mocks
                mock_menu_instance = MockMenu.return_value
                mock_menu_instance.run.return_value = None

                # Dynamic import AFTER patching
                from drakben import main

                # Run main
                with contextlib.suppress(SystemExit):
                    main()

                # Now references in drakben module should point to our mocks
                # But since imports happened at top level of drakben.py, we need to check if
                # patching core.config.ConfigManager worked.
                # If drakben.py does 'from core.config import ConfigManager' at top level,
                # it binds early.

                # Check if Menu was initialized (because it is imported LOCALLY inside main)
                MockMenu.assert_called()
                mock_menu_instance.run.assert_called_once()

                # ConfigManager might fail if it was bound before patch.
                # However, since we deleted 'drakben' from sys.modules, re-importing it
                # should re-execute lines 'from core.config import ConfigManager',
                # which SHOULD pick up our patched version if we patched where it comes from.


def test_environment_check() -> None:
    """Test environment check logic."""
    # Simply test the function logic
    import drakben

    with patch("pathlib.Path.exists", return_value=False):
        with patch("pathlib.Path.mkdir") as mock_mkdir:
            with patch("sys.version_info", (3, 11)):
                drakben.check_environment()
                if mock_mkdir.call_count < 1:
                    msg = "mock_mkdir.call_count >= 1"
                    raise AssertionError(msg)
