import os
import signal
import sys

import pytest

# Insert project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# This configuration file is automatically loaded by pytest
# It helps setting up the environment for all tests


@pytest.fixture(autouse=True)
def _reset_signal_handlers():
    """Prevent drakben.cleanup_resources from calling sys.exit during tests.

    When drakben.py is imported (e.g. by test_main_coverage), it registers
    SIGINT/SIGTERM handlers that call sys.exit(0).  This fixture resets them
    to defaults before and after every test so no spurious SystemExit leaks
    across test boundaries.
    """
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    yield
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
