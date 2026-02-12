import gc
import os
import signal
import sys
import warnings

import pytest

# Insert project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# This configuration file is automatically loaded by pytest
# It helps setting up the environment for all tests


def pytest_configure(config: pytest.Config) -> None:
    """Register warning filters for known library/internal warnings."""
    # ChromaDB internal SQLite connections are managed by the library;
    # our code calls VectorStore.close() which stops the system, but
    # some internal connections are released during GC and emit
    # ResourceWarning.  Suppress these since we cannot control them.
    config.addinivalue_line(
        "filterwarnings",
        "ignore:unclosed database:ResourceWarning",
    )
    # RC4 DeprecationWarning is intentionally emitted by
    # weapon_foundry.py to alert callers that RC4 is weak.
    # In the test suite this is expected behaviour, not a bug.
    config.addinivalue_line(
        "filterwarnings",
        "ignore:RC4 is cryptographically weak:DeprecationWarning",
    )


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


@pytest.fixture(autouse=True)
def _reset_evolution_memory_singleton():
    """Reset the global EvolutionMemory singleton between tests.

    Prevents unclosed SQLite connections from leaking across test boundaries.
    """
    yield
    try:
        from core.intelligence import evolution_memory as _em

        if _em._evolution_memory is not None:
            _em._evolution_memory.close()
            _em._evolution_memory = None
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _suppress_resource_warnings():
    """Force garbage collection after every test and suppress stale ResourceWarnings.

    Some third-party libraries (ChromaDB, sqlite3 via functools.lru_cache)
    keep internal references that produce ResourceWarning when the GC
    finalises them.  Running gc.collect() here ensures those warnings are
    emitted (and filtered) inside the test rather than leaking.
    """
    yield
    # Suppress any resource warnings raised during GC of test objects
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        gc.collect()
