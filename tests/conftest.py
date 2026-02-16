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
    config.addinivalue_line(
        "filterwarnings",
        "ignore:unclosed database:ResourceWarning",
    )
    config.addinivalue_line(
        "filterwarnings",
        "ignore:RC4 is cryptographically weak:DeprecationWarning",
    )


@pytest.fixture(autouse=True)
def _reset_signal_handlers():
    """Prevent drakben.cleanup_resources from calling sys.exit during tests."""
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    yield
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


@pytest.fixture(autouse=True)
def _reset_di_container():
    """Reset the global DI container between tests.

    This replaces the individual singleton reset fixtures with a single
    centralized cleanup via the DI container.
    """
    yield
    try:
        from core.container import reset_container
        reset_container()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _reset_evolution_memory_singleton():
    """Reset the global EvolutionMemory singleton between tests."""
    yield
    try:
        from core.intelligence import evolution_memory as _em

        if _em._evolution_memory is not None:
            _em._evolution_memory.close()
            _em._evolution_memory = None
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _reset_event_and_observability_singletons():
    """Reset EventBus, Tracer, and MetricsCollector singletons between tests."""
    yield
    try:
        from core.events import EventBus
        EventBus.reset()
    except Exception:
        pass
    try:
        from core.observability import MetricsCollector, Tracer
        MetricsCollector.reset()
        Tracer.reset()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _suppress_resource_warnings():
    """Force garbage collection after every test and suppress stale ResourceWarnings."""
    yield
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ResourceWarning)
        gc.collect()
