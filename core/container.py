# core/container.py
# DRAKBEN — Lightweight Dependency Injection Container
# Centralises singleton lifecycle so tests can reset everything in one call.

"""Lightweight DI container for DRAKBEN.

Instead of scattering global singletons across 20+ modules,
register them here and let ``reset_container()`` tear them all down.

Usage::

    from core.container import get_container

    container = get_container()
    container.register("config_manager", lambda: ConfigManager())
    cm = container.resolve("config_manager")

Testing::

    from core.container import reset_container
    reset_container()  # All singletons destroyed
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class Container:
    """Thread-safe singleton registry with lazy instantiation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._factories: dict[str, Any] = {}
        self._instances: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, name: str, factory: Any) -> None:
        """Register a factory (callable) for *name*.

        If *factory* is not callable it is stored as a pre-built instance.
        """
        with self._lock:
            if callable(factory):
                self._factories[name] = factory
                self._instances.pop(name, None)  # Invalidate cached instance
            else:
                # Store directly as instance (no factory needed)
                self._instances[name] = factory
                self._factories.pop(name, None)

    def resolve(self, name: str) -> Any:
        """Resolve *name* → singleton instance (created on first call)."""
        with self._lock:
            if name in self._instances:
                return self._instances[name]
            factory = self._factories.get(name)
            if factory is None:
                msg = f"No registration for '{name}'"
                raise KeyError(msg)
            instance = factory()
            self._instances[name] = instance
            return instance

    def try_resolve(self, name: str) -> Any | None:
        """Like :meth:`resolve` but returns *None* instead of raising."""
        try:
            return self.resolve(name)
        except KeyError:
            return None

    def has(self, name: str) -> bool:
        """Check whether *name* is registered."""
        with self._lock:
            return name in self._factories or name in self._instances

    def reset(self) -> None:
        """Destroy all cached instances (factories survive)."""
        with self._lock:
            # Call .close() on instances that support it
            for inst in self._instances.values():
                _safe_close(inst)
            self._instances.clear()

    def clear(self) -> None:
        """Remove everything (instances + factories)."""
        with self._lock:
            for inst in self._instances.values():
                _safe_close(inst)
            self._instances.clear()
            self._factories.clear()


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_container: Container | None = None
_container_lock = threading.Lock()


def get_container() -> Container:
    """Return the global DI container (created on first call)."""
    global _container
    if _container is None:
        with _container_lock:
            if _container is None:
                _container = Container()
    return _container


def reset_container() -> None:
    """Reset (but don't destroy) the global container.

    Called by ``conftest.py`` between tests to avoid leaking state.
    """
    global _container  # noqa: PLW0602 – read-then-mutate requires global declaration
    if _container is not None:
        _container.reset()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _safe_close(obj: Any) -> None:
    """Call ``obj.close()`` if it exists, swallowing errors."""
    close_fn = getattr(obj, "close", None)
    if callable(close_fn):
        try:
            close_fn()
        except Exception:
            logger.debug("Error closing %s", type(obj).__name__, exc_info=True)
