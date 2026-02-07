# core/stop_controller.py
# DRAKBEN Global Stop Controller
# Ctrl+C ile tüm işlemleri durdurmak için merkezi kontrol

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class StopController:
    """Global stop controller for DRAKBEN.

    Provides a centralized way to stop:
    - LLM queries
    - Tool executions (subprocess)
    - Agent loops
    - Any long-running operation

    Usage:
        from core.stop_controller import stop_controller

        # Check if stopped
        if stop_controller.is_stopped():
            return

        # Register a cleanup callback
        stop_controller.register_cleanup(my_cleanup_func)

        # Trigger stop (usually from signal handler)
        stop_controller.stop()
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._stop_event = threading.Event()
        self._cleanup_callbacks: list[Callable[[], None]] = []
        self._active_processes: list[Any] = []  # subprocess.Popen objects
        self._active_threads: list[threading.Thread] = []
        self._callbacks_lock = threading.Lock()
        self._initialized = True

        logger.debug("StopController initialized")

    def stop(self) -> None:
        """Trigger global stop.

        This will:
        1. Set the stop flag
        2. Terminate all registered processes
        3. Call all cleanup callbacks
        """
        logger.info("🛑 Global STOP triggered!")
        self._stop_event.set()

        # Terminate active processes
        self._terminate_all_processes()

        # Run cleanup callbacks
        self._run_cleanup_callbacks()

    def reset(self) -> None:
        """Reset the stop state for new operations."""
        self._stop_event.clear()
        with self._callbacks_lock:
            self._active_processes.clear()
            self._active_threads.clear()
            self._cleanup_callbacks.clear()
        logger.debug("StopController reset")

    def is_stopped(self) -> bool:
        """Check if stop was triggered."""
        return self._stop_event.is_set()

    def register_process(self, process: Any) -> None:
        """Register an active subprocess for potential termination.

        Args:
            process: subprocess.Popen object
        """
        with self._callbacks_lock:
            self._active_processes.append(process)

    def _terminate_all_processes(self) -> None:
        """Terminate all registered processes."""
        import subprocess

        with self._callbacks_lock:
            processes = list(self._active_processes)

        for proc in processes:
            if proc is None:
                continue

            try:
                if hasattr(proc, "poll") and proc.poll() is None:
                    # Process is still running
                    logger.info("Terminating process PID=%s", proc.pid)

                    # Try graceful termination first
                    proc.terminate()

                    # Wait briefly
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        # Force kill
                        logger.warning("Force killing process PID=%s", proc.pid)
                        proc.kill()

            except OSError as e:
                logger.debug("Process already terminated: %s", e)
            except Exception as e:
                logger.warning("Error terminating process: %s", e)

    def _run_cleanup_callbacks(self) -> None:
        """Run all registered cleanup callbacks."""
        with self._callbacks_lock:
            callbacks = list(self._cleanup_callbacks)

        for callback in callbacks:
            try:
                callback()
            except Exception as e:
                logger.warning("Cleanup callback error: %s", e)


# Global singleton instance
stop_controller = StopController()


def check_stop() -> bool:
    """Convenience function to check stop status.

    Use this in long-running loops:
        while not check_stop():
            do_work()
    """
    return stop_controller.is_stopped()
