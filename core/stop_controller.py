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
    _initialized: bool = False

    def __new__(cls):
        """Singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized: bool = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._stop_event = threading.Event()
        self._cleanup_callbacks: list[Callable[[], None]] = []
        self._active_processes: list[Any] = []  # subprocess.Popen objects
        self._active_threads: list[threading.Thread] = []
        self._callbacks_lock = threading.Lock()
        self._shutdown_timeout: float = 10.0  # seconds
        self._shutdown_phases: list[str] = []  # completed phase names
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

    def graceful_shutdown(self, timeout: float | None = None) -> dict[str, Any]:
        """Perform a full graceful shutdown with phased teardown.

        Phases:
        1. Signal stop to all loops
        2. Drain active processes
        3. Flush logs and observability data
        4. Close database connections
        5. Run custom cleanup callbacks

        Returns:
            Summary dict with completed phases and any errors.
        """
        effective_timeout = timeout or self._shutdown_timeout
        errors: list[str] = []
        self._shutdown_phases = []

        # Phase 1: Signal stop
        logger.info("Shutdown Phase 1: Signal stop")
        self._stop_event.set()
        self._shutdown_phases.append("signal")

        # Phase 2: Drain processes
        logger.info("Shutdown Phase 2: Drain active processes")
        try:
            self._terminate_all_processes()
            self._shutdown_phases.append("drain_processes")
        except Exception as exc:
            errors.append(f"drain_processes: {exc}")

        # Phase 3: Flush observability
        logger.info("Shutdown Phase 3: Flush observability")
        try:
            self._flush_observability()
            self._shutdown_phases.append("flush_observability")
        except Exception as exc:
            errors.append(f"flush_observability: {exc}")

        # Phase 4: Close databases
        logger.info("Shutdown Phase 4: Close databases")
        try:
            self._close_databases()
            self._shutdown_phases.append("close_databases")
        except Exception as exc:
            errors.append(f"close_databases: {exc}")

        # Phase 5: Custom callbacks
        logger.info("Shutdown Phase 5: Custom cleanup callbacks")
        try:
            self._run_cleanup_callbacks()
            self._shutdown_phases.append("cleanup_callbacks")
        except Exception as exc:
            errors.append(f"cleanup_callbacks: {exc}")

        # Phase 6: Wait for threads to finish
        logger.info("Shutdown Phase 6: Join threads")
        try:
            self._join_threads(effective_timeout)
            self._shutdown_phases.append("join_threads")
        except Exception as exc:
            errors.append(f"join_threads: {exc}")

        status = "clean" if not errors else "partial"
        logger.info("Shutdown complete: status=%s, phases=%d, errors=%d",
                     status, len(self._shutdown_phases), len(errors))

        return {
            "status": status,
            "completed_phases": list(self._shutdown_phases),
            "errors": errors,
        }

    def reset(self) -> None:
        """Reset the stop state for new operations."""
        self._stop_event.clear()
        with self._callbacks_lock:
            self._active_processes.clear()
            self._active_threads.clear()
            self._cleanup_callbacks.clear()
        self._shutdown_phases = []
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

    def register_cleanup(self, callback: Callable[[], None]) -> None:
        """Register a cleanup callback to run on stop.

        Args:
            callback: A callable with no arguments, invoked during stop.
        """
        with self._callbacks_lock:
            self._cleanup_callbacks.append(callback)

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

    @staticmethod
    def _flush_observability() -> None:
        """Flush traces and metrics to disk."""
        try:
            from core.observability import get_metrics, get_tracer
            tracer = get_tracer()
            if hasattr(tracer, "export_json"):
                tracer.export_json("logs/traces_shutdown.json")
            metrics = get_metrics()
            if hasattr(metrics, "export_json"):
                metrics.export_json("logs/metrics_shutdown.json")
        except ImportError:
            pass

    @staticmethod
    def _close_databases() -> None:
        """Close known database connections."""
        # Evolution memory
        try:
            from core.intelligence import evolution_memory as _em
            if _em._evolution_memory is not None:
                _em._evolution_memory.close()
                _em._evolution_memory = None
        except (ImportError, OSError):
            pass
        # DI container
        try:
            from core.container import reset_container
            reset_container()
        except (ImportError, OSError):
            pass

    def _join_threads(self, timeout: float) -> None:
        """Wait for registered threads to finish."""
        with self._callbacks_lock:
            threads = [t for t in self._active_threads if t.is_alive()]

        per_thread = max(1.0, timeout / max(len(threads), 1))
        for t in threads:
            t.join(timeout=per_thread)


# Global singleton instance
stop_controller = StopController()


def check_stop() -> bool:
    """Convenience function to check stop status.

    Use this in long-running loops:
        while not check_stop():
            do_work()
    """
    return stop_controller.is_stopped()
