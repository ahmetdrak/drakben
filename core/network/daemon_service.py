"""DRAKBEN Universal Adapter - Daemon Service
Author: @drak_ben
Description: Full daemon mode for headless operation (systemd/Windows Service).
"""

import logging
import os
import signal
import sys
import tempfile
import time

logger = logging.getLogger(__name__)


class DaemonService:
    """Cross-platform daemon/service manager for Drakben.
    Supports Linux (systemd/init.d) and Windows (pywin32).
    """

    def __init__(self, pid_file: str | None = None) -> None:
        if pid_file is None:
            pid_file = os.path.join(tempfile.gettempdir(), "drakben.pid")
        self.pid_file = pid_file
        self.running = False
        self.is_windows = sys.platform == "win32"

    def _cleanup(self) -> None:
        """Remove PID file on exit."""
        # L-5 FIX: Handle PermissionError (e.g. PID file owned by root)
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
        except OSError as e:
            logger.warning("Could not remove PID file %s: %s", self.pid_file, e)

    def _signal_handler(self, _signum: int, _frame: object) -> None:
        """Handle termination signals."""
        self.running = False
        self._cleanup()
        sys.exit(0)

    def get_pid(self) -> int | None:
        """Get running daemon PID."""
        try:
            with open(self.pid_file, encoding="utf-8") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def start(self, target_func=None) -> bool:
        """Start daemon process.

        Args:
            target_func: The main function to run as a daemon.
                         If None, just creates PID file for external process.

        Returns:
            True if daemon started successfully.
        """
        # Check if already running
        existing_pid = self.get_pid()
        if existing_pid:
            try:
                os.kill(existing_pid, 0)  # Check if process alive
                logger.warning("Daemon already running (PID: %s)", existing_pid)
                return False
            except OSError:
                # Stale PID file
                self._cleanup()

        if self.is_windows:
            return self._start_windows(target_func)
        return self._start_unix(target_func)

    def _start_unix(self, target_func=None) -> bool:
        """Start daemon on Unix (double-fork)."""
        try:
            # First fork
            pid = os.fork()
            if pid > 0:
                return True  # Parent returns

            # Decouple from parent environment
            os.setsid()
            os.umask(0o077)

            # Second fork
            pid = os.fork()
            if pid > 0:
                sys.exit(0)

            # Write PID file
            with open(self.pid_file, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))

            # Register signal handlers
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)

            self.running = True
            logger.info("Daemon started (PID: %s)", os.getpid())

            if target_func:
                target_func()
            else:
                # Keep alive loop
                while self.running:
                    time.sleep(1)

            return True
        except AttributeError:
            # os.fork not available (Windows)
            logger.error("Unix daemon mode not available on this platform")
            return False
        except OSError as e:
            logger.exception("Failed to start daemon: %s", e)
            return False

    def _start_windows(self, target_func=None) -> bool:
        """Start as a background process on Windows."""
        import subprocess as sp

        try:
            if target_func:
                # Can't fork on Windows; run target in-process
                with open(self.pid_file, "w", encoding="utf-8") as f:
                    f.write(str(os.getpid()))
                self.running = True
                logger.info("Daemon started in-process (PID: %s)", os.getpid())
                target_func()
                return True
            else:
                # Launch Python script detached
                proc = sp.Popen(
                    [sys.executable, "-m", "drakben"],
                    creationflags=sp.DETACHED_PROCESS | sp.CREATE_NEW_PROCESS_GROUP,
                    stdout=sp.DEVNULL,
                    stderr=sp.DEVNULL,
                )
                with open(self.pid_file, "w", encoding="utf-8") as f:
                    f.write(str(proc.pid))
                logger.info("Daemon started (PID: %s)", proc.pid)
                return True
        except OSError as e:
            logger.exception("Failed to start Windows daemon: %s", e)
            return False

    def stop(self) -> bool:
        """Stop running daemon."""
        pid = self.get_pid()
        if not pid:
            logger.info("Daemon not running")
            return True

        try:
            # M-11 FIX: Cross-platform process termination
            if self.is_windows:
                import subprocess

                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/F"],
                    capture_output=True,
                    check=False,
                )
            else:
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)  # Give process time to clean up on Unix
            self._cleanup()
            logger.info("Daemon stopped")
            return True
        except OSError as e:
            logger.exception("Failed to stop daemon: %s", e)
            return False

    def status(self) -> str:
        """Check daemon status."""
        pid = self.get_pid()
        if pid:
            try:
                os.kill(pid, 0)  # Check if process exists
                return f"Running (PID: {pid})"
            except OSError:
                return "Stale PID file"
        return "Not running"
