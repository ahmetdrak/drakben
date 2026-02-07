"""DRAKBEN Universal Adapter - Daemon Service
Author: @drak_ben
Description: Full daemon mode for headless operation (systemd/Windows Service).
"""

import logging
import os
import signal
import sys
import time

logger = logging.getLogger(__name__)


class DaemonService:
    """Cross-platform daemon/service manager for Drakben.
    Supports Linux (systemd/init.d) and Windows (pywin32).
    """

    def __init__(self, pid_file: str = "/tmp/drakben.pid") -> None:
        self.pid_file = pid_file
        self.running = False
        self.is_windows = sys.platform == "win32"

    def _cleanup(self) -> None:
        """Remove PID file on exit."""
        if os.path.exists(self.pid_file):
            os.remove(self.pid_file)

    def _signal_handler(self, _signum: int, _frame: object) -> None:
        """Handle termination signals."""
        self.running = False
        self._cleanup()
        sys.exit(0)

    def get_pid(self) -> int | None:
        """Get running daemon PID."""
        try:
            with open(self.pid_file) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def stop(self) -> bool:
        """Stop running daemon."""
        pid = self.get_pid()
        if not pid:
            logger.info("Daemon not running")
            return True

        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
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
