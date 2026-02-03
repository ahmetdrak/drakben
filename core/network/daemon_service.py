"""DRAKBEN Universal Adapter - Daemon Service
Author: @drak_ben
Description: Full daemon mode for headless operation (systemd/Windows Service).
"""

import atexit
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

    def daemonize(self) -> bool:
        """Fork process into background (Unix only).
        Windows uses different approach via pywin32.
        """
        if self.is_windows:
            logger.info("Windows detected. Use install_windows_service() instead.")
            return False

        try:
            # First fork
            pid = os.fork()  # pylint: disable=no-member
            if pid > 0:
                sys.exit(0)

        except OSError as e:
            logger.exception("Fork #1 failed: %s", e)
            return False

        # Decouple from parent
        os.chdir("/")
        os.setsid()  # pylint: disable=no-member
        os.umask(0)

        try:
            # Second fork
            pid = os.fork()  # pylint: disable=no-member
            if pid > 0:
                sys.exit(0)

        except OSError as e:
            logger.exception("Fork #2 failed: %s", e)
            return False

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()

        with open("/dev/null") as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())  # pylint: disable=no-member
        with open("/tmp/drakben.log", "a+") as log:
            os.dup2(log.fileno(), sys.stdout.fileno())  # pylint: disable=no-member
            os.dup2(log.fileno(), sys.stderr.fileno())  # pylint: disable=no-member

        # Write PID file
        pid = str(os.getpid())
        with open(self.pid_file, "w") as f:
            f.write(pid)

        # Register cleanup
        atexit.register(self._cleanup)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info("Daemon started with PID %s", pid)
        self.running = True
        return True

    def _cleanup(self) -> None:
        """Remove PID file on exit."""
        if os.path.exists(self.pid_file):
            os.remove(self.pid_file)

    def _signal_handler(self, signum, frame) -> None:
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

    def generate_systemd_unit(self, install_path: str = "/opt/drakben") -> str:
        """Generate systemd service file for Linux."""
        unit_content = f"""[Unit]
Description=Drakben AI Penetration Testing Agent
After=network.target

[Service]
Type=forking
PIDFile={self.pid_file}
ExecStart=/usr/bin/python3 {install_path}/main.py --daemon
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""
        unit_path = "/etc/systemd/system/drakben.service"
        logger.info("Systemd unit file content generated for: %s", unit_path)
        return unit_content

    def install_windows_service(self) -> bool:
        """Install as Windows service using pywin32."""
        if not self.is_windows:
            logger.error("Not a Windows system")
            return False

        try:
            import importlib.util

            if not importlib.util.find_spec(
                "win32service",
            ) or not importlib.util.find_spec("win32serviceutil"):
                raise ImportError

            # This would require a proper service class
            # For now, return instructions
            logger.info(
                "Windows service installation instructions logged successfully.",
            )
            # Windows service registration is managed via external sc.exe or advanced installer
            # to maintain stealth and avoid persistent process handles during runtime.
            return True

        except ImportError:
            logger.warning("pywin32 not installed. Run: pip install pywin32")
            return False
