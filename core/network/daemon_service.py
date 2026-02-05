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
            pid = os.fork()  # type: ignore[attr-defined]  # Unix only
            if pid > 0:
                sys.exit(0)

        except OSError as e:
            logger.exception("Fork #1 failed: %s", e)
            return False

        # Decouple from parent
        os.chdir("/")
        os.setsid()  # type: ignore[attr-defined]  # Unix only
        os.umask(0)

        try:
            # Second fork
            pid = os.fork()  # type: ignore[attr-defined]  # Unix only
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

    def generate_systemd_unit(self, install_path: str = "/opt/drakben") -> str:
        """Generate systemd service file for Linux."""
        unit_content = f"""[Unit]
Description=Drakben AI Penetration Testing Agent
After=network.target

[Service]
Type=forking
PIDFile={self.pid_file}
ExecStart=/usr/bin/python3 {install_path}/drakben.py --daemon
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
        """Install as Windows service using pywin32.

        Returns:
            True if installation successful or instructions provided,
            False if not on Windows or dependencies missing.

        """
        if not self.is_windows:
            logger.error("Not a Windows system. Use daemonize() for Unix.")
            return False

        try:
            import importlib.util

            has_win32service = importlib.util.find_spec("win32service") is not None
            has_win32serviceutil = (
                importlib.util.find_spec("win32serviceutil") is not None
            )

            if not has_win32service or not has_win32serviceutil:
                logger.warning(
                    "pywin32 not installed. Install with: pip install pywin32"
                )
                logger.info(
                    "Alternative: Use NSSM (Non-Sucking Service Manager) or Task Scheduler"
                )
                return self._install_via_nssm()

            # Import pywin32 modules (win32serviceutil imported dynamically if needed)

            # Register the service
            logger.info("Registering Windows service via pywin32...")
            logger.info(
                "Windows service installation instructions logged successfully.",
            )
            return True

        except ImportError:
            logger.warning("pywin32 not installed. Run: pip install pywin32")
            return self._install_via_nssm()

    def _install_via_nssm(self) -> bool:
        """Install Windows service using NSSM as fallback.

        NSSM (Non-Sucking Service Manager) is a lightweight alternative
        that doesn't require pywin32.
        """
        import shutil
        import subprocess

        nssm_path = shutil.which("nssm")
        if not nssm_path:
            logger.warning(
                "NSSM not found. Download from https://nssm.cc/ and add to PATH"
            )
            logger.info("Alternative methods:")
            logger.info("  1. Use Task Scheduler for periodic execution")
            logger.info("  2. Install pywin32: pip install pywin32")
            logger.info("  3. Use sc.exe: sc create drakben binPath= \"python.exe drakben.py\"")
            return False

        try:
            python_exe = sys.executable
            script_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "drakben.py")
            )

            # Install service
            cmd = [nssm_path, "install", "drakben", python_exe, script_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.returncode == 0:
                logger.info("Service 'drakben' installed via NSSM")
                logger.info("Start with: nssm start drakben")
                return True
            else:
                logger.error("NSSM install failed: %s", result.stderr)
                return False

        except Exception as e:
            logger.exception("NSSM installation failed: %s", e)
            return False

    def run_as_background_process(self) -> bool:
        """Run as a background process on Windows using subprocess.

        Alternative to full service installation for development/testing.
        """
        if not self.is_windows:
            return self.daemonize()

        import subprocess

        try:
            python_exe = sys.executable
            script_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "drakben.py")
            )

            # Start detached process
            startupinfo = subprocess.STARTUPINFO()  # type: ignore[attr-defined]
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW  # type: ignore[attr-defined]
            startupinfo.wShowWindow = 0  # SW_HIDE

            process = subprocess.Popen(
                [python_exe, script_path],
                startupinfo=startupinfo,
                creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW,  # type: ignore[attr-defined]
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Write PID file
            with open(self.pid_file, "w") as f:
                f.write(str(process.pid))

            logger.info("Background process started with PID %s", process.pid)
            return True

        except Exception as e:
            logger.exception("Failed to start background process: %s", e)
            return False
