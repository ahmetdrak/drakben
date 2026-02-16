# core/agent/recovery/healer.py
"""Self-healing and error recovery module for DRAKBEN.

This module handles automatic error recovery including:
- Tool installation
- Permission fixes
- Connection retries
- Resource cleanup
- Healing success rate tracking
"""

import logging
import os
import platform
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from rich.console import Console

if TYPE_CHECKING:
    from core.execution.execution_engine import ExecutionEngine

logger = logging.getLogger(__name__)


@dataclass
class HealingStats:
    """Tracks healing attempt outcomes for success rate measurement."""

    total_attempts: int = 0
    successful_heals: int = 0
    failed_heals: int = 0
    by_error_type: dict[str, dict[str, int]] = field(default_factory=dict)

    def record(self, error_type: str, success: bool) -> None:
        """Record a healing attempt outcome."""
        self.total_attempts += 1
        if success:
            self.successful_heals += 1
        else:
            self.failed_heals += 1

        if error_type not in self.by_error_type:
            self.by_error_type[error_type] = {"attempts": 0, "successes": 0}
        self.by_error_type[error_type]["attempts"] += 1
        if success:
            self.by_error_type[error_type]["successes"] += 1

    @property
    def success_rate(self) -> float:
        """Return overall success rate as a percentage (0.0–100.0)."""
        if self.total_attempts == 0:
            return 0.0
        return (self.successful_heals / self.total_attempts) * 100.0

    def get_report(self) -> dict[str, Any]:
        """Return a summary report dict."""
        return {
            "total_attempts": self.total_attempts,
            "successful_heals": self.successful_heals,
            "failed_heals": self.failed_heals,
            "success_rate": round(self.success_rate, 1),
            "by_error_type": dict(self.by_error_type),
        }


class SelfHealer:
    """Handles automatic error recovery and healing.

    Cognitive Complexity kept low by using a dispatch table
    instead of large if-elif chains.
    """

    def __init__(self, executor: "ExecutionEngine", console: Console | None = None):
        """Initialize healer with executor and console.

        Args:
            executor: ExecutionEngine instance for running commands
            console: Rich Console for output (optional)

        """
        self.executor = executor
        self.console = console or Console()
        self.stats = HealingStats()
        self._healing_map = {
            "missing_tool": self._heal_missing_tool,
            "permission_denied": self._heal_permission_denied,
            "python_module_missing": self._heal_python_module_missing,
            "connection_error": self._heal_connection_error,
            "timeout": self._heal_timeout,
            "library_missing": self._heal_library_missing,
            "rate_limit": self._heal_rate_limit,
            "port_in_use": self._heal_port_in_use,
            "disk_full": self._heal_disk_full,
            "firewall_blocked": self._heal_firewall_blocked,
            "database_error": self._heal_database_error,
        }

    def apply_healing(
        self,
        error_diagnosis: dict[str, Any],
        tool_name: str,
        command: str,
    ) -> tuple[bool, Any]:
        """Apply error-specific healing strategy.

        Args:
            error_diagnosis: Error diagnosis dict with 'type' key
            tool_name: Name of the tool that failed
            command: Original command that failed

        Returns:
            Tuple of (healed: bool, retry_result or None)

        """
        error_type = error_diagnosis.get("type", "unknown")
        healing_func = self._healing_map.get(error_type)

        if healing_func:
            healed, result = healing_func(tool_name, command, error_diagnosis)
            self.stats.record(error_type, healed)
            logger.info(
                "Healing %s for %s: %s",
                error_type,
                tool_name,
                "SUCCESS" if healed else "FAILED",
            )
            return healed, result

        return False, None

    def get_healing_stats(self) -> dict[str, Any]:
        """Return healing success statistics report."""
        return self.stats.get_report()

    def _heal_missing_tool(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal missing tool error by auto-installing."""
        if self._install_tool(tool_name):
            self.console.print(
                f"🔄 {tool_name} yüklendi, yeniden deneniyor...",
                style="cyan",
            )
            retry_result = self.executor.terminal.execute(command, timeout=300)
            return retry_result.exit_code == 0, retry_result
        return False, None

    def _heal_permission_denied(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal permission denied by trying sudo."""
        if platform.system().lower() == "windows":
            return False, None

        if command.startswith("sudo"):
            return False, None

        self.console.print("🔐 İzin hatası - sudo ile deneniyor...", style="yellow")
        sudo_cmd = f"sudo {command}"
        retry_result = self.executor.terminal.execute(sudo_cmd, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_python_module_missing(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal missing Python module by pip install.

        Security:
        - Module name regex sanitization
        - Whitelist of known-safe packages
        - Rejects suspicious module names
        """
        module_name = error_diagnosis.get("module")
        if not module_name:
            return False, None

        # Security: Sanitize module name to prevent command injection
        import re

        if not re.match(r"^[a-zA-Z0-9_-]+$", module_name):
            logger.warning("Invalid module name format: %s", module_name)
            return False, None

        # Security: Whitelist of known-safe pentest-related packages
        _SAFE_PACKAGES = frozenset(
            {
                "requests",
                "beautifulsoup4",
                "bs4",
                "lxml",
                "paramiko",
                "scapy",
                "impacket",
                "pycryptodome",
                "cryptography",
                "dnspython",
                "python-nmap",
                "shodan",
                "censys",
                "rich",
                "colorama",
                "tqdm",
                "tabulate",
                "aiohttp",
                "httpx",
                "urllib3",
                "certifi",
                "pyyaml",
                "toml",
                "jinja2",
                "markdown",
                "pillow",
                "python-whois",
                "netaddr",
                "ipaddress",
            }
        )

        if module_name.lower() not in _SAFE_PACKAGES:
            logger.warning(
                "Module '%s' not in safe whitelist, skipping auto-install",
                module_name,
            )
            return False, None

        self.console.print(
            f"📦 Python modülü eksik: {module_name} - yükleniyor...",
            style="yellow",
        )
        pip_result = self.executor.terminal.execute(
            f"pip install {module_name}",
            timeout=120,
        )

        if pip_result.exit_code != 0:
            return False, None

        self.console.print(
            f"✅ {module_name} yüklendi, yeniden deneniyor...",
            style="green",
        )
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_connection_error(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal connection error by retrying with backoff."""
        self.console.print(
            "🌐 Bağlantı hatası - 3 saniye bekleyip yeniden deneniyor...",
            style="yellow",
        )
        time.sleep(3)
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_timeout(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal timeout by retrying with longer timeout."""
        self.console.print(
            "⏱️ Zaman aşımı - daha uzun timeout ile deneniyor...",
            style="yellow",
        )
        retry_result = self.executor.terminal.execute(command, timeout=600)
        return retry_result.exit_code == 0, retry_result

    def _heal_library_missing(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal missing library by installing system package."""
        library = error_diagnosis.get("library", "")
        if not library:
            return False, None

        self.console.print(
            f"📚 Kütüphane eksik: {library} - yükleniyor...",
            style="yellow",
        )

        install_cmd = self._get_library_install_cmd(library)
        if not install_cmd:
            return False, None

        install_result = self.executor.terminal.execute(install_cmd, timeout=180)
        if install_result.exit_code != 0:
            return False, None

        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _get_library_install_cmd(self, library: str) -> str | None:
        """Get install command for a library based on OS."""
        system = platform.system().lower()
        lib_pkg_map = {
            "libssl": "openssl" if system == "darwin" else "libssl-dev",
            "libcrypto": "openssl" if system == "darwin" else "libssl-dev",
            "libffi": "libffi-dev",
            "libpython": "python3-dev",
        }
        pkg = lib_pkg_map.get(library.split(".")[0], library)

        if system == "linux":
            return f"sudo apt-get install -y {pkg}"
        if system == "darwin":
            return f"brew install {pkg}"
        return None

    def _heal_rate_limit(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal rate limit by waiting and retrying."""
        self.console.print("⏳ İstek limiti - 30 saniye bekleniyor...", style="yellow")
        time.sleep(30)
        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _heal_port_in_use(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal port in use by killing process."""
        port = error_diagnosis.get("port")
        if not port:
            return False, None

        self.console.print(
            f"🔌 Port {port} kullanımda - işlem sonlandırılıyor...",
            style="yellow",
        )

        kill_cmd = self._get_port_kill_cmd(port)
        self.executor.terminal.execute(kill_cmd, timeout=30)
        time.sleep(2)

        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _get_port_kill_cmd(self, port: str) -> str:
        """Get command to kill process using a port."""
        # Validate port is numeric to prevent command injection
        if not str(port).isdigit():
            logger.warning("Invalid port value: %s", port)
            return "echo 'Invalid port'"
        port = str(port)
        if platform.system().lower() == "windows":
            return f'for /f "tokens=5" %a in (\'netstat -aon ^| find ":{port}"\') do taskkill /F /PID %a'
        return f"sudo fuser -k {port}/tcp 2>/dev/null || sudo lsof -ti:{port} | xargs -r sudo kill -9"

    def _heal_disk_full(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal disk full by cleaning up."""
        self.console.print(
            "💾 Disk alanı yetersiz - temizlik yapılıyor...",
            style="yellow",
        )

        cleanup_cmd = self._get_cleanup_cmd()
        self.executor.terminal.execute(cleanup_cmd, timeout=60)

        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _get_cleanup_cmd(self) -> str:
        """Get cleanup command based on OS."""
        if platform.system().lower() == "windows":
            return "del /q/f/s %TEMP%\\* 2>nul"
        return "sudo apt-get clean 2>/dev/null; rm -rf /tmp/drakben* 2>/dev/null; rm -rf ~/.cache/drakben* 2>/dev/null"

    def _heal_firewall_blocked(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal firewall blocked by waiting and trying slower."""
        self.console.print(
            "🛡️ Güvenlik duvarı engeli - stealth modda deneniyor...",
            style="yellow",
        )
        time.sleep(10)

        # Slow down scan if possible
        slower_cmd = command.replace("-T4", "-T1").replace("-T5", "-T2")
        timeout = 600 if slower_cmd != command else 300

        retry_result = self.executor.terminal.execute(slower_cmd, timeout=timeout)
        return retry_result.exit_code == 0, retry_result

    def _heal_database_error(
        self,
        tool_name: str,
        command: str,
        error_diagnosis: dict[str, Any],
    ) -> tuple[bool, Any]:
        """Heal database error by removing lock files."""
        self.console.print(
            "🗄️ Veritabanı hatası - düzeltme deneniyor...",
            style="yellow",
        )

        self._cleanup_db_locks()

        retry_result = self.executor.terminal.execute(command, timeout=300)
        return retry_result.exit_code == 0, retry_result

    def _cleanup_db_locks(self) -> None:
        """Remove database lock files."""
        from pathlib import Path

        # Search in project directory and common data directories
        search_dirs = [Path.cwd(), Path.cwd() / "sessions", Path.cwd() / "drakben_vectors"]
        patterns = ["*.db-journal", "*.db-wal", "*.db-shm"]
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue
            for pattern in patterns:
                for lock_file in search_dir.glob(pattern):
                    try:
                        os.remove(lock_file)
                        self.console.print(f"  🗑️ {lock_file} silindi", style="dim")
                    except OSError as e:
                        logger.debug("Could not remove %s: %s", lock_file, e)

    def _install_tool(self, tool_name: str) -> bool:
        """Attempt to install a missing tool.

        Args:
            tool_name: Name of the tool to install

        Returns:
            True if installation succeeded

        """
        # Common tool install mappings
        install_map = {
            "nmap": "nmap",
            "nikto": "nikto",
            "sqlmap": "sqlmap",
            "dirb": "dirb",
            "gobuster": "gobuster",
            "hydra": "hydra",
            "john": "john",
            "hashcat": "hashcat",
            "wpscan": "gem install wpscan",
            "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        }

        if tool_name not in install_map:
            return False

        system = platform.system().lower()
        if system == "linux":
            install_cmd = f"sudo apt-get install -y {install_map[tool_name]}"
        elif system == "darwin":
            install_cmd = f"brew install {install_map[tool_name]}"
        else:
            return False

        self.console.print(f"📥 {tool_name} yükleniyor...", style="cyan")
        result = self.executor.terminal.execute(install_cmd, timeout=180)
        return result.exit_code == 0
