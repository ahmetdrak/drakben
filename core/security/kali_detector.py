# core/kali_detector.py
# Kali Linux Integration - Automatic Tool Detection

import platform
import subprocess


class KaliDetector:
    """Automatically detects available tools on Kali Linux."""

    def __init__(self) -> None:
        self.system = platform.system()
        self.tools = {
            "nmap": {"cmd": "nmap", "desc": "Network scanning"},
            "sqlmap": {"cmd": "sqlmap", "desc": "SQL injection testing"},
            "nikto": {"cmd": "nikto", "desc": "Web server scanning"},
            "hydra": {"cmd": "hydra", "desc": "Brute force attack"},
            "metasploit": {"cmd": "msfconsole", "desc": "Exploit framework"},
            "john": {"cmd": "john", "desc": "Password cracking"},
            "hashcat": {"cmd": "hashcat", "desc": "Hash cracking"},
            "dirsearch": {"cmd": "dirsearch", "desc": "Directory discovery"},
            "gobuster": {"cmd": "gobuster", "desc": "Brute force scanning"},
            "burp": {"cmd": "burp", "desc": "Web proxy"},
        }
        self.available_tools: dict[str, dict[str, str]] = {}
        self._detect_tools()

    def _detect_tools(self) -> None:
        """Check which tools are available on Kali."""
        for tool_name, tool_info in self.tools.items():
            if self._check_command(tool_info["cmd"]):
                self.available_tools[tool_name] = tool_info

    def _check_command(self, cmd: str) -> bool:
        """Check if command is available in PATH."""
        try:
            # Use list form for safer execution (no shell=True)
            check_cmd = ["which", cmd] if self.system != "Windows" else ["where", cmd]
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                check=False,  # We check returncode manually
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def is_kali(self) -> bool:
        """Kali Linux üzerinde çalışıyor mu?"""
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
                return "kali" in content
        except OSError:
            return False

    def get_available_tools(self) -> dict:
        """Mevcut araçları döndür."""
        return self.available_tools
