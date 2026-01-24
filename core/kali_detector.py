# core/kali_detector.py
# Kali Linux Integration - Automatic Tool Detection

import platform
import shlex
import subprocess


class KaliDetector:
    """
    Automatically detects available tools on Kali Linux.
    """

    def __init__(self):
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
        self.available_tools = {}
        self._detect_tools()

    def _detect_tools(self):
        """Check which tools are available on Kali"""
        for tool_name, tool_info in self.tools.items():
            if self._check_command(tool_info["cmd"]):
                self.available_tools[tool_name] = tool_info

    def _check_command(self, cmd: str) -> bool:
        """Check if command is available in PATH"""
        try:
            # Use list form for safer execution (no shell=True)
            check_cmd = ["which", cmd] if self.system != "Windows" else ["where", cmd]
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception:
            return False

    def is_kali(self) -> bool:
        """Kali Linux üzerinde çalışıyor mu?"""
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read().lower()
                return "kali" in content
        except Exception:
            return False

    def get_available_tools(self) -> dict:
        """Mevcut araçları döndür"""
        return self.available_tools

    def suggest_tools_for_target(self, target_type: str) -> list:
        """Hedef türüne göre uygun araçları öner"""
        suggestions = []

        if target_type in ["web", "webapp"]:
            for tool in ["nikto", "sqlmap", "burp", "dirsearch", "gobuster"]:
                if tool in self.available_tools:
                    suggestions.append(tool)

        elif target_type in ["network", "host"]:
            for tool in ["nmap", "hydra", "metasploit"]:
                if tool in self.available_tools:
                    suggestions.append(tool)

        elif target_type == "password":
            for tool in ["hashcat", "john", "hydra"]:
                if tool in self.available_tools:
                    suggestions.append(tool)

        return suggestions

    def run_tool(self, tool: str, args: str) -> dict:
        """Kali aracını çalıştır"""
        if tool not in self.available_tools:
            return {"success": False, "error": f"❌ '{tool}' aracı Kali'de bulunamadı"}

        try:
            # Parse arguments safely using shlex
            cmd_list = [tool] + shlex.split(args)
            cmd_str = f"{tool} {args}"  # For display purposes
            result = subprocess.run(
                cmd_list, capture_output=True, text=True, timeout=300
            )
            return {
                "success": True,
                "tool": tool,
                "command": cmd_str,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "❌ Zaman aşımı (300s)"}
        except Exception as e:
            return {"success": False, "error": f"❌ Hata: {str(e)}"}
