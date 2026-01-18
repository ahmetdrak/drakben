# core/kali_detector.py
# Kali Linux Entegrasyonu - Otomatik Araç Tespiti

import subprocess
import os
import platform

class KaliDetector:
    """
    Kali Linux üzerinde mevcut araçları otomatik olarak tespit eder
    """
    
    def __init__(self):
        self.system = platform.system()
        self.tools = {
            "nmap": {"cmd": "nmap", "desc": "Ağ taraması"},
            "sqlmap": {"cmd": "sqlmap", "desc": "SQL injection testi"},
            "nikto": {"cmd": "nikto", "desc": "Web sunucu taraması"},
            "hydra": {"cmd": "hydra", "desc": "Brute force saldırısı"},
            "metasploit": {"cmd": "msfconsole", "desc": "Exploit framework"},
            "john": {"cmd": "john", "desc": "Parola kırma"},
            "hashcat": {"cmd": "hashcat", "desc": "Hash kırma"},
            "dirsearch": {"cmd": "dirsearch", "desc": "Dizin keşfi"},
            "gobuster": {"cmd": "gobuster", "desc": "Brute force scanning"},
            "burp": {"cmd": "burp", "desc": "Web proxy"},
        }
        self.available_tools = {}
        self._detect_tools()
    
    def _detect_tools(self):
        """Kali'de hangi araçların mevcut olduğunu kontrol et"""
        for tool_name, tool_info in self.tools.items():
            if self._check_command(tool_info["cmd"]):
                self.available_tools[tool_name] = tool_info
    
    def _check_command(self, cmd: str) -> bool:
        """Komutun PATH'te mevcut olup olmadığını kontrol et"""
        try:
            result = subprocess.run(
                f"which {cmd}" if self.system != "Windows" else f"where {cmd}",
                shell=True,
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    
    def is_kali(self) -> bool:
        """Kali Linux üzerinde çalışıyor mu?"""
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read().lower()
                return "kali" in content
        except:
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
            return {
                "success": False,
                "error": f"❌ '{tool}' aracı Kali'de bulunamadı"
            }
        
        try:
            cmd = f"{tool} {args}"
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            return {
                "success": True,
                "tool": tool,
                "command": cmd,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"❌ Zaman aşımı (300s)"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"❌ Hata: {str(e)}"
            }
