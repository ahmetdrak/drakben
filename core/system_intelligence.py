"""
DRAKBEN System Intelligence
Author: @drak_ben
Description: 5 modules for system awareness and environment understanding
"""

import os
import sys
import platform
import subprocess
import shutil
import psutil
import socket
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class SystemInfo:
    """System information container"""
    os_name: str
    os_version: str
    architecture: str
    is_kali: bool
    is_root: bool
    has_internet: bool
    python_version: str


# ====================
# MODULE 1: SystemFingerprint
# ====================
class SystemFingerprint:
    """Detects OS, distribution, version, architecture"""
    
    def __init__(self):
        self.cached_info: Optional[SystemInfo] = None
    
    def get_system_info(self) -> SystemInfo:
        """Get comprehensive system information"""
        if self.cached_info:
            return self.cached_info
        
        # Detect OS
        os_name = platform.system()  # Linux, Windows, Darwin
        os_version = platform.release()
        architecture = platform.machine()  # x86_64, aarch64, etc.
        
        # Check if Kali Linux
        is_kali = self._is_kali_linux()
        
        # Check if root/admin
        is_root = self._is_privileged()
        
        # Check internet
        has_internet = self._check_internet()
        
        # Python version
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        
        self.cached_info = SystemInfo(
            os_name=os_name,
            os_version=os_version,
            architecture=architecture,
            is_kali=is_kali,
            is_root=is_root,
            has_internet=has_internet,
            python_version=python_version
        )
        
        return self.cached_info
    
    def _is_kali_linux(self) -> bool:
        """Check if running on Kali Linux"""
        if platform.system() != "Linux":
            return False
        
        # Check /etc/os-release
        try:
            with open("/etc/os-release", "r") as f:
                content = f.read().lower()
                return "kali" in content
        except:
            return False
    
    def _is_privileged(self) -> bool:
        """Check if running as root (Linux) or admin (Windows)"""
        if platform.system() == "Windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0
    
    def _check_internet(self) -> bool:
        """Check if internet is available"""
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except:
            return False


# ====================
# MODULE 2: EnvironmentScanner
# ====================
class EnvironmentScanner:
    """Scans for installed tools and binaries"""
    
    def __init__(self):
        self.tool_cache: Dict[str, bool] = {}
    
    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        if tool_name in self.tool_cache:
            return self.tool_cache[tool_name]
        
        result = shutil.which(tool_name) is not None
        self.tool_cache[tool_name] = result
        return result
    
    def scan_pentest_tools(self) -> Dict[str, bool]:
        """Scan for common pentesting tools"""
        tools = [
            "nmap", "masscan", "rustscan",
            "sqlmap", "nikto", "gobuster", "dirb", "ffuf",
            "metasploit", "msfconsole", "msfvenom",
            "hydra", "john", "hashcat",
            "aircrack-ng", "wireshark", "tcpdump",
            "burpsuite", "zaproxy",
            "netcat", "nc", "socat",
            "curl", "wget", "git"
        ]
        
        return {tool: self.is_tool_installed(tool) for tool in tools}
    
    def get_missing_tools(self, required_tools: List[str]) -> List[str]:
        """Get list of missing tools"""
        return [tool for tool in required_tools if not self.is_tool_installed(tool)]
    
    def suggest_install_command(self, tool: str) -> str:
        """Suggest command to install missing tool"""
        install_map = {
            "nmap": "sudo apt install nmap -y",
            "sqlmap": "sudo apt install sqlmap -y",
            "nikto": "sudo apt install nikto -y",
            "gobuster": "sudo apt install gobuster -y",
            "hydra": "sudo apt install hydra -y",
            "msfconsole": "sudo apt install metasploit-framework -y",
            "msfvenom": "sudo apt install metasploit-framework -y",
            "aircrack-ng": "sudo apt install aircrack-ng -y",
            "john": "sudo apt install john -y",
            "hashcat": "sudo apt install hashcat -y"
        }
        
        return install_map.get(tool, f"sudo apt install {tool} -y")


# ====================
# MODULE 3: PermissionManager
# ====================
class PermissionManager:
    """Manages permissions and privilege escalation"""
    
    def __init__(self):
        self.system = SystemFingerprint()
    
    def check_root(self) -> bool:
        """Check if running as root"""
        return self.system.get_system_info().is_root
    
    def can_sudo(self) -> bool:
        """Check if user can use sudo"""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False
    
    def elevate_command(self, command: str) -> str:
        """Add sudo to command if needed"""
        if self.check_root():
            return command
        
        if self.can_sudo():
            return f"sudo {command}"
        
        return command  # Return as-is, might fail
    
    def check_file_permissions(self, filepath: str) -> Dict[str, bool]:
        """Check file read/write/execute permissions"""
        return {
            "readable": os.access(filepath, os.R_OK),
            "writable": os.access(filepath, os.W_OK),
            "executable": os.access(filepath, os.X_OK)
        }


# ====================
# MODULE 4: ResourceMonitor
# ====================
class ResourceMonitor:
    """Monitors system resources (RAM, CPU, disk)"""
    
    def get_memory_info(self) -> Dict[str, float]:
        """Get memory usage information"""
        mem = psutil.virtual_memory()
        return {
            "total_gb": mem.total / (1024**3),
            "available_gb": mem.available / (1024**3),
            "used_gb": mem.used / (1024**3),
            "percent": mem.percent
        }
    
    def get_cpu_info(self) -> Dict[str, float]:
        """Get CPU usage information"""
        return {
            "percent": psutil.cpu_percent(interval=1),
            "count": psutil.cpu_count(),
            "load_avg": psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0, 0, 0)
        }
    
    def get_disk_info(self, path: str = "/") -> Dict[str, float]:
        """Get disk usage information"""
        try:
            disk = psutil.disk_usage(path)
            return {
                "total_gb": disk.total / (1024**3),
                "used_gb": disk.used / (1024**3),
                "free_gb": disk.free / (1024**3),
                "percent": disk.percent
            }
        except:
            return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}
    
    def is_resource_available(self) -> bool:
        """Check if system has enough resources"""
        mem = self.get_memory_info()
        disk = self.get_disk_info()
        
        # Need at least 1GB RAM and 5GB disk
        return mem["available_gb"] > 1.0 and disk["free_gb"] > 5.0
    
    def get_resource_summary(self) -> str:
        """Get human-readable resource summary"""
        mem = self.get_memory_info()
        cpu = self.get_cpu_info()
        disk = self.get_disk_info()
        
        return f"""
📊 System Resources:
  RAM: {mem['used_gb']:.1f}GB / {mem['total_gb']:.1f}GB ({mem['percent']:.1f}%)
  CPU: {cpu['percent']:.1f}% ({cpu['count']} cores)
  Disk: {disk['used_gb']:.1f}GB / {disk['total_gb']:.1f}GB ({disk['percent']:.1f}%)
        """.strip()


# ====================
# MODULE 5: NetworkAwareness
# ====================
class NetworkAwareness:
    """Understands network connectivity and interfaces"""
    
    def get_local_ip(self) -> Optional[str]:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return None
    
    def get_hostname(self) -> str:
        """Get system hostname"""
        return socket.gethostname()
    
    def is_connected(self) -> bool:
        """Check if internet is available"""
        return SystemFingerprint()._check_internet()
    
    def get_network_interfaces(self) -> List[str]:
        """Get list of network interfaces"""
        try:
            interfaces = psutil.net_if_addrs()
            return list(interfaces.keys())
        except:
            return []
    
    def check_port_open(self, host: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open on target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_network_summary(self) -> str:
        """Get human-readable network summary"""
        local_ip = self.get_local_ip()
        hostname = self.get_hostname()
        connected = self.is_connected()
        interfaces = self.get_network_interfaces()
        
        return f"""
🌐 Network Status:
  Hostname: {hostname}
  Local IP: {local_ip or 'Unknown'}
  Internet: {'✅ Connected' if connected else '❌ Disconnected'}
  Interfaces: {', '.join(interfaces[:3])}
        """.strip()


# ====================
# UNIFIED FACADE
# ====================
class SystemIntelligence:
    """Main facade combining all 5 modules"""
    
    def __init__(self):
        self.fingerprint = SystemFingerprint()
        self.scanner = EnvironmentScanner()
        self.permissions = PermissionManager()
        self.resources = ResourceMonitor()
        self.network = NetworkAwareness()
    
    def get_full_system_context(self) -> Dict:
        """Get complete system intelligence in one call"""
        sys_info = self.fingerprint.get_system_info()
        pentest_tools = self.scanner.scan_pentest_tools()
        
        return {
            "system": {
                "os": sys_info.os_name,
                "version": sys_info.os_version,
                "arch": sys_info.architecture,
                "is_kali": sys_info.is_kali,
                "is_root": sys_info.is_root,
                "python": sys_info.python_version
            },
            "tools": {
                "installed": [k for k, v in pentest_tools.items() if v],
                "missing": [k for k, v in pentest_tools.items() if not v]
            },
            "permissions": {
                "is_root": self.permissions.check_root(),
                "can_sudo": self.permissions.can_sudo()
            },
            "resources": {
                "memory": self.resources.get_memory_info(),
                "cpu": self.resources.get_cpu_info(),
                "disk": self.resources.get_disk_info(),
                "available": self.resources.is_resource_available()
            },
            "network": {
                "local_ip": self.network.get_local_ip(),
                "hostname": self.network.get_hostname(),
                "connected": self.network.is_connected(),
                "interfaces": self.network.get_network_interfaces()
            }
        }
    
    def get_printable_summary(self) -> str:
        """Get human-readable system summary"""
        sys_info = self.fingerprint.get_system_info()
        resource_summary = self.resources.get_resource_summary()
        network_summary = self.network.get_network_summary()
        
        return f"""
{'='*50}
🖥️  SYSTEM INTELLIGENCE
{'='*50}

💻 Operating System:
  OS: {sys_info.os_name} {sys_info.os_version}
  Architecture: {sys_info.architecture}
  Kali Linux: {'✅ Yes' if sys_info.is_kali else '❌ No'}
  Root Access: {'✅ Yes' if sys_info.is_root else '❌ No'}
  Python: {sys_info.python_version}

{resource_summary}

{network_summary}

{'='*50}
        """.strip()
