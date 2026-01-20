# core/plugins/adapters/nmap_plugin.py
# DRAKBEN Nmap Recon Plugin

import subprocess
import re
import asyncio
from typing import Dict, List, Optional
from ..base import ReconPlugin, PluginSpec, PluginResult, PluginKind


class NmapReconPlugin(ReconPlugin):
    """
    Nmap ile port tarama ve servis tespiti
    """
    
    def __init__(self, spec: PluginSpec = None):
        if spec is None:
            spec = PluginSpec(
                plugin_id="recon.nmap",
                kind=PluginKind.RECON,
                name="Nmap Scanner",
                version="1.0.0",
                description="Port scanning and service detection with Nmap",
                capabilities=["port_scan", "service_detection", "os_detection", "vuln_scan"],
                requires_approval=False,
                timeout=600
            )
        super().__init__(spec)
        self._nmap_available = None
    
    async def initialize(self) -> bool:
        """Check if nmap is available"""
        self._nmap_available = await self._check_nmap()
        self.initialized = True
        return self._nmap_available
    
    async def _check_nmap(self) -> bool:
        """Check if nmap is installed"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return proc.returncode == 0
        except FileNotFoundError:
            return False
    
    async def _do_recon(self, target: str, **kwargs) -> PluginResult:
        """Execute nmap scan"""
        scan_type = kwargs.get("scan_type", "quick")
        ports = kwargs.get("ports")
        scripts = kwargs.get("scripts")
        
        # Build nmap command
        cmd = self._build_command(target, scan_type, ports, scripts)
        
        # Execute
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.spec.timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            if proc.returncode != 0:
                return PluginResult(
                    success=False,
                    errors=[stderr.decode('utf-8', errors='ignore')],
                    output=output
                )
            
            # Parse results
            parsed = self._parse_output(output)
            
            return PluginResult(
                success=True,
                data=parsed,
                output=output,
                next_steps=self._suggest_next_steps(parsed)
            )
            
        except asyncio.TimeoutError:
            return PluginResult(
                success=False,
                errors=["Nmap scan timed out"]
            )
        except Exception as e:
            return PluginResult(
                success=False,
                errors=[str(e)]
            )
    
    def _build_command(self, target: str, scan_type: str, ports: str = None, scripts: str = None) -> str:
        """Build nmap command based on scan type"""
        
        if scan_type == "quick":
            cmd = f"nmap -T4 -F {target}"
        elif scan_type == "full":
            cmd = f"nmap -p- -sV -sC -T4 {target}"
        elif scan_type == "stealth":
            cmd = f"nmap -sS -T2 {target}"
        elif scan_type == "version":
            cmd = f"nmap -sV -T4 {target}"
        elif scan_type == "aggressive":
            cmd = f"nmap -A -T4 {target}"
        elif scan_type == "vuln":
            cmd = f"nmap --script=vuln -T4 {target}"
        else:
            cmd = f"nmap -sV -T4 {target}"
        
        if ports:
            cmd += f" -p {ports}"
        
        if scripts:
            cmd += f" --script={scripts}"
        
        return cmd
    
    def _parse_output(self, output: str) -> Dict:
        """Parse nmap output"""
        result = {
            "host_status": "unknown",
            "open_ports": [],
            "services": [],
            "os_detection": None,
            "vulnerabilities": []
        }
        
        # Check host status
        if "Host is up" in output:
            result["host_status"] = "up"
        elif "Host seems down" in output:
            result["host_status"] = "down"
        
        # Parse open ports
        port_pattern = r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?'
        for match in re.finditer(port_pattern, output):
            port_info = {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5).strip() if match.group(5) else ""
            }
            
            if port_info["state"] == "open":
                result["open_ports"].append(port_info["port"])
                result["services"].append(port_info)
        
        # Parse OS detection
        os_pattern = r'OS details:\s*(.+)'
        os_match = re.search(os_pattern, output)
        if os_match:
            result["os_detection"] = os_match.group(1).strip()
        
        # Parse vulnerabilities (from vuln scripts)
        if "VULNERABLE" in output:
            vuln_pattern = r'\|\s*(CVE-\d+-\d+)'
            for match in re.finditer(vuln_pattern, output):
                result["vulnerabilities"].append(match.group(1))
        
        return result
    
    def _suggest_next_steps(self, parsed: Dict) -> List[str]:
        """Suggest next steps based on scan results"""
        next_steps = []
        
        services = [s["service"] for s in parsed.get("services", [])]
        
        if "http" in services or "https" in services:
            next_steps.append("Web taraması yap (nikto, gobuster)")
            next_steps.append("SQL injection testi (sqlmap)")
        
        if "ssh" in services:
            next_steps.append("SSH brute force (hydra)")
        
        if "mysql" in services or "mssql" in services:
            next_steps.append("Veritabanı enumeration")
        
        if "smb" in services or "netbios-ssn" in services:
            next_steps.append("SMB enumeration (enum4linux)")
        
        if "ftp" in services:
            next_steps.append("FTP anonymous login kontrolü")
        
        if parsed.get("vulnerabilities"):
            next_steps.append("CVE exploit araştırması")
        
        return next_steps


# Quick scan shortcut
async def quick_scan(target: str) -> PluginResult:
    """Quick nmap scan helper"""
    plugin = NmapReconPlugin()
    await plugin.initialize()
    return await plugin.execute(target=target, scan_type="quick")


# Full scan shortcut
async def full_scan(target: str) -> PluginResult:
    """Full nmap scan helper"""
    plugin = NmapReconPlugin()
    await plugin.initialize()
    return await plugin.execute(target=target, scan_type="full")
