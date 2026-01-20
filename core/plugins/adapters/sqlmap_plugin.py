# core/plugins/adapters/sqlmap_plugin.py
# DRAKBEN SQLMap Exploit Plugin

import subprocess
import asyncio
import re
from typing import Dict, List, Optional
from ..base import ExploitPlugin, PluginSpec, PluginResult, PluginKind


class SqlmapExploitPlugin(ExploitPlugin):
    """
    SQLMap ile SQL Injection testi ve exploitation
    """
    
    def __init__(self, spec: PluginSpec = None):
        if spec is None:
            spec = PluginSpec(
                plugin_id="exploit.sqlmap",
                kind=PluginKind.EXPLOIT,
                name="SQLMap",
                version="1.0.0",
                description="SQL injection testing and exploitation with SQLMap",
                capabilities=["sqli_detect", "sqli_exploit", "db_dump", "os_shell"],
                requires_approval=True,
                timeout=600
            )
        super().__init__(spec)
        self._sqlmap_available = None
    
    async def initialize(self) -> bool:
        """Check if sqlmap is available"""
        self._sqlmap_available = await self._check_sqlmap()
        self.initialized = True
        return self._sqlmap_available
    
    async def _check_sqlmap(self) -> bool:
        """Check if sqlmap is installed"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "sqlmap", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return proc.returncode == 0
        except FileNotFoundError:
            return False
    
    async def _do_exploit(self, target: str, vulnerability: str = None, **kwargs) -> PluginResult:
        """Execute SQLMap scan"""
        level = kwargs.get("level", 1)
        risk = kwargs.get("risk", 1)
        mode = kwargs.get("mode", "detect")  # detect, dbs, tables, dump
        cookies = kwargs.get("cookies")
        data = kwargs.get("data")  # POST data
        
        # Build command
        cmd = self._build_command(target, mode, level, risk, cookies, data)
        
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
            
            # Parse results
            parsed = self._parse_output(output)
            
            return PluginResult(
                success=parsed.get("vulnerable", False) or parsed.get("databases"),
                data=parsed,
                output=output,
                warnings=self._get_warnings(output),
                next_steps=self._suggest_next_steps(parsed, mode)
            )
            
        except asyncio.TimeoutError:
            return PluginResult(
                success=False,
                errors=["SQLMap scan timed out"]
            )
        except Exception as e:
            return PluginResult(
                success=False,
                errors=[str(e)]
            )
    
    def _build_command(self, target: str, mode: str, level: int, risk: int, 
                       cookies: str = None, data: str = None) -> str:
        """Build sqlmap command"""
        
        cmd = f"sqlmap -u '{target}' --batch --level={level} --risk={risk}"
        
        if cookies:
            cmd += f" --cookie='{cookies}'"
        
        if data:
            cmd += f" --data='{data}'"
        
        # Mode-specific options
        if mode == "dbs":
            cmd += " --dbs"
        elif mode == "tables":
            db = self.get_context("database")
            if db:
                cmd += f" -D {db} --tables"
            else:
                cmd += " --dbs"
        elif mode == "dump":
            db = self.get_context("database")
            table = self.get_context("table")
            if db and table:
                cmd += f" -D {db} -T {table} --dump"
            elif db:
                cmd += f" -D {db} --dump"
        elif mode == "os_shell":
            cmd += " --os-shell"
        
        return cmd
    
    def _parse_output(self, output: str) -> Dict:
        """Parse SQLMap output"""
        result = {
            "vulnerable": False,
            "injection_type": None,
            "parameter": None,
            "databases": [],
            "tables": [],
            "columns": [],
            "data": []
        }
        
        # Check if vulnerable
        if "is vulnerable" in output.lower() or "parameter is vulnerable" in output.lower():
            result["vulnerable"] = True
        
        # Find injection type
        injection_types = ["boolean-based blind", "time-based blind", "UNION query", 
                         "error-based", "stacked queries"]
        for inj_type in injection_types:
            if inj_type.lower() in output.lower():
                result["injection_type"] = inj_type
                break
        
        # Find vulnerable parameter
        param_pattern = r"Parameter:\s*(\S+)"
        param_match = re.search(param_pattern, output)
        if param_match:
            result["parameter"] = param_match.group(1)
        
        # Parse databases
        db_pattern = r"\[\*\]\s*(\S+)"
        if "available databases" in output.lower():
            db_section = output.split("available databases")[1].split("[")[0]
            result["databases"] = re.findall(db_pattern, output)
        
        return result
    
    def _get_warnings(self, output: str) -> List[str]:
        """Extract warnings from output"""
        warnings = []
        
        if "WAF/IPS" in output:
            warnings.append("Web Application Firewall detected")
        
        if "connection timed out" in output.lower():
            warnings.append("Connection timeouts occurred")
        
        return warnings
    
    def _suggest_next_steps(self, parsed: Dict, mode: str) -> List[str]:
        """Suggest next steps"""
        next_steps = []
        
        if parsed.get("vulnerable"):
            if mode == "detect":
                next_steps.append("Veritabanlarını listele (--dbs)")
                next_steps.append("OS shell dene (--os-shell)")
            
            if parsed.get("databases"):
                next_steps.append("Tabloları listele")
                next_steps.append("Veri dump et")
        else:
            next_steps.append("Level/risk değerlerini artır")
            next_steps.append("POST parametrelerini dene")
            next_steps.append("Cookie'leri kontrol et")
        
        return next_steps


# Quick SQLi test shortcut
async def test_sqli(url: str, level: int = 1) -> PluginResult:
    """Quick SQL injection test"""
    plugin = SqlmapExploitPlugin()
    await plugin.initialize()
    return await plugin.execute(target=url, mode="detect", level=level)
