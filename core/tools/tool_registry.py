# core/tools/tool_registry.py
# DRAKBEN Tool Registry - Central Hub for All Tools
# Author: @drak_ben
"""
Tool Registry: Maps tool names to their implementations.

This is the "nervous system" that connects:
- Shell commands (nmap, nikto, sqlmap)
- Python modules (modules/recon.py, modules/exploit/)
- Singularity (code generation)
- Hive Mind (AD attacks, lateral movement)

Each tool has:
- name: Unique identifier
- type: shell | python | hybrid
- module: Python module path (for python/hybrid)
- command: Shell command template (for shell/hybrid)
- description: What it does
- phase: Which pentest phase it belongs to
"""

import asyncio
import logging
import shlex
import subprocess
import threading as _tr_threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ToolType(Enum):
    """Tool execution type."""
    SHELL = "shell"       # Direct shell command
    PYTHON = "python"     # Python module function
    HYBRID = "hybrid"     # Both (Python wrapper around shell)


class PentestPhase(Enum):
    """Pentest phases for tool categorization."""
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    LATERAL = "lateral"
    REPORTING = "reporting"


@dataclass
class Tool:
    """Tool definition."""
    name: str
    type: ToolType
    description: str
    phase: PentestPhase
    command_template: str | None = None  # For shell tools: "nmap -sV {target}"
    python_func: Callable | None = None  # For python tools
    requires_root: bool = False
    timeout: int = 300


class ToolRegistry:
    """Central registry for all pentesting tools."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._register_builtin_tools()

    def _register_builtin_tools(self) -> None:
        """Register all built-in tools."""
        # =================================================================
        # SHELL TOOLS (Direct command execution)
        # =================================================================

        # RECON Phase
        self.register(Tool(
            name="nmap",
            type=ToolType.SHELL,
            description="Network port scanner and service detection",
            phase=PentestPhase.RECON,
            command_template="nmap -sV -sC -T4 {target}",
            timeout=600,
        ))

        self.register(Tool(
            name="nmap_stealth",
            type=ToolType.SHELL,
            description="Stealthy SYN scan",
            phase=PentestPhase.RECON,
            command_template="nmap -sS -T2 -f {target}",
            requires_root=True,
            timeout=900,
        ))

        self.register(Tool(
            name="nmap_vuln",
            type=ToolType.SHELL,
            description="Nmap vulnerability scripts",
            phase=PentestPhase.VULN_SCAN,
            command_template="nmap --script vuln {target}",
            timeout=900,
        ))

        self.register(Tool(
            name="gobuster",
            type=ToolType.SHELL,
            description="Directory and file bruteforcing",
            phase=PentestPhase.RECON,
            command_template="gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q",
            timeout=600,
        ))

        self.register(Tool(
            name="ffuf",
            type=ToolType.SHELL,
            description="Fast web fuzzer",
            phase=PentestPhase.RECON,
            command_template="ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302",
            timeout=600,
        ))

        # VULN_SCAN Phase
        self.register(Tool(
            name="nikto",
            type=ToolType.SHELL,
            description="Web server vulnerability scanner",
            phase=PentestPhase.VULN_SCAN,
            command_template="nikto -h {target}",
            timeout=900,
        ))

        self.register(Tool(
            name="nuclei",
            type=ToolType.SHELL,
            description="Fast vulnerability scanner with templates",
            phase=PentestPhase.VULN_SCAN,
            command_template="nuclei -u http://{target} -severity medium,high,critical",
            timeout=600,
        ))

        # EXPLOIT Phase
        self.register(Tool(
            name="sqlmap",
            type=ToolType.SHELL,
            description="SQL injection detection and exploitation",
            phase=PentestPhase.EXPLOIT,
            command_template="sqlmap -u http://{target}/ --forms --batch --level=2",
            timeout=900,
        ))

        self.register(Tool(
            name="hydra",
            type=ToolType.SHELL,
            description="Password bruteforce tool",
            phase=PentestPhase.EXPLOIT,
            command_template="hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} ssh -t 4",
            timeout=1800,
        ))

        # Additional RECON Tools
        self.register(Tool(
            name="whatweb",
            type=ToolType.SHELL,
            description="Web fingerprinting and technology detection",
            phase=PentestPhase.RECON,
            command_template="whatweb -v {target}",
            timeout=120,
        ))

        self.register(Tool(
            name="amass",
            type=ToolType.SHELL,
            description="Subdomain enumeration and OSINT",
            phase=PentestPhase.RECON,
            command_template="amass enum -passive -d {target}",
            timeout=600,
        ))

        self.register(Tool(
            name="subfinder",
            type=ToolType.SHELL,
            description="Fast subdomain discovery",
            phase=PentestPhase.RECON,
            command_template="subfinder -d {target} -silent",
            timeout=300,
        ))

        self.register(Tool(
            name="feroxbuster",
            type=ToolType.SHELL,
            description="Fast content discovery tool",
            phase=PentestPhase.RECON,
            command_template="feroxbuster -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q",
            timeout=600,
        ))

        # Additional AD/Lateral Tools
        self.register(Tool(
            name="enum4linux",
            type=ToolType.SHELL,
            description="Windows/Samba enumeration",
            phase=PentestPhase.RECON,
            command_template="enum4linux -a {target}",
            timeout=300,
        ))

        self.register(Tool(
            name="crackmapexec",
            type=ToolType.SHELL,
            description="Swiss army knife for pentesting networks",
            phase=PentestPhase.EXPLOIT,
            command_template="crackmapexec smb {target}",
            timeout=300,
        ))

        self.register(Tool(
            name="impacket_secretsdump",
            type=ToolType.SHELL,
            description="Credential dumping via Impacket",
            phase=PentestPhase.POST_EXPLOIT,
            command_template="impacket-secretsdump {target}",
            timeout=300,
        ))

        self.register(Tool(
            name="bloodhound",
            type=ToolType.SHELL,
            description="Active Directory attack path mapping",
            phase=PentestPhase.RECON,
            command_template="bloodhound-python -d {target} -c All",
            timeout=600,
        ))

        self.register(Tool(
            name="responder",
            type=ToolType.SHELL,
            description="LLMNR/NBT-NS/MDNS poisoner",
            phase=PentestPhase.EXPLOIT,
            command_template="responder -I eth0 -wrf -v 2>&1 | tee responder_{target}.log",
            requires_root=True,
            timeout=3600,
        ))

        # Web Security Tools
        self.register(Tool(
            name="wpscan",
            type=ToolType.SHELL,
            description="WordPress security scanner",
            phase=PentestPhase.VULN_SCAN,
            command_template="wpscan --url http://{target} --enumerate vp,vt,u",
            timeout=600,
        ))

        self.register(Tool(
            name="testssl",
            type=ToolType.SHELL,
            description="SSL/TLS configuration testing",
            phase=PentestPhase.VULN_SCAN,
            command_template="testssl.sh {target}",
            timeout=300,
        ))

        # =================================================================
        # PYTHON TOOLS (Module functions)
        # =================================================================

        # Import modules lazily to avoid circular imports
        self._register_python_tools()

    def _register_python_tools(self) -> None:
        """Register Python module tools."""
        # Passive Recon (Python)
        self.register(Tool(
            name="passive_recon",
            type=ToolType.PYTHON,
            description="Passive reconnaissance (DNS, WHOIS, headers, forms)",
            phase=PentestPhase.RECON,
            python_func=self._run_passive_recon,
            timeout=60,
        ))

        # SQL Injection Test (Python)
        self.register(Tool(
            name="sqli_test",
            type=ToolType.PYTHON,
            description="SQL injection testing with polyglot payloads",
            phase=PentestPhase.EXPLOIT,
            python_func=self._run_sqli_test,
            timeout=120,
        ))

        # XSS Test (Python)
        self.register(Tool(
            name="xss_test",
            type=ToolType.PYTHON,
            description="Cross-site scripting detection",
            phase=PentestPhase.EXPLOIT,
            python_func=self._run_xss_test,
            timeout=120,
        ))

        # Hive Mind - AD Enumeration
        self.register(Tool(
            name="ad_enum",
            type=ToolType.PYTHON,
            description="Active Directory enumeration",
            phase=PentestPhase.RECON,
            python_func=self._run_ad_enum,
            timeout=300,
        ))

        # Hive Mind - Lateral Movement
        self.register(Tool(
            name="lateral_move",
            type=ToolType.PYTHON,
            description="Lateral movement techniques",
            phase=PentestPhase.LATERAL,
            python_func=self._run_lateral_move,
            timeout=300,
        ))

        # C2 Framework - Beacon
        self.register(Tool(
            name="c2_beacon",
            type=ToolType.PYTHON,
            description="Command & Control beacon setup",
            phase=PentestPhase.POST_EXPLOIT,
            python_func=self._run_c2_beacon,
            timeout=60,
        ))

        # Weapon Foundry - Payload Generation
        self.register(Tool(
            name="weapon_forge",
            type=ToolType.PYTHON,
            description="Generate custom payloads and shellcode",
            phase=PentestPhase.EXPLOIT,
            python_func=self._run_weapon_forge,
            timeout=120,
        ))

        # Post-Exploitation
        self.register(Tool(
            name="post_exploit",
            type=ToolType.PYTHON,
            description="Post-exploitation actions (creds, persistence, loot)",
            phase=PentestPhase.POST_EXPLOIT,
            python_func=self._run_post_exploit,
            timeout=300,
        ))

        # Singularity - Code Evolution
        self.register(Tool(
            name="evolve",
            type=ToolType.PYTHON,
            description="Generate new tools via AI (Singularity engine)",
            phase=PentestPhase.EXPLOIT,
            python_func=self._run_evolve,
            timeout=60,
        ))

        # Reporting
        self.register(Tool(
            name="report",
            type=ToolType.PYTHON,
            description="Generate professional pentest report",
            phase=PentestPhase.REPORTING,
            python_func=self._run_report,
            timeout=120,
        ))

        # WAF Bypass Engine
        self.register(Tool(
            name="waf_bypass",
            type=ToolType.PYTHON,
            description="WAF detection and adaptive bypass via mutation engine",
            phase=PentestPhase.EXPLOIT,
            python_func=self._run_waf_bypass,
            timeout=120,
        ))

        # Subdomain Enumeration (Python)
        self.register(Tool(
            name="subdomain_enum",
            type=ToolType.PYTHON,
            description="Python-based subdomain enumeration with multiple techniques",
            phase=PentestPhase.RECON,
            python_func=self._run_subdomain_enum,
            timeout=300,
        ))

        # Nuclei Scanner (Python)
        self.register(Tool(
            name="nuclei_scan",
            type=ToolType.PYTHON,
            description="Python-based Nuclei vulnerability scanner",
            phase=PentestPhase.VULN_SCAN,
            python_func=self._run_nuclei_scan,
            timeout=300,
        ))

        # CVE Database Lookup
        self.register(Tool(
            name="cve_lookup",
            type=ToolType.PYTHON,
            description="Search CVE database for known vulnerabilities",
            phase=PentestPhase.VULN_SCAN,
            python_func=self._run_cve_lookup,
            timeout=60,
        ))

    def register(self, tool: Tool) -> None:
        """Register a tool."""
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s", tool.name)

    def get(self, name: str) -> Tool | None:
        """Get tool by name."""
        return self._tools.get(name)

    def list_tools(self, phase: PentestPhase | None = None) -> list[Tool]:
        """List all tools, optionally filtered by phase."""
        if phase:
            return [t for t in self._tools.values() if t.phase == phase]
        return list(self._tools.values())

    def list_names(self) -> list[str]:
        """List all tool names."""
        return list(self._tools.keys())

    def list_by_phase(self, phase: PentestPhase) -> list[Tool]:
        """List tools by pentest phase."""
        return [t for t in self._tools.values() if t.phase == phase]

    def list_by_type(self, tool_type: ToolType) -> list[Tool]:
        """List tools by type (SHELL, PYTHON, HYBRID)."""
        return [t for t in self._tools.values() if t.type == tool_type]

    def format_tool_info(self, name: str) -> str | None:
        """Format tool info for display."""
        tool = self.get(name)
        if not tool:
            return None
        return (
            f"[{tool.name}]\n"
            f"  Type: {tool.type.value}\n"
            f"  Phase: {tool.phase.value}\n"
            f"  Description: {tool.description}\n"
            f"  Timeout: {tool.timeout}s\n"
            f"  Root Required: {tool.requires_root}"
        )

    def format_all_tools(self) -> str:
        """Format all tools for display."""
        lines = ["=" * 60, "DRAKBEN Tool Registry", "=" * 60]
        for phase in PentestPhase:
            tools = self.list_by_phase(phase)
            if tools:
                lines.append(f"\n[{phase.value.upper()}]")
                for tool in tools:
                    root_flag = " [ROOT]" if tool.requires_root else ""
                    lines.append(f"  • {tool.name}{root_flag}: {tool.description}")
        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    async def run(self, tool_name: str, **kwargs: Any) -> dict:
        """Async wrapper for tool execution."""
        tool = self.get(tool_name)
        if not tool:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        target = kwargs.pop("target", "")

        if tool.type == ToolType.SHELL:
            return await self._async_execute_shell(tool, target=target, **kwargs)
        elif tool.type == ToolType.PYTHON:
            return await self._async_execute_python(tool, target, **kwargs)
        else:
            return {"success": False, "error": f"Unknown tool type: {tool.type}"}

    async def _async_execute_shell(self, tool: Tool, target: str = "", **kwargs: Any) -> dict:
        """Execute shell tool asynchronously."""
        safe_target = shlex.quote(target) if target else ""
        command = tool.command_template.format(target=safe_target, **kwargs)

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=tool.timeout,
            )
            return {
                "success": proc.returncode == 0,
                "output": stdout.decode("utf-8", errors="replace"),
                "error": stderr.decode("utf-8", errors="replace") if stderr else "",
                "returncode": proc.returncode,
                "tool": tool.name,
                "command": command,
            }
        except TimeoutError:
            return {"success": False, "error": "Timeout", "tool": tool.name}
        except Exception as e:
            return {"success": False, "error": str(e), "tool": tool.name}

    # =========================================================================
    # EXECUTION METHODS
    # =========================================================================

    def execute(self, tool_name: str, target: str, **kwargs: Any) -> dict:
        """Execute a tool by name.

        Args:
            tool_name: Name of the tool to execute
            target: Target (IP, domain, URL)
            **kwargs: Additional arguments

        Returns:
            Dict with 'success', 'output', 'error' keys
        """
        tool = self.get(tool_name)
        if not tool:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}

        if tool.type == ToolType.SHELL:
            return self._execute_shell(tool, target, **kwargs)
        elif tool.type == ToolType.PYTHON:
            return self._execute_python(tool, target, **kwargs)
        elif tool.type == ToolType.HYBRID:
            # Hybrid: prefer Python func if available, fall back to shell
            if tool.python_func is not None:
                return self._execute_python(tool, target, **kwargs)
            return self._execute_shell(tool, target, **kwargs)
        else:
            return {"success": False, "error": f"Unknown tool type: {tool.type}"}

    def _execute_shell(self, tool: Tool, target: str, live_output: bool = True, **kwargs: Any) -> dict:
        """Execute a shell tool."""
        safe_target = shlex.quote(target) if target else ""
        command = tool.command_template.format(target=safe_target, **kwargs)

        logger.info("Executing: %s", command)

        try:
            if live_output:
                # Live output mode
                process = subprocess.Popen(
                    command,
                    shell=True,  # nosec B602 - Tool execution requires shell
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                output_lines = []
                for line in process.stdout:
                    print(line, end="", flush=True)
                    output_lines.append(line)
                process.wait(timeout=tool.timeout)

                output = "".join(output_lines)
                success = process.returncode == 0
            else:
                # Silent mode
                result = subprocess.run(
                    command,
                    shell=True,  # nosec B602 - Tool execution requires shell
                    capture_output=True,
                    text=True,
                    timeout=tool.timeout,
                )
                output = result.stdout + result.stderr
                success = result.returncode == 0

            return {
                "success": success,
                "output": output,
                "tool": tool.name,
                "command": command,
            }

        except subprocess.TimeoutExpired:
            # Kill the process to prevent resource leaks
            if live_output:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except Exception:
                    pass
            return {"success": False, "error": "Timeout", "tool": tool.name}
        except Exception as e:
            return {"success": False, "error": str(e), "tool": tool.name}

    def _execute_python(self, tool: Tool, target: str, **kwargs: Any) -> dict:
        """Execute a Python tool (sync version for sync callers)."""
        if not tool.python_func:
            return {"success": False, "error": "No Python function defined"}

        try:
            result = tool.python_func(target, **kwargs)
            # If the result is a coroutine, run it synchronously
            if asyncio.iscoroutine(result):
                try:
                    result = asyncio.run(result)
                except RuntimeError:
                    # Already in an async context - use a new thread to run it
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        result = pool.submit(asyncio.run, result).result(timeout=120)
            return {
                "success": True,
                "output": result,
                "tool": tool.name,
            }
        except Exception as e:
            logger.exception("Python tool %s failed: %s", tool.name, e)
            return {"success": False, "error": str(e), "tool": tool.name}

    async def _async_execute_python(self, tool: Tool, target: str, **kwargs: Any) -> dict:
        """Execute a Python tool (async version for async callers)."""
        if not tool.python_func:
            return {"success": False, "error": "No Python function defined"}

        try:
            result = tool.python_func(target, **kwargs)
            # If the result is a coroutine, await it
            if asyncio.iscoroutine(result):
                result = await result
            return {
                "success": True,
                "output": result,
                "tool": tool.name,
            }
        except Exception as e:
            logger.exception("Python tool %s failed: %s", tool.name, e)
            return {"success": False, "error": str(e), "tool": tool.name}

    # =========================================================================
    # PYTHON TOOL IMPLEMENTATIONS (Wrappers)
    # =========================================================================

    def _run_passive_recon(self, target: str, **kwargs: Any) -> dict:
        """Run passive_recon from modules/recon.py - returns coroutine."""
        from modules.recon import passive_recon
        # Return the coroutine directly, let _async_execute_python await it
        return passive_recon(target)

    def _run_sqli_test(self, target: str, **kwargs: Any) -> dict:
        """Run SQL injection test from modules/exploit"""
        from modules.exploit import PolyglotEngine

        # Get polyglot payloads
        payloads = PolyglotEngine.get_chimera_payloads()

        # Test each payload
        results = {"target": target, "payloads_tested": len(payloads), "findings": []}

        # Note: Actual HTTP testing would go here
        # For now, return payload list for manual testing
        results["payloads"] = payloads
        results["note"] = "Use sqlmap for automated testing or test payloads manually"

        return results

    def _run_xss_test(self, target: str, **kwargs: Any) -> dict:
        """Run XSS test from modules/exploit"""
        from modules.exploit import AIEvasion

        # XSS payloads
        base_payload = "<script>alert(1)</script>"
        mutations = AIEvasion.mutate_payload(base_payload, strategy="semantic")

        return {
            "target": target,
            "base_payload": base_payload,
            "mutations": mutations,
            "note": "Test these payloads in input fields",
        }

    def _run_ad_enum(self, target: str, **kwargs: Any) -> dict:
        """Run AD enumeration via hive_mind module."""
        try:
            from modules.hive_mind import (
                ADAnalyzer,
                CredentialHarvester,
                NetworkMapper,
            )

            mapper = NetworkMapper()
            host = mapper.quick_scan(target)
            creds = CredentialHarvester().get_all_credentials()
            domain = ADAnalyzer().detect_domain()

            return {
                "target": target,
                "domain": domain,
                "host": {"ip": host.ip, "ports": host.ports} if host else None,
                "credentials_found": len(creds),
                "suggested": f"enum4linux -a {target}",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_lateral_move(self, target: str, **kwargs: Any) -> dict:
        """Attempt lateral movement to *target* via hive_mind."""
        try:
            from modules.hive_mind import (
                ADAnalyzer,
                CredentialHarvester,
                LateralMover,
                NetworkHost,
                NetworkMapper,
            )

            mapper = NetworkMapper()
            host = mapper.quick_scan(target)
            creds = CredentialHarvester().get_all_credentials()
            analyzer = ADAnalyzer()

            # Build discovered hosts for path calculation
            local_ips = mapper.get_local_interfaces()
            source = local_ips[0] if local_ips else "127.0.0.1"
            source_host = mapper.quick_scan(source) or NetworkHost(ip=source, ports=[])
            hosts = {source: source_host}
            if host:
                hosts[target] = host

            path = analyzer.calculate_attack_path(source, target, creds, hosts)
            mover = LateralMover()

            return {
                "target": target,
                "source": source,
                "path_found": path is not None,
                "hops": path.hops if path else [],
                "techniques": [t.value for t in path.techniques] if path else [],
                "probability": path.probability if path else 0,
                "credentials_available": len(creds),
                "movement_stats": mover.get_movement_stats(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_c2_beacon(self, target: str, **kwargs: Any) -> dict:
        """Initialise a C2 channel toward *target*."""
        try:
            from modules.c2_framework import (
                C2Channel,
                C2Config,
                C2Protocol,
            )

            protocol_name = kwargs.get("protocol", "https")
            protocol = C2Protocol(protocol_name)
            config = C2Config(protocol=protocol, actual_host=target)
            channel = C2Channel(config)

            return {
                "target": target,
                "protocol": protocol.value,
                "beacon_status": channel.status.value,
                "encryption_key_len": len(channel.encryption_key),
                "available_protocols": [p.value for p in C2Protocol],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_weapon_forge(self, target: str, **kwargs: Any) -> dict:
        """Generate a payload via WeaponFoundry.forge()."""
        try:
            from modules.weapon_foundry import (
                EncryptionMethod,
                PayloadFormat,
                ShellType,
                WeaponFoundry,
            )

            lhost = kwargs.get("lhost", "127.0.0.1")
            lport = int(kwargs.get("lport", 4444))
            fmt = PayloadFormat(kwargs.get("format", "python"))
            enc = EncryptionMethod(kwargs.get("encryption", "xor"))
            shell = ShellType(kwargs.get("shell_type", "reverse_tcp"))

            foundry = WeaponFoundry()
            payload = foundry.forge(
                shell_type=shell, lhost=lhost, lport=lport,
                encryption=enc, output_format=fmt,
            )

            return {
                "target": target,
                "shell_type": payload.metadata.get("shell_type", shell.value),
                "format": payload.output_format.value,
                "encryption": payload.encryption.value,
                "size_bytes": len(payload.payload),
                "capabilities": foundry.list_capabilities(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_post_exploit(self, target: str, **kwargs: Any) -> dict:
        """Run post-exploitation enumeration on *target*."""
        try:
            from modules.post_exploit import (
                LinuxPostExploit,
                PostExploitEngine,
                WindowsPostExploit,
            )

            # Expose available engines and their actions
            linux_actions = [
                m for m in dir(LinuxPostExploit)
                if not m.startswith("_") and callable(getattr(LinuxPostExploit, m, None))
            ]
            windows_actions = [
                m for m in dir(WindowsPostExploit)
                if not m.startswith("_") and callable(getattr(WindowsPostExploit, m, None))
            ]

            return {
                "target": target,
                "engine": PostExploitEngine.__name__,
                "linux_actions": linux_actions,
                "windows_actions": windows_actions,
                "note": "Provide a ShellInterface to PostExploitEngine to execute",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_evolve(self, target: str, **kwargs: Any) -> dict:
        """Generate new capability via Singularity engine and auto-register."""
        try:
            from core.singularity import SingularityEngine
            engine = SingularityEngine()
            description = kwargs.get("description", f"Tool to analyze {target}")
            tool_name = kwargs.get("tool_name")
            code = engine.create_and_register(description, tool_name=tool_name)
            return {
                "target": target,
                "generated_code": code[:2000] if code else None,
                "registered": code is not None,
                "status": "Tool generated and registered" if code else "Generation failed",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_report(self, target: str, **kwargs: Any) -> dict:
        """Generate a pentest report for *target*."""
        try:
            from modules.report_generator import ReportFormat, ReportGenerator

            fmt = ReportFormat(kwargs.get("format", "html"))
            output_path = kwargs.get("output", f"reports/{target}_report.{fmt.value}")

            gen = ReportGenerator()
            gen.set_target(target)
            gen.start_assessment()
            stats = gen.get_statistics()

            return {
                "target": target,
                "format": fmt.value,
                "output_path": output_path,
                "statistics": stats,
                "available_formats": [f.value for f in ReportFormat],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_waf_bypass(self, target: str, **kwargs: Any) -> dict:
        """Run WAF bypass engine against *target*."""
        try:
            from modules.waf_bypass_engine import WAFBypassEngine

            engine = WAFBypassEngine()
            payload = kwargs.get("payload", "' OR 1=1 --")
            aggressiveness = int(kwargs.get("aggressiveness", 2))

            bypasses = engine.bypass_sql(payload, aggressiveness=aggressiveness)

            return {
                "target": target,
                "bypass_count": len(bypasses),
                "top_bypasses": bypasses[:10],
                "note": "Use fingerprint_waf() with response headers for targeted bypass",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_subdomain_enum(self, target: str, **kwargs: Any) -> dict:
        """Run Python-based subdomain enumeration for *target*."""
        try:
            from modules.subdomain import SubdomainEnumerator

            enumerator = SubdomainEnumerator()
            results = asyncio.run(enumerator.enumerate(target))
            subdomains = [str(r) for r in results] if results else []

            return {
                "target": target,
                "subdomains_found": len(subdomains),
                "subdomains": subdomains[:100],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_nuclei_scan(self, target: str, **kwargs: Any) -> dict:
        """Run Python Nuclei scanner against *target*."""
        try:
            from modules.nuclei import NucleiScanner

            scanner = NucleiScanner()
            results = asyncio.run(scanner.scan(target))
            findings = [str(r) for r in results] if results else []

            return {
                "target": target,
                "findings_count": len(findings),
                "findings": findings[:50],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_cve_lookup(self, target: str, **kwargs: Any) -> dict:
        """Search CVE database for vulnerabilities related to *target*."""
        try:
            from modules.cve_database import CVEDatabase

            db = CVEDatabase()
            query = kwargs.get("query", target)
            results = asyncio.run(db.search_cves(query))
            entries = [
                {"id": r.cve_id, "description": r.description[:200], "severity": r.severity}
                for r in results
            ] if results else []

            return {
                "query": query,
                "cve_count": len(entries),
                "entries": entries[:20],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


# Singleton instance
_registry: ToolRegistry | None = None
_registry_lock = _tr_threading.Lock()


def get_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = ToolRegistry()
    return _registry
