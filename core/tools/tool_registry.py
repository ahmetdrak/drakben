# core/tools/tool_registry.py
# DRAKBEN Tool Registry - Central Hub for All Tools
# Author: @drak_ben
"""
Tool Registry: Maps tool names to their implementations.

This is the "nervous system" that connects:
- Shell commands (nmap, nikto, sqlmap)
- Python modules (modules/recon.py, modules/exploit.py)
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
import subprocess
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

    def register(self, tool: Tool) -> None:
        """Register a tool."""
        self._tools[tool.name] = tool
        logger.debug(f"Registered tool: {tool.name}")

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
        else:
            return {"success": False, "error": f"Unknown tool type: {tool.type}"}

    def _execute_shell(self, tool: Tool, target: str, live_output: bool = True, **kwargs: Any) -> dict:
        """Execute a shell tool."""
        command = tool.command_template.format(target=target, **kwargs)

        logger.info(f"Executing: {command}")

        try:
            if live_output:
                # Live output mode
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                output_lines = []
                for line in process.stdout:
                    print(line, end='', flush=True)
                    output_lines.append(line)
                process.wait(timeout=tool.timeout)

                output = "".join(output_lines)
                success = process.returncode == 0
            else:
                # Silent mode
                result = subprocess.run(
                    command,
                    shell=True,
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
            return {"success": False, "error": "Timeout", "tool": tool.name}
        except Exception as e:
            return {"success": False, "error": str(e), "tool": tool.name}

    def _execute_python(self, tool: Tool, target: str, **kwargs: Any) -> dict:
        """Execute a Python tool."""
        if not tool.python_func:
            return {"success": False, "error": "No Python function defined"}

        try:
            result = tool.python_func(target, **kwargs)
            return {
                "success": True,
                "output": result,
                "tool": tool.name,
            }
        except Exception as e:
            logger.exception(f"Python tool {tool.name} failed: {e}")
            return {"success": False, "error": str(e), "tool": tool.name}

    # =========================================================================
    # PYTHON TOOL IMPLEMENTATIONS (Wrappers)
    # =========================================================================

    def _run_passive_recon(self, target: str, **kwargs: Any) -> dict:
        """Run passive_recon from modules/recon.py"""
        from modules.recon import passive_recon
        return asyncio.run(passive_recon(target))

    def _run_sqli_test(self, target: str, **kwargs: Any) -> dict:
        """Run SQL injection test from modules/exploit.py"""
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
        """Run XSS test from modules/exploit.py"""
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
        """Run AD enumeration from modules/hive_mind.py"""
        try:
            from modules.hive_mind import HiveMind
            HiveMind()  # Validate module loads
            return {
                "target": target,
                "status": "ready",
                "note": "Use /shell to run: ldapsearch or enum4linux",
                "suggested": f"enum4linux -a {target}",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_lateral_move(self, target: str, **kwargs: Any) -> dict:
        """Run lateral movement from modules/hive_mind.py"""
        try:
            from modules.hive_mind import MovementTechnique
            techniques = [t.value for t in MovementTechnique]
            return {
                "target": target,
                "available_techniques": techniques,
                "note": "Select technique based on available credentials",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_c2_beacon(self, target: str, **kwargs: Any) -> dict:
        """Start C2 beacon from modules/c2_framework.py"""
        try:
            from modules.c2_framework import C2Framework, C2Protocol
            C2Framework()  # Validate module loads
            return {
                "target": target,
                "protocols": [p.value for p in C2Protocol],
                "status": "C2 framework ready",
                "note": "Use c2.start_listener() to begin",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_weapon_forge(self, target: str, **kwargs: Any) -> dict:
        """Generate payload from modules/weapon_foundry.py"""
        try:
            from modules.weapon_foundry import WeaponFoundry
            foundry = WeaponFoundry()
            templates = foundry.list_templates() if hasattr(foundry, 'list_templates') else []
            return {
                "target": target,
                "templates": templates[:10] if templates else ["reverse_shell", "bind_shell", "meterpreter"],
                "status": "Weapon foundry ready",
                "note": "Specify payload type and format",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_post_exploit(self, target: str, **kwargs: Any) -> dict:
        """Run post-exploitation from modules/post_exploit.py"""
        try:
            from modules.post_exploit import PostExploit
            PostExploit()  # Validate module loads
            return {
                "target": target,
                "actions": ["dump_creds", "persistence", "loot", "pivot"],
                "status": "Post-exploit module ready",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_evolve(self, target: str, **kwargs: Any) -> dict:
        """Generate new capability via Singularity engine."""
        try:
            from core.singularity import SingularityEngine
            engine = SingularityEngine()
            description = kwargs.get("description", f"Tool to analyze {target}")
            code = engine.create_capability(description, language="python")
            return {
                "target": target,
                "generated_code": code[:2000] if code else None,
                "status": "Code generated" if code else "Generation failed",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


# Singleton instance
_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
