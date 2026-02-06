"""Refactored Agent — Tool Executor Mixin.

Provides specialized tool execution methods for weapon foundry,
singularity, OSINT, hive mind, metasploit, and AD attacks.

Extracted from refactored_agent.py for maintainability.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.singularity.base import CodeSnippet
    from modules.hive_mind import AttackPath, NetworkHost
    from modules.weapon_foundry import GeneratedPayload

logger = logging.getLogger(__name__)


class RAToolExecutorsMixin:
    """Mixin providing specialized tool executor methods.

    Expects the host class to provide:
    - self.console (Rich Console)
    - self.state (AgentState with .target attribute)
    """

    def _execute_weapon_foundry(self, args: dict) -> dict:
        """Execute Weapon Foundry to generate payloads."""
        try:
            from modules.weapon_foundry import WeaponFoundry

            foundry = WeaponFoundry()

            payload_type = args.get("format", "python")
            lhost = args.get("lhost")
            lport = args.get("lport", 4444)
            # Args from Agent LLM might call it 'type' instead of 'format'
            if not payload_type and "type" in args:
                payload_type = args["type"]

            if not lhost:
                lhost = "127.0.0.1"
                self.console.print("⚠️ LHOST missing, using localhost.", style="yellow")

            self.console.print(f"🔨 Forging Payload ({payload_type})...", style="cyan")

            artifact: GeneratedPayload = foundry.forge(
                lhost=lhost,
                lport=int(lport),
                format=payload_type,
                encryption="aes",
                iterations=5,
            )

            if artifact:
                filename = artifact.metadata.get("filename", "payload.bin")
                return {
                    "success": True,
                    "output": f"Payload SUCCESS: {filename}",
                    "artifact": filename,
                }
            return {"success": False, "error": "Payload generation failed"}
        except Exception as e:
            logger.exception("WeaponFoundry error: %s", e)
            return {"success": False, "error": f"WeaponFoundry error: {e}"}

    def _execute_singularity(self, args: dict) -> dict:
        """Execute Singularity to write custom code."""
        try:
            from core.singularity.synthesizer import CodeSynthesizer

            # Initialize with existing Brain/Coder components if available
            synth = CodeSynthesizer()

            instruction = args.get("description") or args.get("instruction")
            lang = args.get("language", "python")

            if not instruction:
                return {
                    "success": False,
                    "error": "No instruction provided for code synthesis",
                }

            self.console.print(
                f"🔮 Singularity: Synthesizing {lang} code...",
                style="magenta",
            )

            # Use generate_tool (which returns artifact)
            # Args might differ, check CodeSynthesizer definition.
            # Assuming generate_tool is the main entry point from context step 1960.
            result: CodeSnippet = synth.generate_tool(
                description=instruction,
                language=lang,
            )

            if getattr(result, "success", False):
                return {
                    "success": True,
                    "output": f"Code Synthesized: {result.file_path}\nContent Preview:\n{result.content[:300] if result.content else ''}",
                }
            return {
                "success": False,
                "error": f"Synthesis failed: {getattr(result, 'error', 'Unknown Error')}",
            }

        except Exception as e:
            logger.exception("Singularity error: %s", e)
            return {"success": False, "error": f"Singularity error: {e}"}

    def _execute_osint(self, _tool_name: str, args: dict) -> dict:
        """Execute OSINT tools."""
        try:
            from modules.social_eng.osint import OSINTSpider

            recon = OSINTSpider()

            target = args.get("target") or self.state.target
            if not target:
                return {"success": False, "error": "Target required"}

            self.console.print(f"🕵️ OSINT Scanning: {target}", style="blue")
            results = recon.harvest_domain(target)
            return {"success": True, "output": str(results)[:2000]}
        except Exception as e:
            return {"success": False, "error": f"OSINT error: {e}"}

    def _execute_hive_mind(self, tool_name: str, args: dict) -> dict:
        """Execute Hive Mind internal module."""
        try:
            from modules.hive_mind import HiveMind

            hive = HiveMind()

            self.console.print("🐝 Waking up HIVE MIND...", style="magenta")

            if tool_name == "hive_mind_scan":
                init_res: dict[str, Any] = hive.initialize()
                # If target is IP/subnet, use it. Otherwise auto-detect.
                subnet = (
                    args.get("target")
                    if args.get("target") and "/" in str(args.get("target"))
                    else None
                )

                hosts: list[NetworkHost] = hive.scan_network(subnet)
                hosts_data: list[str] = [str(h) for h in hosts]

                observation: str = f"Hive Mind Intelligence:\nInitialized: {init_res}\nDiscovered Hosts: {len(hosts)}\n{hosts_data}"
                self.console.print(observation, style="cyan")

                return {
                    "success": True,
                    "init": init_res,
                    "hosts_discovered": len(hosts),
                    "hosts": hosts_data,
                    "output": observation,
                }

            if tool_name == "hive_mind_attack":
                self.console.print("🐝 Calculating Attack Paths...", style="magenta")
                target = args.get("target", "Domain Admin")
                paths: list[AttackPath] = hive.find_attack_paths(target)

                if not paths:
                    return {"success": False, "error": "No viable attack paths found"}

                # Execute best path
                best_path: AttackPath = paths[0]
                self.console.print(f"🚀 Executing Path: {best_path}", style="red")

                result: dict[str, Any] = hive.execute_movement(best_path)
                return {
                    "success": result["success"],
                    "hops": result["hops_completed"],
                    "output": f"Movement result: {'Success' if result['success'] else 'Failed'}. Final Position: {result['final_position']}",
                }

            return {"success": False, "error": "Unknown Hive Mind tool"}

        except Exception as e:
            return {"success": False, "error": f"Hive Mind Error: {e!s}"}

    def _execute_metasploit(self, args: dict) -> dict:
        """Execute Metasploit module via wrapper."""
        try:
            from modules.metasploit import MetasploitBridge

            # Initialize if needed (singleton pattern preferred in real usage, but instantiating for now)
            msf = MetasploitBridge()

            # 'module' and 'options' are expected in args
            module = args.get("module")
            options = args.get("options", {})

            if not module:
                return {"success": False, "error": "Metasploit module name required"}

            self.console.print(f"🔥 Launching Metasploit: {module}", style="red")
            result = msf.execute_module(module, options)

            return {
                "success": result.get("success", False),
                "output": result.get("output", ""),
                "session_id": result.get("session_id"),
            }
        except ImportError:
            return {"success": False, "error": "modules.metasploit not found"}
        except Exception as e:
            logger.exception("Metasploit error")
            return {"success": False, "error": f"Metasploit execution failed: {e}"}

    def _execute_ad_attacks(self, tool_name: str, args: dict) -> dict:
        """Execute Active Directory attacks (Native)."""
        try:
            from modules.ad_attacks import ActiveDirectoryAttacker

            attacker = ActiveDirectoryAttacker()

            domain = args.get("domain")
            target_ip = args.get("target_ip")

            if not domain or not target_ip:
                return {
                    "success": False,
                    "error": "Domain and Target IP required for AD attacks",
                }

            result = {}
            if tool_name == "ad_asreproast":
                # Async shim
                import asyncio

                user_file = args.get("user_file")
                result = asyncio.run(
                    attacker.run_asreproast(domain, target_ip, user_file),
                )

            elif tool_name == "ad_smb_spray":
                # Async shim
                import asyncio

                user_file = args.get("user_file")
                password = args.get("password")
                if not user_file or not password:
                    return {
                        "success": False,
                        "error": "User file and password required for spray",
                    }

                # Check concurrency arg
                concurrency = args.get("concurrency", 10)
                result = asyncio.run(
                    attacker.run_smb_spray(
                        domain,
                        target_ip,
                        user_file,
                        password,
                        concurrency,
                    ),
                )

            else:
                return {"success": False, "error": f"Unknown AD tool: {tool_name}"}

            return {
                "success": result.get("success", False),
                "output": json.dumps(result, indent=2),
                "data": result,
            }

        except ImportError:
            return {"success": False, "error": "modules.ad_attacks not found"}
        except Exception as e:
            logger.exception("AD Attack error")
            return {"success": False, "error": f"AD Attack failed: {e}"}
