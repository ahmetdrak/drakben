"""Refactored Agent — Tool Executor Mixin.

Provides specialized tool execution methods for weapon foundry,
singularity, OSINT, hive mind, metasploit, AD attacks,
WAF bypass engine, C2 framework, subdomain enumeration,
Nuclei scanning, and CVE database lookup.

Extracted from refactored_agent.py for maintainability.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.agent._agent_protocol import AgentProtocol
    from core.singularity.base import CodeSnippet
    from modules.hive_mind import AttackPath, NetworkHost
    from modules.weapon_foundry import GeneratedPayload

    _MixinBase = AgentProtocol
else:
    _MixinBase = object


def _run_coro_safe(coro, *, timeout: float = 300) -> Any:
    """Run a coroutine from sync code, safe even inside a running event loop."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=timeout)


logger = logging.getLogger(__name__)


class RAToolExecutorsMixin(_MixinBase):
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

            payload_type = args.get("format") or args.get("type") or "python"
            lhost = args.get("lhost")
            lport = args.get("lport", 4444)
            encryption = args.get("encryption", "aes")

            if not lhost:
                lhost = "127.0.0.1"
                self.console.print("⚠️ LHOST missing, using localhost.", style="yellow")

            self.console.print(f"🔨 Forging Payload ({payload_type})...", style="cyan")

            artifact: GeneratedPayload = foundry.forge(
                lhost=lhost,
                lport=int(lport),
                output_format=payload_type,  # type: ignore[arg-type]
                encryption=encryption,
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

            if result.code:
                return {
                    "success": True,
                    "output": (f"Code Synthesized: {result.purpose}\nContent Preview:\n{result.code[:300]}"),
                }
            return {
                "success": False,
                "error": "Synthesis failed: no code generated",
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
                subnet = args.get("target") if args.get("target") and "/" in str(args.get("target")) else None

                hosts: list[NetworkHost] = hive.scan_network(subnet)
                hosts_data: list[str] = [str(h) for h in hosts]

                observation: str = (
                    f"Hive Mind Intelligence:\nInitialized: {init_res}\nDiscovered Hosts: {len(hosts)}\n{hosts_data}"
                )
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
                    "output": (
                        f"Movement result: {'Success' if result['success'] else 'Failed'}."
                        f" Final Position: {result['final_position']}"
                    ),
                }

            return {"success": False, "error": "Unknown Hive Mind tool"}

        except Exception as e:
            return {"success": False, "error": f"Hive Mind Error: {e!s}"}

    def _execute_metasploit(self, args: dict) -> dict:
        """Execute Metasploit module via wrapper."""
        try:
            from modules.metasploit import MetasploitRPC

            msf = MetasploitRPC()

            module = args.get("module")
            options = args.get("options", {})

            if not module:
                return {"success": False, "error": "Metasploit module name required"}

            rpc_host = options.pop("rpc_host", "127.0.0.1")
            rpc_port = int(options.pop("rpc_port", 55553))
            rpc_user = options.pop("rpc_user", "msf")
            rpc_pass = options.pop("rpc_pass", "")

            self.console.print(f"🔥 Launching Metasploit: {module}", style="red")

            async def _run_msf() -> dict:
                await msf.connect(rpc_host, rpc_port, rpc_user, rpc_pass)
                try:
                    result = await msf._call("module.execute", [module, options])
                    return {"success": bool(result), "output": str(result)[:2000]}
                finally:
                    await msf.disconnect()

            result = _run_coro_safe(_run_msf())
            return {
                "success": result.get("success", False),
                "output": result.get("output", ""),
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
                user_file = args.get("user_file")
                result = _run_coro_safe(
                    attacker.run_asreproast(domain, target_ip, user_file),
                )

            elif tool_name == "ad_smb_spray":
                # Async shim
                user_file = args.get("user_file")
                password = args.get("password")
                if not user_file or not password:
                    return {
                        "success": False,
                        "error": "User file and password required for spray",
                    }

                # Check concurrency arg
                concurrency = args.get("concurrency", 10)
                result = _run_coro_safe(
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

    def _execute_waf_bypass(self, args: dict) -> dict:
        """Execute WAF Bypass Engine for WAF detection and evasion."""
        try:
            from modules.waf_bypass_engine import PayloadType, WAFBypassEngine

            engine = WAFBypassEngine()
            target = args.get("target") or getattr(self.state, "target", None)

            if not target:
                return {"success": False, "error": "Target required for WAF bypass"}

            self.console.print(f"🛡️ WAF Bypass Engine → {target}", style="cyan")

            results: dict[str, Any] = {"target": target, "waf_detected": "unknown"}

            # If response headers provided, fingerprint WAF
            headers = args.get("headers", {})
            body = args.get("body", "")
            status_code = args.get("status_code", 403)
            if headers:
                waf_type = engine.fingerprint_waf(headers, body, status_code)
                results["waf_detected"] = waf_type.name

            # Generate bypass payloads for requested type
            payload = args.get("payload", "' OR 1=1 --")
            payload_type = args.get("payload_type", "sqli")
            aggressiveness = int(args.get("aggressiveness", 2))

            type_map = {
                "sqli": PayloadType.SQLI,
                "xss": PayloadType.XSS,
                "rce": PayloadType.RCE,
            }
            p_type = type_map.get(payload_type, PayloadType.SQLI)

            if p_type == PayloadType.SQLI:
                bypasses = engine.bypass_sql(payload, aggressiveness=aggressiveness)
            elif p_type == PayloadType.XSS:
                bypasses = engine.bypass_xss(payload)
            else:
                bypasses = engine.bypass_rce(payload)

            results["payload_type"] = payload_type
            results["bypass_count"] = len(bypasses)
            results["bypasses"] = bypasses[:10]  # Top 10

            self.console.print(
                f"   Generated {len(bypasses)} bypass payloads",
                style="green",
            )

            return {"success": True, "output": json.dumps(results, indent=2), "data": results}

        except ImportError:
            return {"success": False, "error": "modules.waf_bypass_engine not found"}
        except Exception as e:
            logger.exception("WAF Bypass error: %s", e)
            return {"success": False, "error": f"WAF Bypass error: {e}"}

    def _execute_c2(self, args: dict) -> dict:
        """Execute C2 Framework for beacon communication setup."""
        try:
            from modules.c2_framework import C2Channel, C2Config, C2Protocol

            target = args.get("target") or getattr(self.state, "target", None)
            if not target:
                return {"success": False, "error": "Target required for C2 beacon"}

            self.console.print(f"📡 C2 Framework → {target}", style="red")

            protocol_name = args.get("protocol", "https")
            protocol = C2Protocol(protocol_name)
            config = C2Config(protocol=protocol, actual_host=target)
            channel = C2Channel(config)

            results = {
                "target": target,
                "protocol": protocol.value,
                "beacon_status": channel.status.value,
                "encryption_key_len": len(channel.encryption_key),
                "available_protocols": [p.value for p in C2Protocol],
            }

            self.console.print(
                f"   Beacon: {channel.status.value} | Protocol: {protocol.value}",
                style="green",
            )

            return {"success": True, "output": json.dumps(results, indent=2), "data": results}

        except ImportError:
            return {"success": False, "error": "modules.c2_framework not found"}
        except Exception as e:
            logger.exception("C2 Framework error: %s", e)
            return {"success": False, "error": f"C2 Framework error: {e}"}

    def _execute_subdomain_enum(self, args: dict) -> dict:
        """Execute Python-based subdomain enumeration."""
        try:
            from modules.subdomain import SubdomainEnumerator

            target = args.get("target") or getattr(self.state, "target", None)
            if not target:
                return {"success": False, "error": "Target domain required"}

            self.console.print(f"🔍 Subdomain Enumeration → {target}", style="blue")

            enumerator = SubdomainEnumerator()
            results = _run_coro_safe(enumerator.enumerate(target))
            subdomains = [str(r) for r in results] if results else []

            return {
                "success": True,
                "output": f"Found {len(subdomains)} subdomains:\n" + "\n".join(subdomains[:50]),
                "data": {"target": target, "count": len(subdomains), "subdomains": subdomains[:100]},
            }

        except ImportError:
            return {"success": False, "error": "modules.subdomain not found"}
        except Exception as e:
            logger.exception("Subdomain enumeration error: %s", e)
            return {"success": False, "error": f"Subdomain error: {e}"}

    def _execute_nuclei_scan(self, args: dict) -> dict:
        """Execute Python Nuclei scanner."""
        try:
            from modules.nuclei import NucleiScanner

            target = args.get("target") or getattr(self.state, "target", None)
            if not target:
                return {"success": False, "error": "Target required for Nuclei scan"}

            self.console.print(f"☢️ Nuclei Scan → {target}", style="yellow")

            scanner = NucleiScanner()
            results = _run_coro_safe(scanner.scan(target))
            findings = [str(r) for r in results] if results else []

            return {
                "success": True,
                "output": f"Nuclei found {len(findings)} issues:\n" + "\n".join(findings[:20]),
                "data": {"target": target, "findings_count": len(findings)},
            }

        except ImportError:
            return {"success": False, "error": "modules.nuclei not found"}
        except Exception as e:
            logger.exception("Nuclei scan error: %s", e)
            return {"success": False, "error": f"Nuclei scan error: {e}"}

    def _execute_cve_lookup(self, args: dict) -> dict:
        """Execute CVE database lookup."""
        try:
            from modules.cve_database import CVEDatabase

            query = args.get("query") or args.get("product") or args.get("cve_id", "")
            if not query:
                return {"success": False, "error": "Query or product name required for CVE lookup"}

            self.console.print(f"🔎 CVE Lookup → {query}", style="cyan")

            db = CVEDatabase()
            results = _run_coro_safe(db.search_cves(query))
            entries = (
                [{"id": r.cve_id, "description": r.description[:200], "severity": r.severity} for r in results]
                if results
                else []
            )

            return {
                "success": True,
                "output": f"Found {len(entries)} CVEs for '{query}':\n"
                + "\n".join(f"  {e['id']}: {e['description']}" for e in entries[:10]),
                "data": {"query": query, "count": len(entries), "entries": entries[:20]},
            }

        except ImportError:
            return {"success": False, "error": "modules.cve_database not found"}
        except Exception as e:
            logger.exception("CVE lookup error: %s", e)
            return {"success": False, "error": f"CVE lookup error: {e}"}
