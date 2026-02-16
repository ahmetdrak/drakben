"""Refactored Agent — State Update Mixin.

Provides methods for updating agent state from tool execution results,
including observation creation, result dispatching, vulnerability processing,
and phase transition logic.

Extracted from refactored_agent.py for maintainability.
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.agent._agent_protocol import AgentProtocol
    from core.agent.state import ServiceInfo

    _MixinBase = AgentProtocol
else:
    _MixinBase = object

logger = logging.getLogger(__name__)

# Error message constant (mirrors refactored_agent._ERR_UNKNOWN)
_ERR_UNKNOWN = "Unknown error"


class RAStateUpdatesMixin(_MixinBase):
    """Mixin providing state update functionality for RefactoredDrakbenAgent.

    Expects the host class to provide:
    - self.state (AgentState), self.brain (DrakbenBrain)
    - self.tool_selector (ToolSelector), self.console (Rich Console)
    - self.MSG_STATE_NOT_NONE (str constant)
    """

    def _update_state_from_result(
        self,
        tool_name: str,
        result: dict,
        observation: str,
    ) -> None:
        """Update state based on tool result."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        # Set observation
        self.state.set_observation(observation)

        # 1. Record Result Execution (Success/Failure)
        self._record_execution_outcome(tool_name, result)

        # Record a meaningful state change even on failure so stagnation
        # detection doesn't see only "iteration" entries.
        change_type = "tool_success" if result.get("success") else "tool_failure"
        self.state._record_change(change_type, {"tool": tool_name})

        if not result.get("success"):
            return

        # 2. Update State Specifics based on Tool
        self._dispatch_state_update(tool_name, result)

    def _record_execution_outcome(self, tool_name: str, result: dict) -> None:
        """Record success or failure to brain and tool selector."""
        output = result.get("stdout", "") + "\n" + result.get("stderr", "")
        success = result.get("success", False)

        if not success:
            self.tool_selector.record_tool_failure(tool_name)

        self.brain.observe(tool=tool_name, output=output, success=success)

    def _dispatch_state_update(self, tool_name: str, result: dict) -> None:
        """Dispatch state update based on tool type and advance phase."""
        if "nmap_port_scan" in tool_name:
            self._update_state_nmap_port_scan(result)
            self._advance_phase_recon()
        elif "nmap_service_scan" in tool_name or "nikto" in tool_name:
            self._update_state_service_completion(result)
            self._advance_phase_vuln_scan()
        elif "vuln" in tool_name or "sqlmap" in tool_name:
            observation = result.get("stdout", "")
            self._process_vulnerability_result(tool_name, result, observation)
            self._advance_phase_exploit()
        elif "exploit" in tool_name:
            self._process_exploit_result(tool_name, result)
            self._advance_phase_post_exploit()

    # ---- Phase advancement helpers (reduce cognitive complexity) ----

    def _get_transparency(self):
        """Get transparency dashboard (lazy import to avoid circular deps)."""
        try:
            from core.ui.transparency import get_transparency
            return get_transparency(getattr(self, "console", None))
        except ImportError:
            return None

    def _advance_phase_recon(self) -> None:
        """Advance to RECON after successful port scan."""
        from core.agent.state import AttackPhase

        if self.state.phase in (AttackPhase.INIT, AttackPhase.RECON):
            old_phase = self.state.phase.value
            self.state.phase = AttackPhase.RECON
            self.state._record_change("phase_advance", "recon")
            logger.info("Phase advanced → RECON")
            td = self._get_transparency()
            if td:
                td.show_phase_transition(old_phase, "RECON", "Port scan completed — moving to reconnaissance")

    def _advance_phase_vuln_scan(self) -> None:
        """Advance to VULN_SCAN after service/web scan."""
        from core.agent.state import AttackPhase

        if self.state.phase in (AttackPhase.INIT, AttackPhase.RECON):
            old_phase = self.state.phase.value
            self.state.phase = AttackPhase.VULN_SCAN
            self.state._record_change("phase_advance", "vuln_scan")
            logger.info("Phase advanced → VULN_SCAN")
            td = self._get_transparency()
            if td:
                td.show_phase_transition(old_phase, "VULN_SCAN", "Services identified — scanning for vulnerabilities")

    def _advance_phase_exploit(self) -> None:
        """Advance to EXPLOIT or VULN_SCAN after vulnerability assessment."""
        from core.agent.state import AttackPhase

        early = (AttackPhase.INIT, AttackPhase.RECON, AttackPhase.VULN_SCAN)
        if self.state.phase not in early:
            return
        old_phase = self.state.phase.value
        if self.state.vulnerabilities:
            self.state.phase = AttackPhase.EXPLOIT
            self.state._record_change("phase_advance", "exploit")
            logger.info("Phase advanced → EXPLOIT (vulns found)")
            td = self._get_transparency()
            if td:
                n_vulns = len(self.state.vulnerabilities)
                td.show_phase_transition(
                    old_phase, "EXPLOIT",
                    f"{n_vulns} vulnerabilities found — attempting exploitation",
                )
        elif self.state.phase != AttackPhase.VULN_SCAN:
            self.state.phase = AttackPhase.VULN_SCAN
            self.state._record_change("phase_advance", "vuln_scan")
            td = self._get_transparency()
            if td:
                td.show_phase_transition(old_phase, "VULN_SCAN", "No vulns yet — continuing vulnerability scan")

    def _advance_phase_post_exploit(self) -> None:
        """Advance to POST_EXPLOIT or EXPLOIT after exploitation attempt."""
        from core.agent.state import AttackPhase

        old_phase = self.state.phase.value
        if self.state.has_foothold:
            self.state.phase = AttackPhase.POST_EXPLOIT
            self.state._record_change("phase_advance", "post_exploit")
            logger.info("Phase advanced → POST_EXPLOIT (foothold gained)")
            td = self._get_transparency()
            if td:
                td.show_phase_transition(old_phase, "POST_EXPLOIT", "Foothold gained — post-exploitation phase")
        elif self.state.phase in (AttackPhase.INIT, AttackPhase.RECON, AttackPhase.VULN_SCAN):
            self.state.phase = AttackPhase.EXPLOIT
            self.state._record_change("phase_advance", "exploit")

    # Positive evidence patterns for foothold detection
    _FOOTHOLD_POSITIVE = [
        "session opened", "meterpreter", "shell session",
        "command shell", "reverse shell", "bind shell",
        "successfully exploited", "access granted",
        "root@", "www-data@", "uid=", "whoami",
    ]
    # Negative evidence that overrides positive matches
    _FOOTHOLD_NEGATIVE = [
        "unsuccessful", "not vulnerable", "failed",
        "no session", "exploit completed but no session",
        "success rate: 0", "0 sessions opened",
    ]

    def _process_exploit_result(self, tool_name: str, result: dict) -> None:
        """Helper to process exploit results with robust evidence checking."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        observation = (result.get("stdout", "") + "\n" + result.get("stderr", "")).lower()

        # Check for negative evidence first (overrides any positive match)
        has_negative = any(neg in observation for neg in self._FOOTHOLD_NEGATIVE)
        if has_negative:
            self.state.set_observation(f"Exploit {tool_name} did not succeed (negative evidence found)")
            return

        # Check for positive evidence of shell/foothold
        has_positive = any(pos in observation for pos in self._FOOTHOLD_POSITIVE)
        if has_positive:
            self.state.set_foothold(tool_name)
            td = self._get_transparency()
            if td:
                td.show_state_change("foothold_gained", f"{tool_name} — shell/access obtained")
        else:
            self.state.set_observation(f"Exploit {tool_name} completed but no clear foothold evidence")

    def _update_state_nmap_port_scan(self, result: dict) -> None:
        """Update state from Nmap port scan results."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        from core.tools.tool_parsers import parse_nmap_output

        stdout = result.get("stdout", "")
        # Hybrid parsing with LLM fallback
        parsed_services = parse_nmap_output(stdout, llm_client=self.brain.llm_client)

        if parsed_services:
            from core.agent.state import ServiceInfo

            services = [
                ServiceInfo(
                    port=svc_dict["port"],
                    protocol=svc_dict["proto"],
                    service=svc_dict["service"],
                )
                for svc_dict in parsed_services
            ]
            self.state.update_services(services)

            # Show discovered services to user (transparency)
            td = self._get_transparency()
            if td and self.state.open_services:
                td.show_discovered_services(self.state.open_services)
        else:
            # Log warning instead of injecting fake data
            logger.warning(
                "Nmap output parsing returned no services. "
                "Raw output (first 500 chars): %s",
                stdout[:500],
            )
            self.state.set_observation(
                "Nmap parsing failed — no services extracted from output. "
                "Consider re-running the scan or checking target reachability.",
            )
            td = self._get_transparency()
            if td:
                td.show_state_change(
                    "parse_failure",
                    "Nmap output could not be parsed — no mock data injected",
                )

    def _update_state_service_completion(self, result: dict) -> None:
        """Mark service as tested.

        Tries multiple strategies to identify the port:
        1. From args dict (if LLM provided port param)
        2. From the command string (e.g. 'nmap -p 80 ...')
        3. From stdout (service scan output)
        """
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)

        # Strategy 1: From args
        args_port = result.get("args", {}).get("port")

        # Strategy 2: Extract from command string
        if not args_port:
            args_port = self._extract_port_from_command(result)

        # Strategy 3: Try to extract from stdout (may handle multi-port)
        if not args_port and self._try_mark_ports_from_stdout(result):
            return

        if not args_port:
            self.state.set_observation("Service scan completed but could not determine port from result")
            return

        self._validate_and_mark_port(args_port)

    def _extract_port_from_command(self, result: dict) -> int | None:
        """Extract port number from command string in result."""
        import re

        command = result.get("command", "") or result.get("args", {}).get("command", "")
        if not command:
            return None
        port_match = re.search(r"-p\s*(\d{1,5})", str(command))
        if port_match:
            port_num = int(port_match.group(1))
            if 1 <= port_num <= 65535:
                return port_num
        return None

    def _try_mark_ports_from_stdout(self, result: dict) -> bool:
        """Try to extract and mark ports from stdout. Returns True if handled."""
        import re

        stdout = result.get("stdout", "")
        if not stdout:
            return False
        # Look for nmap-style "PORT/tcp open" lines
        port_matches = re.findall(r"(\d{1,5})/(?:tcp|udp)\s+open", stdout)
        if not port_matches:
            return False
        for port_str in port_matches:
            port_num = int(port_str)
            if port_num in self.state.open_services:
                svc = self.state.open_services[port_num]
                self.state.mark_surface_tested(port_num, svc.service)
        return True

    def _validate_and_mark_port(self, args_port: object) -> None:
        """Validate port value and mark the service as tested."""
        try:
            port_int = int(args_port)  # type: ignore[call-overload]
        except (ValueError, TypeError):
            self.state.set_observation(f"Invalid port value: {args_port}")
            return

        if port_int in self.state.open_services:
            service_info: ServiceInfo = self.state.open_services[port_int]
            self.state.mark_surface_tested(port_int, service_info.service)

    def _process_vulnerability_result(
        self,
        tool_name: str,
        result: dict,
        observation: str,
    ) -> None:
        """Helper to process vulnerability scan results."""
        if ("vuln" in tool_name or "sqlmap" in tool_name) and (
            "vulnerable" in observation.lower() or "injection" in observation.lower()
        ):
            self._handle_sqlmap_vulnerabilities(result)

            # AUTO-POC: Reanimate ExploitCrafter to generate reproduction scripts
            try:
                from modules.research.exploit_crafter import ExploitCrafter
                from modules.research.fuzzer import FuzzResult

                target_name: str = self.state.target or "target"
                crafter = ExploitCrafter()
                # Create a mock FuzzResult from the tool findings
                mock_crash = FuzzResult(
                    input_data=result.get("stdout", "Vulnerability payload"),
                    crash_detected=True,
                    error_message=f"Vulnerability found via {tool_name}: {observation}",
                )
                poc_path: str = crafter.generate_poc(
                    target_name.replace(".", "_"),
                    mock_crash,
                )
                self.console.print(
                    f"🚀 [bold green]Autonomous PoC Generated:[/] {poc_path}",
                )
            except Exception as e:
                logger.debug("PoC generation failed: %s", e)

    def _handle_sqlmap_vulnerabilities(self, result: dict) -> None:
        """Process SQLMap results and update state."""
        from core.tools.tool_parsers import parse_sqlmap_output

        stdout = result.get("stdout", "")
        # Hybrid parsing with LLM fallback
        _ = parse_sqlmap_output(stdout, llm_client=self.brain.llm_client)

        # Process findings (if any)
        if not (result.get("success") and "findings" in result):
            return

        for finding in result["findings"]:
            if self.state:
                self._record_single_vulnerability(finding)

    def _record_single_vulnerability(self, finding: dict) -> None:
        """Create a VulnerabilityInfo from a finding dict and add to state."""
        from core.agent.state import VulnerabilityInfo

        severity_str: str = str(finding.get("severity", "medium")).lower()

        vuln = VulnerabilityInfo(
            vuln_id=f"VULN-{int(time.time())}-{secrets.randbelow(9000) + 1000}",
            service=finding.get("service", "unknown"),
            port=int(finding.get("port", 0)),
            severity=severity_str,
            exploitable=True,
            exploit_attempted=False,
            exploit_success=False,
        )

        if hasattr(self.state, "add_vulnerability"):
            self.state.add_vulnerability(vuln)
        elif hasattr(self.state, "vulnerabilities") and isinstance(
            self.state.vulnerabilities,
            list,
        ):
            self.state.vulnerabilities.append(vuln)

        # Notify user about discovered vulnerability
        td = self._get_transparency()
        if td:
            td.show_state_change(
                "vulnerability_found",
                f"{vuln.vuln_id} — {vuln.service}:{vuln.port} ({vuln.severity})",
            )
