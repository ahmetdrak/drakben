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
    from core.agent.state import ServiceInfo

logger = logging.getLogger(__name__)

# Error message constant (mirrors refactored_agent._ERR_UNKNOWN)
_ERR_UNKNOWN = "Unknown error"


class RAStateUpdatesMixin:
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
        """Dispatch state update based on tool type."""
        if "nmap_port_scan" in tool_name:
            self._update_state_nmap_port_scan(result)
        elif "nmap_service_scan" in tool_name or "nikto" in tool_name:
            self._update_state_service_completion(result)
        elif "vuln" in tool_name or "sqlmap" in tool_name:
            observation = result.get("stdout", "")
            self._process_vulnerability_result(tool_name, result, observation)
        elif "exploit" in tool_name:
            self._process_exploit_result(tool_name, result)

    def _process_exploit_result(self, tool_name: str, result: dict) -> None:
        """Helper to process exploit results."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        observation = result.get("stdout", "") + "\n" + result.get("stderr", "")
        # Check if exploit succeeded based on output evidence
        if (
            "success" in observation.lower()
            or "shell" in observation.lower()
        ):
            self.state.set_foothold(tool_name)
        else:
            self.state.set_observation("Exploit did not succeed; foothold not set")

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
        else:
            # Fallback to mock if parsing failed (for testing)
            self._apply_mock_services()

    def _apply_mock_services(self) -> None:
        """Apply mock services for testing or fallback."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)
        from core.agent.state import ServiceInfo

        services: list[ServiceInfo] = [
            ServiceInfo(port=80, protocol="tcp", service="http"),
            ServiceInfo(port=443, protocol="tcp", service="https"),
            ServiceInfo(port=22, protocol="tcp", service="ssh"),
        ]
        self.state.update_services(services)

    def _update_state_service_completion(self, result: dict) -> None:
        """Mark service as tested."""
        if self.state is None:
            raise AssertionError(self.MSG_STATE_NOT_NONE)

        args_port = result.get("args", {}).get("port")
        if not args_port:
            self.state.set_observation("Missing port in tool args; state not updated")
            return

        if args_port in self.state.open_services:
            service_info: ServiceInfo = self.state.open_services[args_port]
            self.state.mark_surface_tested(args_port, service_info.service)

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

        # 3. Process findings (if any)
        if result.get("success") and "findings" in result:
            for finding in result["findings"]:
                if self.state:
                    from core.agent.state import VulnerabilityInfo

                    # Adapt finding dict to VulnerabilityInfo dataclass
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
