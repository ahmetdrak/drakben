# core/agent/cognitive/perceive.py
"""Perceive Module - Stanford Cognitive Architecture.

The Perceive module is the first stage of the cognitive cycle:
Tool Output → ConceptNode Conversion

This module:
1. Takes raw tool outputs (nmap, sqlmap, nuclei, etc.)
2. Extracts key information
3. Auto-scores poignancy (importance)
4. Creates properly typed ConceptNodes
5. Stores them in the MemoryStream

Stanford Reference:
"The first step in the cognitive cycle is perceiving - the agent observes
the environment and converts observations into memory nodes."

Pentest-Specific Extensions:
- Automatic vulnerability severity detection
- Credential extraction and secure handling
- Service discovery parsing
- CVE identification and scoring
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

from core.agent.memory.concept_node import (
    ConceptNode,
    NodeType,
    PentestRelevance,
    SPOTriple,
    create_event_node,
    create_finding_node,
)

if TYPE_CHECKING:
    from core.agent.memory.memory_stream import MemoryStream

logger = logging.getLogger(__name__)


# Patterns for extracting pentest-relevant information
PATTERNS = {
    # CVE pattern
    "cve": re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE),
    # Port/service pattern (from nmap)
    "port_service": re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\w+)"),
    # IP address pattern
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    # Vulnerability keywords
    "vuln_critical": re.compile(
        r"(RCE|remote code execution|command injection|SQL injection|"
        r"authentication bypass|privilege escalation|root|admin access)",
        re.IGNORECASE,
    ),
    "vuln_high": re.compile(
        r"(XSS|cross-site scripting|IDOR|path traversal|LFI|RFI|"
        r"file inclusion|SSRF|XXE|deserialization)",
        re.IGNORECASE,
    ),
    # Credential patterns
    "credential": re.compile(
        r"(password|passwd|pwd|credential|secret|api.?key|token|auth)",
        re.IGNORECASE,
    ),
    # Success indicators
    "success": re.compile(
        r"(success|found|discovered|vulnerable|confirmed|exploited|pwned)",
        re.IGNORECASE,
    ),
    # Failure indicators
    "failure": re.compile(
        r"(failed|error|timeout|refused|denied|not vulnerable|not found)",
        re.IGNORECASE,
    ),
}


class PerceiveModule:
    """Converts tool outputs into ConceptNodes for memory storage.

    This is the sensory input system of the cognitive architecture.
    It observes tool outputs and creates structured memory nodes.
    """

    def __init__(self, memory_stream: MemoryStream | None = None) -> None:
        """Initialize the perceive module.

        Args:
            memory_stream: Optional MemoryStream for direct storage
        """
        self._memory_stream = memory_stream

    def perceive(
        self,
        tool_name: str,
        tool_output: str,
        target: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> list[ConceptNode]:
        """Perceive and convert tool output to memory nodes.

        Args:
            tool_name: Name of the tool (nmap, sqlmap, etc.)
            tool_output: Raw output from the tool
            target: Target IP/domain
            metadata: Additional context

        Returns:
            List of created ConceptNodes
        """
        nodes: list[ConceptNode] = []

        # Determine tool type and use specialized parser
        parser = self._get_parser(tool_name)
        nodes = parser(tool_name, tool_output, target, metadata or {})

        # Store nodes if memory stream is available
        if self._memory_stream:
            for node in nodes:
                self._memory_stream.add(node)
                logger.debug(
                    "Perceived: %s (%s, poignancy=%.1f)",
                    node.description[:50],
                    node.node_type.value,
                    node.poignancy,
                )

        return nodes

    def _get_parser(self, tool_name: str) -> Any:
        """Get the appropriate parser for a tool."""
        parsers = {
            "nmap": self._parse_nmap,
            "sqlmap": self._parse_vuln_scanner,
            "nuclei": self._parse_vuln_scanner,
            "nikto": self._parse_vuln_scanner,
            "dirb": self._parse_dirb,
            "gobuster": self._parse_dirb,
            "hydra": self._parse_credential_tool,
            "hashcat": self._parse_credential_tool,
            "metasploit": self._parse_exploit_tool,
            "msfconsole": self._parse_exploit_tool,
        }
        return parsers.get(tool_name.lower(), self._parse_generic)

    def _parse_nmap(
        self,
        tool_name: str,
        output: str,
        target: str | None,
        metadata: dict,
    ) -> list[ConceptNode]:
        """Parse nmap output for service discovery."""
        nodes: list[ConceptNode] = []

        # Extract port/service information
        port_matches = PATTERNS["port_service"].findall(output)
        services_found = []

        for port, protocol, service in port_matches:
            services_found.append(f"{port}/{protocol} ({service})")

            # Create event node for each discovered service
            node = create_event_node(
                description=f"Discovered {service} on port {port}/{protocol}",
                tool=tool_name,
                result="service_discovered",
                poignancy=self._calculate_service_poignancy(service),
                target=target,
                pentest_relevance=PentestRelevance.SERVICE_INFO,
            )
            nodes.append(node)

        # Create summary event if services found
        if services_found:
            summary = create_event_node(
                description=f"Port scan completed: {len(services_found)} open ports found",
                tool=tool_name,
                result="scan_complete",
                poignancy=6.0,
                target=target,
                pentest_relevance=PentestRelevance.RECON_DATA,
            )
            summary.metadata["services"] = services_found
            nodes.append(summary)

        return nodes

    def _parse_vuln_scanner(
        self,
        tool_name: str,
        output: str,
        target: str | None,
        metadata: dict,
    ) -> list[ConceptNode]:
        """Parse vulnerability scanner output (sqlmap, nuclei, nikto)."""
        nodes: list[ConceptNode] = []

        # Check for CVEs
        cves = PATTERNS["cve"].findall(output)
        for cve in set(cves):
            node = create_finding_node(
                description=f"CVE identified: {cve}",
                finding_type="vulnerability",
                severity="high",  # CVEs are at least high
                target=target,
            )
            node.metadata["cve"] = cve
            nodes.append(node)

        # Check for critical vulnerabilities
        if PATTERNS["vuln_critical"].search(output):
            severity = "critical"
            relevance = PentestRelevance.CRITICAL_VULN
            poignancy = 10.0
        elif PATTERNS["vuln_high"].search(output):
            severity = "high"
            relevance = PentestRelevance.HIGH_VULN
            poignancy = 8.0
        else:
            severity = "medium"
            relevance = PentestRelevance.RECON_DATA
            poignancy = 5.0

        # Create main finding node
        finding = ConceptNode(
            description=self._summarize_output(output, tool_name),
            poignancy=poignancy,
            node_type=NodeType.FINDING,
            pentest_relevance=relevance,
            spo_triple=SPOTriple(
                subject=tool_name,
                predicate="discovered",
                obj=f"{severity} vulnerability",
            ),
            metadata={"tool": tool_name, "severity": severity, "cves": cves},
            target=target,
        )
        nodes.append(finding)

        return nodes

    def _parse_dirb(
        self,
        tool_name: str,
        output: str,
        target: str | None,
        metadata: dict,
    ) -> list[ConceptNode]:
        """Parse directory bruteforce output."""
        nodes: list[ConceptNode] = []

        # Count found directories/files by parsing line-by-line with proper pattern
        # Dirb/Gobuster lines look like: "+ http://...  (CODE:200|SIZE:1234)"
        dirb_line_pattern = re.compile(
            r"(?:^\+?\s*https?://\S+.*\bCODE:\s*200\b)"
            r"|(?:^https?://\S+\s+\(Status:\s*200\b)"
            r"|(?:^/\S+\s+\(Status:\s*200\b)",
            re.MULTILINE,
        )
        found_count = len(dirb_line_pattern.findall(output))
        # Fallback: count lines containing 'found' keyword as secondary signal
        for line in output.splitlines():
            stripped = line.strip().lower()
            if "found" in stripped and "200" not in stripped:
                found_count += 1

        node = create_event_node(
            description=f"Directory enumeration: {found_count} interesting paths found",
            tool=tool_name,
            result="enumeration_complete",
            poignancy=min(5.0 + found_count * 0.5, 8.0),
            target=target,
            pentest_relevance=PentestRelevance.RECON_DATA,
        )
        nodes.append(node)

        return nodes

    def _parse_credential_tool(
        self,
        tool_name: str,
        output: str,
        target: str | None,
        metadata: dict,
    ) -> list[ConceptNode]:
        """Parse credential tools output (hydra, hashcat)."""
        nodes: list[ConceptNode] = []

        # Check for success
        if PATTERNS["success"].search(output):
            # Credential found - HIGH IMPORTANCE
            node = create_finding_node(
                description=f"Credential discovered via {tool_name}",
                finding_type="credential",
                severity="critical",
                target=target,
            )
            node.poignancy = 9.0  # Very high
            node.pentest_relevance = PentestRelevance.CREDENTIAL
            nodes.append(node)
        else:
            # Attempt without success
            node = create_event_node(
                description=f"Credential attack attempted with {tool_name}",
                tool=tool_name,
                result="no_credentials_found",
                poignancy=4.0,
                target=target,
                pentest_relevance=PentestRelevance.RECON_DATA,
            )
            nodes.append(node)

        return nodes

    def _parse_exploit_tool(
        self,
        tool_name: str,
        output: str,
        target: str | None,
        metadata: dict,
    ) -> list[ConceptNode]:
        """Parse exploit framework output (metasploit)."""
        nodes: list[ConceptNode] = []

        # Check for successful exploitation
        success_indicators = ["session opened", "meterpreter", "shell", "pwned"]
        is_success = any(ind in output.lower() for ind in success_indicators)

        if is_success:
            # CRITICAL: Foothold achieved
            node = ConceptNode(
                description=f"FOOTHOLD ACHIEVED via {tool_name}",
                poignancy=10.0,  # Maximum importance
                node_type=NodeType.FINDING,
                pentest_relevance=PentestRelevance.ATTACK_PATH,
                spo_triple=SPOTriple(
                    subject=tool_name,
                    predicate="achieved",
                    obj="foothold/shell access",
                ),
                metadata={"tool": tool_name, "foothold": True},
                target=target,
            )
            nodes.append(node)
        else:
            # Exploit attempted
            node = create_event_node(
                description=f"Exploit attempted with {tool_name}",
                tool=tool_name,
                result="exploit_attempted",
                poignancy=6.0,
                target=target,
                pentest_relevance=PentestRelevance.RECON_DATA,
            )
            nodes.append(node)

        return nodes

    def _parse_generic(
        self,
        tool_name: str,
        output: str,
        target: str | None,
        metadata: dict,
    ) -> list[ConceptNode]:
        """Generic parser for unknown tools."""
        # Auto-detect importance from output content
        poignancy = self._auto_score_poignancy(output)
        relevance = self._detect_pentest_relevance(output)

        node = create_event_node(
            description=self._summarize_output(output, tool_name),
            tool=tool_name,
            result="completed",
            poignancy=poignancy,
            target=target,
            pentest_relevance=relevance,
        )

        return [node]

    def _calculate_service_poignancy(self, service: str) -> float:
        """Calculate poignancy based on service type."""
        high_value_services = {
            "ssh": 6.0,
            "ftp": 6.0,
            "smb": 7.0,
            "rdp": 7.0,
            "telnet": 7.0,
            "mysql": 7.0,
            "postgresql": 7.0,
            "mssql": 7.0,
            "oracle": 7.0,
            "redis": 6.5,
            "mongodb": 6.5,
            "ldap": 7.0,
            "http": 5.0,
            "https": 5.0,
        }
        return high_value_services.get(service.lower(), 5.0)

    def _auto_score_poignancy(self, output: str) -> float:
        """Auto-score poignancy based on output content."""
        score = 5.0  # Base score

        # Critical vulnerability indicators
        if PATTERNS["vuln_critical"].search(output):
            score = max(score, 9.0)
        elif PATTERNS["vuln_high"].search(output):
            score = max(score, 7.0)

        # Credential indicators
        if PATTERNS["credential"].search(output):
            score = max(score, 8.0)

        # Success/failure modifiers
        if PATTERNS["success"].search(output):
            score = min(score + 1.0, 10.0)
        if PATTERNS["failure"].search(output):
            score = max(score - 1.0, 1.0)

        return score

    def _detect_pentest_relevance(self, output: str) -> PentestRelevance:
        """Detect pentest relevance category from output."""
        if PATTERNS["vuln_critical"].search(output):
            return PentestRelevance.CRITICAL_VULN
        if PATTERNS["vuln_high"].search(output):
            return PentestRelevance.HIGH_VULN
        if PATTERNS["credential"].search(output):
            return PentestRelevance.CREDENTIAL
        if PATTERNS["port_service"].search(output):
            return PentestRelevance.SERVICE_INFO
        return PentestRelevance.GENERIC

    def _summarize_output(self, output: str, tool_name: str) -> str:
        """Create a concise summary of tool output."""
        # Take first 200 chars, clean up
        summary = output[:200].strip()
        summary = " ".join(summary.split())  # Normalize whitespace

        if len(output) > 200:
            summary += "..."

        return f"{tool_name}: {summary}"


def perceive_tool_output(
    tool_name: str,
    tool_output: str,
    memory_stream: MemoryStream | None = None,
    target: str | None = None,
) -> list[ConceptNode]:
    """Convenience function to perceive tool output.

    Args:
        tool_name: Name of the tool
        tool_output: Raw tool output
        memory_stream: Optional MemoryStream for storage
        target: Target IP/domain

    Returns:
        List of created ConceptNodes
    """
    perceiver = PerceiveModule(memory_stream)
    return perceiver.perceive(tool_name, tool_output, target)
