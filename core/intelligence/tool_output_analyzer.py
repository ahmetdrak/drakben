# core/intelligence/tool_output_analyzer.py
# DRAKBEN — Intelligent Tool Output Analyzer
# Parses raw tool outputs (nmap, nikto, etc.) into structured data
# using regex first, then LLM fallback for complex cases.
#
# Key improvement: Instead of dumping 500 lines of nmap output into
# the LLM context, we pre-parse it into compact structured data.

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AnalyzedOutput:
    """Structured analysis result from any tool output."""

    tool: str
    raw_length: int
    success: bool

    # Parsed data
    ports: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    credentials: list[dict[str, str]] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)

    # Metadata
    severity: str = "info"  # info, low, medium, high, critical
    summary: str = ""

    def to_compact_str(self, max_chars: int = 1500) -> str:
        """Convert to compact string for LLM context injection.

        Instead of feeding raw 500-line output, feed this compact summary.
        """
        lines: list[str] = []
        lines.append(f"[{self.tool}] {'OK' if self.success else 'FAIL'} | Severity: {self.severity}")

        if self.summary:
            lines.append(f"Summary: {self.summary}")

        if self.ports:
            ports_str = ", ".join(
                f"{p['port']}/{p.get('proto', 'tcp')}({p.get('service', '?')})"
                for p in self.ports[:15]
            )
            lines.append(f"Ports: {ports_str}")

        if self.vulnerabilities:
            for v in self.vulnerabilities[:5]:
                severity = v.get("severity", "?")
                name = v.get("name", v.get("title", "Unknown"))
                lines.append(f"  VULN [{severity}]: {name}")

        if self.credentials:
            lines.append(f"Credentials found: {len(self.credentials)}")

        if self.directories:
            dirs_str = ", ".join(self.directories[:10])
            lines.append(f"Directories: {dirs_str}")

        if self.findings:
            for f in self.findings[:5]:
                lines.append(f"  - {f[:120]}")

        result = "\n".join(lines)
        return result[:max_chars]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for persistence."""
        return {
            "tool": self.tool,
            "success": self.success,
            "severity": self.severity,
            "summary": self.summary,
            "ports": self.ports,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "findings": self.findings,
            "credentials": self.credentials,
            "directories": self.directories,
        }


class ToolOutputAnalyzer:
    """Parses raw tool output into structured data.

    Strategy:
    1. Use tool-specific regex parsers (fast, reliable)
    2. Fall back to generic pattern matching
    3. Optionally use LLM for complex/unknown formats

    Usage::

        analyzer = ToolOutputAnalyzer()
        result = analyzer.analyze("nmap_port_scan", raw_output)
        compact = result.to_compact_str()  # Feed this to LLM instead of raw output

    """

    def __init__(self, llm_client: Any = None) -> None:
        self._llm = llm_client

        # Tool-specific parsers
        self._parsers: dict[str, Any] = {
            "nmap_port_scan": self._parse_nmap,
            "nmap_service_scan": self._parse_nmap,
            "nmap_vuln_scan": self._parse_nmap_vuln,
            "nikto_web_scan": self._parse_nikto,
            "gobuster": self._parse_gobuster,
            "ffuf": self._parse_ffuf,
            "sqlmap_scan": self._parse_sqlmap,
            "hydra": self._parse_hydra,
            "searchsploit": self._parse_searchsploit,
            "enum4linux": self._parse_enum4linux,
            "nuclei_scan": self._parse_nuclei,
        }

    def analyze(self, tool_name: str, raw_output: str, *, success: bool = True) -> AnalyzedOutput:
        """Analyze tool output into structured data.

        Args:
            tool_name: Name of the tool that produced the output
            raw_output: Raw stdout from the tool
            success: Whether the tool execution succeeded

        Returns:
            AnalyzedOutput with parsed data

        """
        result = AnalyzedOutput(
            tool=tool_name,
            raw_length=len(raw_output),
            success=success,
        )

        if not raw_output or not raw_output.strip():
            result.summary = "No output"
            return result

        # Use tool-specific parser
        parser = self._parsers.get(tool_name)
        if parser:
            try:
                parser(raw_output, result)
            except Exception as e:
                logger.debug("Parser for %s failed: %s", tool_name, e)

        # Generic pattern matching (always runs, adds to existing data)
        self._generic_analysis(raw_output, result)

        # Auto-generate summary if not set
        if not result.summary:
            result.summary = self._auto_summary(result)

        return result

    # ─────────────────────── Tool-Specific Parsers ───────────────────────

    def _parse_nmap(self, output: str, result: AnalyzedOutput) -> None:
        """Parse nmap port/service scan output."""
        # Port lines: 80/tcp open http Apache 2.4.49
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?",
        )
        for match in port_pattern.finditer(output):
            port_info = {
                "port": int(match.group(1)),
                "proto": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": (match.group(5) or "").strip(),
            }
            if port_info["state"] == "open":
                result.ports.append(port_info)
                result.services.append({
                    "port": port_info["port"],
                    "service": port_info["service"],
                    "version": port_info["version"],
                })

        # OS detection
        os_match = re.search(r"OS details?:\s*(.+)", output)
        if os_match:
            result.findings.append(f"OS: {os_match.group(1).strip()}")

        # Hostname
        hostname_match = re.search(r"Nmap scan report for\s+(\S+)", output)
        if hostname_match:
            result.findings.append(f"Host: {hostname_match.group(1)}")

    def _parse_nmap_vuln(self, output: str, result: AnalyzedOutput) -> None:
        """Parse nmap vulnerability scan output (--script vuln)."""
        # First parse ports
        self._parse_nmap(output, result)

        # CVE references
        cve_pattern = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
        seen_cves: set[str] = set()
        for match in cve_pattern.finditer(output):
            cve = match.group(1).upper()
            if cve not in seen_cves:
                seen_cves.add(cve)
                result.vulnerabilities.append({
                    "name": cve,
                    "severity": "high",
                    "type": "cve",
                })

        # VULNERABLE marker
        if "VULNERABLE" in output.upper():
            result.severity = "high"
            vuln_pattern = re.compile(r"^\|\s+(.+VULNERABLE.+)$", re.MULTILINE | re.IGNORECASE)
            for match in vuln_pattern.finditer(output):
                result.findings.append(match.group(1).strip()[:150])

    def _parse_nikto(self, output: str, result: AnalyzedOutput) -> None:
        """Parse nikto web vulnerability scan output."""
        # Nikto findings: + OSVDB-xxxx: /path: description
        finding_pattern = re.compile(r"^\+\s+(.+)$", re.MULTILINE)
        for match in finding_pattern.finditer(output):
            line = match.group(1).strip()
            if len(line) > 10:
                result.findings.append(line[:150])
                # Check severity indicators
                if any(kw in line.lower() for kw in ("xss", "injection", "rce", "execute")):
                    result.severity = "high"
                elif any(kw in line.lower() for kw in ("directory", "listing", "disclosure")):
                    if result.severity == "info":
                        result.severity = "medium"

        # Server info
        server_match = re.search(r"Server:\s*(.+)", output)
        if server_match:
            result.findings.insert(0, f"Server: {server_match.group(1).strip()}")

    def _parse_gobuster(self, output: str, result: AnalyzedOutput) -> None:
        """Parse gobuster directory discovery output."""
        # /path (Status: 200) [Size: 1234]
        dir_pattern = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\)")
        for match in dir_pattern.finditer(output):
            path = match.group(1)
            status = int(match.group(2))
            if status < 400:
                result.directories.append(path)
                result.findings.append(f"Directory: {path} (HTTP {status})")

    def _parse_ffuf(self, output: str, result: AnalyzedOutput) -> None:
        """Parse ffuf fuzzing output."""
        # Various ffuf output formats
        entry_pattern = re.compile(r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)")
        for match in entry_pattern.finditer(output):
            path = match.group(1)
            status = int(match.group(2))
            if status < 400:
                result.directories.append(path)
                result.findings.append(f"Found: {path} (HTTP {status}, {match.group(3)} bytes)")

    def _parse_sqlmap(self, output: str, result: AnalyzedOutput) -> None:
        """Parse sqlmap SQL injection output."""
        output_lower = output.lower()

        if "is vulnerable" in output_lower or "sqlmap identified" in output_lower:
            result.severity = "critical"

            # Extract injection types
            type_pattern = re.compile(r"Type:\s*(.+)", re.IGNORECASE)
            param_pattern = re.compile(r"Parameter:\s*#?(\S+)", re.IGNORECASE)

            current_param = ""
            for line in output.split("\n"):
                pm = param_pattern.search(line)
                if pm:
                    current_param = pm.group(1)

                tm = type_pattern.search(line)
                if tm:
                    result.vulnerabilities.append({
                        "name": f"SQLi: {tm.group(1).strip()}",
                        "parameter": current_param,
                        "severity": "critical",
                        "type": "sqli",
                    })

        # Database info
        db_match = re.search(r"back-end DBMS:\s*(.+)", output, re.IGNORECASE)
        if db_match:
            result.findings.append(f"DBMS: {db_match.group(1).strip()}")

    def _parse_hydra(self, output: str, result: AnalyzedOutput) -> None:
        """Parse hydra brute-force output."""
        # [22][ssh] host: 10.0.0.1   login: admin   password: admin123
        cred_pattern = re.compile(
            r"\[\d+\]\[\S+\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
        )
        for match in cred_pattern.finditer(output):
            result.credentials.append({
                "username": match.group(1),
                "password": match.group(2),
            })
            result.severity = "critical"

        if result.credentials:
            result.findings.append(f"Found {len(result.credentials)} valid credential(s)")

    def _parse_searchsploit(self, output: str, result: AnalyzedOutput) -> None:
        """Parse searchsploit exploit search output."""
        # Exploit Title | Path
        entry_pattern = re.compile(r"^\s*(.+?)\s*\|\s*(exploits/.+|shellcodes/.+)$", re.MULTILINE)
        for match in entry_pattern.finditer(output):
            title = match.group(1).strip()
            path = match.group(2).strip()
            if title and not title.startswith("-"):
                result.findings.append(f"Exploit: {title}")
                result.vulnerabilities.append({
                    "name": title[:100],
                    "path": path,
                    "severity": "medium",
                    "type": "exploit",
                })

    def _parse_enum4linux(self, output: str, result: AnalyzedOutput) -> None:
        """Parse enum4linux SMB enumeration output."""
        # Users
        user_pattern = re.compile(r"user:\[\s*(\S+)\s*\]", re.IGNORECASE)
        users = set()
        for match in user_pattern.finditer(output):
            users.add(match.group(1))

        if users:
            result.findings.append(f"Users: {', '.join(sorted(users)[:10])}")

        # Shares
        share_pattern = re.compile(r"^\s*(\\\\[^ ]+)\s+(Disk|IPC|Printer)", re.MULTILINE)
        for match in share_pattern.finditer(output):
            result.findings.append(f"Share: {match.group(1)} ({match.group(2)})")

        # Domain
        domain_match = re.search(r"Domain Name:\s*(\S+)", output, re.IGNORECASE)
        if domain_match:
            result.findings.append(f"Domain: {domain_match.group(1)}")

    def _parse_nuclei(self, output: str, result: AnalyzedOutput) -> None:
        """Parse nuclei vulnerability scanner output."""
        # [severity] [template-id] [protocol] target
        entry_pattern = re.compile(
            r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)",
        )
        for match in entry_pattern.finditer(output):
            severity = match.group(1).lower()
            template = match.group(2)

            result.vulnerabilities.append({
                "name": template,
                "severity": severity,
                "type": "nuclei",
            })

            # Update overall severity
            severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if severity_order.get(severity, 0) > severity_order.get(result.severity, 0):
                result.severity = severity

    # ─────────────────────── Generic Analysis ───────────────────────

    def _generic_analysis(self, output: str, result: AnalyzedOutput) -> None:
        """Generic pattern matching for any tool output."""
        output_lower = output.lower()

        # CVE detection (if not already found)
        if not result.vulnerabilities:
            cve_pattern = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
            seen: set[str] = set()
            for match in cve_pattern.finditer(output):
                cve = match.group(1).upper()
                if cve not in seen:
                    seen.add(cve)
                    result.vulnerabilities.append({
                        "name": cve,
                        "severity": "medium",
                        "type": "cve",
                    })

        # Severity escalation based on keywords
        critical_keywords = ["remote code execution", "rce", "shell", "root access", "admin access"]
        high_keywords = ["vulnerable", "exploit", "injection", "overflow"]
        medium_keywords = ["disclosure", "directory listing", "weak password"]

        if any(kw in output_lower for kw in critical_keywords):
            result.severity = "critical"
        elif any(kw in output_lower for kw in high_keywords) and result.severity in ("info", "low"):
            result.severity = "high"
        elif any(kw in output_lower for kw in medium_keywords) and result.severity == "info":
            result.severity = "medium"

    def _auto_summary(self, result: AnalyzedOutput) -> str:
        """Generate automatic summary from parsed data."""
        parts: list[str] = []

        if result.ports:
            parts.append(f"{len(result.ports)} open port(s)")
        if result.vulnerabilities:
            parts.append(f"{len(result.vulnerabilities)} vulnerability(ies)")
        if result.credentials:
            parts.append(f"{len(result.credentials)} credential(s) found")
        if result.directories:
            parts.append(f"{len(result.directories)} directory(ies) discovered")
        if result.findings and not parts:
            parts.append(f"{len(result.findings)} finding(s)")

        if not parts:
            return "No significant findings"

        return f"{result.tool}: {', '.join(parts)} [{result.severity}]"
