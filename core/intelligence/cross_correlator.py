# core/intelligence/cross_correlator.py
# DRAKBEN — Cross-Tool Output Correlation Engine
#
# Problem: nmap finds port 80, nikto finds /admin, nuclei finds CVE
#          — but these are stored separately, never correlated.
# Solution: Build a unified TargetProfile that merges findings from
#          ALL tools into a single enriched picture.
#
# This enables:
#   - "Port 80 has Apache 2.4.49 (nmap) + path traversal (nikto) + CVE-2021-41773 (nuclei)"
#   - Automatic attack surface prioritization
#   - Duplicate finding elimination
#   - Confidence boosting when multiple tools agree

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ServiceProfile:
    """Everything known about a single service on a target."""

    port: int
    protocol: str = "tcp"
    service: str = ""           # e.g., "http", "ssh", "smb"
    product: str = ""           # e.g., "Apache", "OpenSSH"
    version: str = ""           # e.g., "2.4.49", "7.9p1"
    os_hint: str = ""
    cves: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    tools_reported: list[str] = field(default_factory=list)
    paths_discovered: list[str] = field(default_factory=list)
    credentials: list[dict] = field(default_factory=list)
    severity: str = "info"      # Highest severity across findings
    confidence: float = 0.0     # Higher when multiple tools agree
    last_updated: float = 0.0

    @staticmethod
    def _merge_unique(target: list, source: list) -> None:
        """Append items from source to target, skipping duplicates."""
        for item in source:
            if item not in target:
                target.append(item)

    def merge(self, other: ServiceProfile) -> None:
        """Merge another profile's findings into this one."""
        if not self.product and other.product:
            self.product = other.product
        if not self.version and other.version:
            self.version = other.version
        if not self.os_hint and other.os_hint:
            self.os_hint = other.os_hint

        for attr in ("cves", "findings", "tools_reported", "paths_discovered", "credentials"):
            self._merge_unique(getattr(self, attr), getattr(other, attr))

        # Severity escalation
        self.severity = _max_severity(self.severity, other.severity)

        # Confidence boosting: more tools = more confidence
        self.confidence = min(1.0, 0.3 * len(self.tools_reported))
        self.last_updated = time.time()


@dataclass
class TargetProfile:
    """Unified intelligence picture of a target, merging all tool outputs."""

    target: str
    services: dict[str, ServiceProfile] = field(default_factory=dict)  # key: "port/proto"
    os_fingerprint: str = ""
    hostnames: list[str] = field(default_factory=list)
    network_position: str = ""   # "external", "internal", "dmz"
    total_findings: int = 0
    highest_severity: str = "info"
    attack_surface_score: float = 0.0  # 0-10
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)

    def get_service(self, port: int, proto: str = "tcp") -> ServiceProfile:
        """Get or create a service profile for a port."""
        key = f"{port}/{proto}"
        if key not in self.services:
            self.services[key] = ServiceProfile(port=port, protocol=proto)
        return self.services[key]

    def get_critical_services(self) -> list[ServiceProfile]:
        """Get services with high/critical severity, sorted by priority."""
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        critical = [
            s for s in self.services.values()
            if s.severity in ("critical", "high")
        ]
        return sorted(critical, key=lambda s: sev_order.get(s.severity, 4))

    def get_attack_paths(self) -> list[dict[str, Any]]:
        """Generate prioritized attack paths from correlated findings."""
        paths: list[dict[str, Any]] = []
        for svc in self.services.values():
            if not svc.cves and svc.severity in ("info", "low"):
                continue
            path = {
                "service": f"{svc.service}:{svc.port}",
                "product": f"{svc.product} {svc.version}".strip(),
                "cves": svc.cves[:5],
                "findings_count": len(svc.findings),
                "confidence": svc.confidence,
                "severity": svc.severity,
                "suggested_tools": _suggest_tools_for_service(svc),
            }
            paths.append(path)

        # Sort by severity then confidence
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        paths.sort(key=lambda p: (sev_order.get(p["severity"], 4), -p["confidence"]))
        return paths

    def to_compact_str(self) -> str:
        """Compact string representation for LLM context injection."""
        lines = [f"=== Target Profile: {self.target} ==="]
        if self.os_fingerprint:
            lines.append(f"OS: {self.os_fingerprint}")
        lines.append(f"Attack Surface Score: {self.attack_surface_score:.1f}/10")
        lines.append(f"Highest Severity: {self.highest_severity}")
        lines.append(f"Services: {len(self.services)}")

        for key, svc in sorted(self.services.items()):
            lines.append(self._format_service_line(key, svc))

        self._append_attack_paths(lines)
        return "\n".join(lines)

    def _format_service_line(self, key: str, svc: ServiceProfile) -> str:
        """Format a single service line for compact output."""
        svc_line = f"  {key}: {svc.service}"
        if svc.product:
            svc_line += f" ({svc.product} {svc.version})".rstrip()
        if svc.cves:
            svc_line += f" [CVEs: {', '.join(svc.cves[:3])}]"
        if svc.severity in ("critical", "high"):
            svc_line += f" ⚠️ {svc.severity.upper()}"
            for f in svc.findings[:3]:
                svc_line += f"\n    → {f[:80]}"
        return svc_line

    def _append_attack_paths(self, lines: list[str]) -> None:
        """Append prioritized attack paths to output lines."""
        attack_paths = self.get_attack_paths()
        if not attack_paths:
            return
        lines.append(f"\nPrioritized Attack Paths ({len(attack_paths)}):")
        for i, ap in enumerate(attack_paths[:5], 1):
            lines.append(
                f"  {i}. {ap['service']} {ap['product']} "
                f"[{ap['severity']}] conf={ap['confidence']:.0%}",
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize for storage/transmission."""
        return {
            "target": self.target,
            "os_fingerprint": self.os_fingerprint,
            "hostnames": self.hostnames,
            "highest_severity": self.highest_severity,
            "attack_surface_score": self.attack_surface_score,
            "services": {
                k: {
                    "port": s.port, "protocol": s.protocol,
                    "service": s.service, "product": s.product,
                    "version": s.version, "cves": s.cves,
                    "findings": s.findings[:10],
                    "severity": s.severity, "confidence": s.confidence,
                    "tools_reported": s.tools_reported,
                    "paths_discovered": s.paths_discovered[:20],
                }
                for k, s in self.services.items()
            },
        }

    def recalculate(self) -> None:
        """Recalculate aggregate stats after merges."""
        self.total_findings = sum(len(s.findings) for s in self.services.values())
        if self.services:
            self.highest_severity = max(
                (s.severity for s in self.services.values()),
                key=lambda sv: _SEVERITY_ORDER.get(sv, 4),
                default="info",
            )
        self.attack_surface_score = self._calc_attack_surface()
        self.last_updated = time.time()

    def _calc_attack_surface(self) -> float:
        """Calculate attack surface score (0-10)."""
        score = 0.0
        for svc in self.services.values():
            sev_weight = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.3, "info": 0.1}
            score += sev_weight.get(svc.severity, 0.1)
            score += len(svc.cves) * 0.5
            score += len(svc.paths_discovered) * 0.05
        return min(10.0, score)


# ── Severity helpers ──

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_WEB_SERVICES = ("http", "https", "ssl/http")


def _max_severity(a: str, b: str) -> str:
    """Return the higher severity."""
    if _SEVERITY_ORDER.get(a, 4) <= _SEVERITY_ORDER.get(b, 4):
        return a
    return b


def _suggest_tools_for_service(svc: ServiceProfile) -> list[str]:
    """Suggest tools based on service type."""
    suggestions: list[str] = []
    service_lower = svc.service.lower()

    if service_lower in _WEB_SERVICES:
        suggestions.extend(["nikto", "gobuster", "sqlmap", "nuclei"])
    if service_lower == "ssh":
        suggestions.append("hydra")
    if service_lower in ("smb", "microsoft-ds", "netbios-ssn"):
        suggestions.extend(["enum4linux", "smbclient", "crackmapexec"])
    if service_lower in ("mysql", "postgresql", "mssql"):
        suggestions.extend(["sqlmap", "hydra"])
    if service_lower == "ftp":
        suggestions.extend(["hydra", "nmap_scripts"])
    if service_lower in ("rdp", "ms-wbt-server"):
        suggestions.append("hydra")
    if service_lower in ("dns", "domain"):
        suggestions.extend(["dnsrecon", "fierce"])
    if service_lower == "smtp":
        suggestions.append("smtp-user-enum")
    if service_lower == "snmp":
        suggestions.append("snmpwalk")

    # CVE-based suggestions
    if svc.cves:
        if "nuclei" not in suggestions:
            suggestions.append("nuclei")
        suggestions.append("searchsploit")

    # WAF-detected suggestions
    if "waf" in " ".join(svc.findings).lower():
        suggestions.append("wafw00f")

    # Remove tools already used
    already_used = set(svc.tools_reported)
    return [t for t in suggestions if t not in already_used]


class CrossCorrelator:
    """Correlates outputs from multiple tools into unified target profiles.

    Usage::

        correlator = CrossCorrelator()
        correlator.ingest("nmap", nmap_output, target="10.0.0.1")
        correlator.ingest("nikto", nikto_output, target="10.0.0.1")
        profile = correlator.get_profile("10.0.0.1")
        print(profile.to_compact_str())

    """

    # Regex patterns for common output formats
    _RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    _RE_PORT = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)")
    _RE_NMAP_VERSION = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+?)\s+(\S+\s+[\d.]+)")
    _RE_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    _RE_NIKTO_FINDING = re.compile(r"\+\s+(.*)")
    _RE_HTTP_STATUS = re.compile(r"\b(200|301|302|403|404|500)\b")
    _RE_CRED = re.compile(
        r"(?:user(?:name)?|login|admin)\s*[:=]\s*(\S+).*?pass(?:word)?\s*[:=]\s*(\S+)",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        self._stats = {
            "ingestions": 0,
            "correlations_found": 0,
            "cves_extracted": 0,
        }

    def ingest(
        self,
        tool_name: str,
        output: str,
        target: str,
        *,
        parsed_data: dict | None = None,
    ) -> TargetProfile:
        """Ingest tool output and correlate with existing findings.

        Args:
            tool_name: Name of the tool (nmap, nikto, etc.).
            output: Raw stdout from the tool.
            target: Target IP/domain.
            parsed_data: Pre-parsed structured data (from ToolOutputAnalyzer).

        Returns:
            Updated TargetProfile for this target.

        """
        self._stats["ingestions"] += 1

        profile = self._profiles.get(target)
        if not profile:
            profile = TargetProfile(target=target)
            self._profiles[target] = profile

        # Use parsed data if available, otherwise parse raw output
        if parsed_data:
            self._ingest_parsed(profile, tool_name, parsed_data)
        else:
            self._ingest_raw(profile, tool_name, output)

        # Extract CVEs from any output
        cves_found = self._RE_CVE.findall(output)
        if cves_found:
            self._stats["cves_extracted"] += len(cves_found)
            self._distribute_cves(profile, cves_found, tool_name)

        # Extract credentials
        self._extract_and_associate_creds(output, tool_name, profile)

        profile.recalculate()
        return profile

    def _extract_and_associate_creds(
        self, output: str, tool_name: str, profile: TargetProfile,
    ) -> None:
        """Extract credentials from output and associate with services."""
        creds = self._RE_CRED.findall(output)
        for user, pwd in creds:
            cred = {"username": user, "password": pwd, "source": tool_name}
            for svc in profile.services.values():
                if tool_name in svc.tools_reported:
                    if cred not in svc.credentials:
                        svc.credentials.append(cred)
                    break

        profile.recalculate()
        return profile

    def get_profile(self, target: str) -> TargetProfile | None:
        """Get the current correlated profile for a target."""
        return self._profiles.get(target)

    def get_all_profiles(self) -> dict[str, TargetProfile]:
        """Get all target profiles."""
        return dict(self._profiles)

    def get_context_for_llm(self, target: str) -> str:
        """Get a compact string summary for LLM context injection."""
        profile = self._profiles.get(target)
        if not profile:
            return f"No correlated intelligence for {target} yet."
        return profile.to_compact_str()

    def get_stats(self) -> dict[str, Any]:
        """Return correlator statistics."""
        return {
            **self._stats,
            "targets_tracked": len(self._profiles),
            "total_services": sum(
                len(p.services) for p in self._profiles.values()
            ),
        }

    # ─────────────────── Internal Parsers ───────────────────

    def _ingest_parsed(
        self, profile: TargetProfile, tool_name: str, data: dict,
    ) -> None:
        """Ingest pre-parsed structured data."""
        self._ingest_open_ports(profile, tool_name, data.get("open_ports", []))
        self._ingest_vulnerabilities(profile, tool_name, data)
        self._ingest_discovered_paths(profile, data.get("paths", []))

    def _ingest_open_ports(
        self, profile: TargetProfile, tool_name: str, ports: list[dict],
    ) -> None:
        """Ingest open port data into profile."""
        for port_info in ports:
            port = port_info.get("port", 0)
            proto = port_info.get("protocol", "tcp")
            if not port:
                continue
            svc = profile.get_service(port, proto)
            svc.service = port_info.get("service", svc.service)
            svc.product = port_info.get("product", svc.product)
            svc.version = port_info.get("version", svc.version)
            if tool_name not in svc.tools_reported:
                svc.tools_reported.append(tool_name)

    def _ingest_vulnerabilities(
        self, profile: TargetProfile, tool_name: str, data: dict,
    ) -> None:
        """Ingest vulnerability findings into profile."""
        severity = data.get("severity", "medium")
        for vuln in data.get("vulnerabilities", []):
            finding = vuln if isinstance(vuln, str) else str(vuln)
            self._associate_finding(profile, tool_name, finding, severity)

    def _associate_finding(
        self, profile: TargetProfile, tool_name: str,
        finding: str, severity: str,
    ) -> None:
        """Associate a finding with the most relevant service."""
        for svc in profile.services.values():
            if tool_name in svc.tools_reported:
                if finding not in svc.findings:
                    svc.findings.append(finding)
                svc.severity = _max_severity(svc.severity, severity)
                return
        if profile.services:
            first = next(iter(profile.services.values()))
            if finding not in first.findings:
                first.findings.append(finding)

    def _ingest_discovered_paths(
        self, profile: TargetProfile, paths: list,
    ) -> None:
        """Ingest discovered paths into web service profiles."""
        for path in paths:
            path_str = path if isinstance(path, str) else str(path)
            for svc in profile.services.values():
                if svc.service in _WEB_SERVICES:
                    if path_str not in svc.paths_discovered:
                        svc.paths_discovered.append(path_str)
                    break

    def _ingest_raw(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse raw tool output into profile."""
        tool_lower = tool_name.lower()

        if "nmap" in tool_lower:
            self._parse_nmap_into_profile(profile, tool_name, output)
        elif "nikto" in tool_lower:
            self._parse_nikto_into_profile(profile, tool_name, output)
        elif "gobuster" in tool_lower or "ffuf" in tool_lower:
            self._parse_dirscan_into_profile(profile, tool_name, output)
        elif "nuclei" in tool_lower:
            self._parse_nuclei_into_profile(profile, tool_name, output)
        elif "enum4linux" in tool_lower:
            self._parse_enum4linux_into_profile(profile, tool_name, output)
        elif "hydra" in tool_lower:
            self._parse_hydra_into_profile(profile, tool_name, output)
        elif "sqlmap" in tool_lower:
            self._parse_sqlmap_into_profile(profile, tool_name, output)
        else:
            self._parse_generic_into_profile(profile, tool_name, output)

    def _parse_nmap_into_profile(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse nmap output into target profile."""
        self._nmap_parse_ports(profile, tool_name, output)
        self._nmap_detect_os(profile, output)
        self._nmap_find_vulns(profile, tool_name, output)

    def _nmap_parse_ports(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Extract open ports and service info from nmap output."""
        for match in self._RE_PORT.finditer(output):
            port = int(match.group(1))
            proto = match.group(2)
            service = match.group(3)
            version_info = match.group(4).strip()

            svc = profile.get_service(port, proto)
            svc.service = service
            if tool_name not in svc.tools_reported:
                svc.tools_reported.append(tool_name)

            if version_info:
                parts = version_info.split()
                if parts:
                    svc.product = parts[0]
                if len(parts) > 1:
                    svc.version = parts[1]

    @staticmethod
    def _nmap_detect_os(profile: TargetProfile, output: str) -> None:
        """Extract OS detection from nmap output."""
        os_match = re.search(r"OS details?:\s*(.+)", output)
        if os_match:
            profile.os_fingerprint = os_match.group(1).strip()[:100]

    def _nmap_find_vulns(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Extract vulnerability findings from nmap output."""
        for line in output.split("\n"):
            stripped = line.strip()
            if "VULNERABLE" not in stripped.upper():
                continue
            for svc in profile.services.values():
                if tool_name in svc.tools_reported:
                    if stripped not in svc.findings:
                        svc.findings.append(stripped[:200])
                    svc.severity = _max_severity(svc.severity, "high")
                    self._stats["correlations_found"] += 1

    def _parse_nikto_into_profile(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse nikto output into web service profile."""
        port_match = re.search(r"Target Port:\s*(\d+)", output)
        port = int(port_match.group(1)) if port_match else 80
        svc = profile.get_service(port, "tcp")
        svc.service = svc.service or "http"
        if tool_name not in svc.tools_reported:
            svc.tools_reported.append(tool_name)

        for match in self._RE_NIKTO_FINDING.finditer(output):
            finding = match.group(1).strip()[:200]
            if not finding or finding in svc.findings:
                continue
            svc.findings.append(finding)
            svc.severity = _max_severity(svc.severity, self._classify_nikto_severity(finding))

            path_match = re.search(r"(/\S+)", finding)
            if path_match and path_match.group(1) not in svc.paths_discovered:
                svc.paths_discovered.append(path_match.group(1))

    @staticmethod
    def _classify_nikto_severity(finding: str) -> str:
        """Classify a nikto finding's severity based on content keywords."""
        lower = finding.lower()
        if any(k in lower for k in ("sql injection", "rce", "remote code", "command injection")):
            return "critical"
        if any(k in lower for k in (".git", "phpinfo", "backup", "config")):
            return "high"
        if any(k in lower for k in ("x-frame", "x-content", "server header")):
            return "low"
        return "info"

    def _find_web_service(
        self, profile: TargetProfile, tool_name: str, fallback_port: int = 80,
    ) -> ServiceProfile:
        """Find first web service in profile or create one on fallback port."""
        for svc in profile.services.values():
            if svc.service in _WEB_SERVICES:
                if tool_name not in svc.tools_reported:
                    svc.tools_reported.append(tool_name)
                return svc
        svc = profile.get_service(fallback_port, "tcp")
        svc.service = "http"
        if tool_name not in svc.tools_reported:
            svc.tools_reported.append(tool_name)
        return svc

    def _parse_dirscan_into_profile(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse gobuster/ffuf output."""
        web_svc = self._find_web_service(profile, tool_name)

        for line in output.split("\n"):
            self._parse_dirscan_line(line, web_svc)

    def _parse_dirscan_line(self, line: str, web_svc: ServiceProfile) -> None:
        """Parse a single line of gobuster/ffuf output."""
        # Gobuster format: /path (Status: 200) [Size: 1234]
        path_match = re.search(r"(/\S+)\s+.*(?:Status|status):\s*(\d+)", line)
        if path_match:
            path = path_match.group(1)
            status = path_match.group(2)
            if path not in web_svc.paths_discovered:
                web_svc.paths_discovered.append(path)
            if status in ("200", "301", "302"):
                web_svc.findings.append(f"Path found: {path} [{status}]")
            return

        # FFUF format
        ffuf_match = re.search(r"\[Status:\s*(\d+).*URL:\s*(\S+)", line)
        if ffuf_match:
            url = ffuf_match.group(2)
            path = re.sub(r"https?://[^/]+", "", url)
            if path and path not in web_svc.paths_discovered:
                web_svc.paths_discovered.append(path)

    def _parse_nuclei_into_profile(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse nuclei output into profile."""
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("[INF]"):
                continue

            # Nuclei format: [severity] [template-id] [protocol] url
            sev_match = re.search(r"\[(critical|high|medium|low|info)\]", line, re.IGNORECASE)
            severity = sev_match.group(1).lower() if sev_match else "info"

            # Find port from URL or associate with web service
            port_from_url = re.search(r":(\d+)", line)
            port = int(port_from_url.group(1)) if port_from_url else 80
            svc = profile.get_service(port, "tcp")
            svc.service = svc.service or "http"
            if tool_name not in svc.tools_reported:
                svc.tools_reported.append(tool_name)

            if line not in svc.findings:
                svc.findings.append(line[:200])
            svc.severity = _max_severity(svc.severity, severity)
            self._stats["correlations_found"] += 1

    def _parse_enum4linux_into_profile(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse enum4linux output."""
        svc = profile.get_service(445, "tcp")
        svc.service = svc.service or "smb"
        if tool_name not in svc.tools_reported:
            svc.tools_reported.append(tool_name)

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            if any(k in line.lower() for k in ("share", "user", "group", "null session", "password policy")):
                if line not in svc.findings:
                    svc.findings.append(line[:200])
            if "null session" in line.lower() and "success" in line.lower():
                svc.severity = _max_severity(svc.severity, "high")

    def _parse_hydra_into_profile(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse hydra output for credentials."""
        for line in output.split("\n"):
            cred_match = re.search(
                r"\[(\d+)\]\[(\w+)\].*login:\s*(\S+)\s+password:\s*(\S+)",
                line,
            )
            if cred_match:
                port = int(cred_match.group(1))
                svc = profile.get_service(port, "tcp")
                if tool_name not in svc.tools_reported:
                    svc.tools_reported.append(tool_name)
                cred = {
                    "username": cred_match.group(3),
                    "password": cred_match.group(4),
                    "source": tool_name,
                }
                if cred not in svc.credentials:
                    svc.credentials.append(cred)
                svc.severity = _max_severity(svc.severity, "critical")
                svc.findings.append(f"Valid credentials: {cred['username']}:***")

    def _parse_sqlmap_into_profile(
        self, profile: TargetProfile, tool_name: str, output: str,
    ) -> None:
        """Parse sqlmap output."""
        web_svc = self._find_web_service(profile, tool_name)

        injectable = False
        for line in output.split("\n"):
            stripped = line.strip()
            lower = stripped.lower()
            if "injectable" in lower or "parameter" in lower:
                if stripped not in web_svc.findings:
                    web_svc.findings.append(stripped[:200])
                injectable = True
            elif "database:" in lower or "table:" in lower:
                if stripped not in web_svc.findings:
                    web_svc.findings.append(stripped[:200])

        if injectable:
            web_svc.severity = _max_severity(web_svc.severity, "critical")

    def _parse_generic_into_profile(
        self, profile: TargetProfile, _tool_name: str, output: str,
    ) -> None:
        """Generic parser for unknown tools."""
        for line in output.split("\n"):
            line = line.strip()
            if not line or len(line) < 5:
                continue
            if "VULNERABLE" in line.upper() or "CVE-" in line:
                for svc in profile.services.values():
                    if line[:200] not in svc.findings:
                        svc.findings.append(line[:200])
                    break

    def _distribute_cves(
        self, profile: TargetProfile, cves: list[str], tool_name: str,
    ) -> None:
        """Associate extracted CVEs with the most likely service."""
        unique_cves = list(dict.fromkeys(cves))
        for cve in unique_cves:
            self._associate_cve(profile, cve, tool_name)

    def _associate_cve(
        self, profile: TargetProfile, cve: str, tool_name: str,
    ) -> None:
        """Associate a single CVE with the matching service."""
        for svc in profile.services.values():
            if tool_name in svc.tools_reported:
                if cve not in svc.cves:
                    svc.cves.append(cve)
                svc.severity = _max_severity(svc.severity, "high")
                return
        if profile.services:
            first = next(iter(profile.services.values()))
            if cve not in first.cves:
                first.cves.append(cve)
