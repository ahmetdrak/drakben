# modules/nuclei.py
# DRAKBEN Nuclei Scanner Integration
# Fast vulnerability scanning with Nuclei templates

import asyncio
import contextlib
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.state import AgentState

logger = logging.getLogger(__name__)


def _get_default_port(scheme: str | None) -> int:
    """Get default port for scheme."""
    return 443 if scheme == "https" else 80


class NucleiSeverity(Enum):
    """Nuclei severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class NucleiTemplateType(Enum):
    """Nuclei template categories."""

    CVE = "cves"
    VULNERABILITIES = "vulnerabilities"
    MISCONFIGURATIONS = "misconfigurations"
    EXPOSURES = "exposures"
    TECHNOLOGIES = "technologies"
    WORKFLOWS = "workflows"
    DEFAULT_LOGINS = "default-logins"
    TAKEOVERS = "takeovers"
    FILE = "file"
    DNS = "dns"
    HEADLESS = "headless"


@dataclass
class NucleiResult:
    """Nuclei scan result."""

    template_id: str
    template_name: str
    severity: NucleiSeverity
    host: str
    matched_at: str
    extracted_results: list[str] = field(default_factory=list)
    curl_command: str = ""
    description: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity.value,
            "host": self.host,
            "matched_at": self.matched_at,
            "extracted_results": self.extracted_results,
            "curl_command": self.curl_command,
            "description": self.description,
            "reference": self.reference,
            "tags": self.tags,
        }


@dataclass
class NucleiScanConfig:
    """Nuclei scan configuration."""

    templates: list[str] = field(default_factory=list)
    template_types: list[NucleiTemplateType] = field(default_factory=list)
    severity: list[NucleiSeverity] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    exclude_tags: list[str] = field(default_factory=list)
    rate_limit: int = 150
    bulk_size: int = 25
    concurrency: int = 25
    timeout: int = 10
    retries: int = 1
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    max_host_errors: int = 30


class NucleiScanner:
    """Nuclei Scanner Integration.

    Features:
    - Template-based scanning
    - Severity filtering
    - Custom templates support
    - Async execution
    - Result parsing
    """

    def __init__(self, nuclei_path: str = "nuclei") -> None:
        """Initialize Nuclei scanner.

        Args:
            nuclei_path: Path to nuclei binary

        """
        self.nuclei_path = nuclei_path
        self.templates_path: str | None = None
        self.available = self._check_nuclei()

        if self.available:
            logger.info("Nuclei scanner initialized")
        else:
            logger.warning("Nuclei not found - scanner disabled")

    def _check_nuclei(self) -> bool:
        """Check if nuclei is available."""
        return shutil.which(self.nuclei_path) is not None

    def _parse_severity(self, severity_str: str) -> NucleiSeverity:
        """Parse severity string to enum."""
        severity_map = {
            "info": NucleiSeverity.INFO,
            "low": NucleiSeverity.LOW,
            "medium": NucleiSeverity.MEDIUM,
            "high": NucleiSeverity.HIGH,
            "critical": NucleiSeverity.CRITICAL,
        }
        return severity_map.get(severity_str.lower(), NucleiSeverity.UNKNOWN)

    def _build_nuclei_command(
        self,
        targets_file: str,
        config: NucleiScanConfig,
        output_file: str | None = None,
    ) -> list[str]:
        """Build nuclei command line."""
        cmd = [self.nuclei_path, "-list", targets_file, "-json"]

        if config.templates:
            for t in config.templates:
                cmd.extend(["-t", t])

        if config.severity:
            cmd.extend(["-severity", ",".join(s.value for s in config.severity)])

        if output_file:
            cmd.extend(["-o", output_file])

        return cmd

    async def _execute_nuclei_scan(self, cmd: list[str]) -> list[NucleiResult]:
        """Execute nuclei scan and parse output."""
        results = []
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            # Additional error logging from stderr
            if stderr and b"error" in stderr.lower():
                logger.debug("Nuclei stderr: %s", stderr.decode(errors="replace"))

            for line in stdout.decode(errors="replace").splitlines():
                res = self._parse_result(line)
                if res:
                    results.append(res)

        except asyncio.CancelledError:
            logger.warning("Nuclei scan cancelled, killing subprocess...")
            if process and process.returncode is None:
                try:
                    process.terminate()
                    # Give it a tiny bit to terminate gracefully
                    await asyncio.sleep(0.1)
                    if process.returncode is None:
                        process.kill()
                except ProcessLookupError:
                    pass
            raise
        except Exception as e:
            logger.exception("Nuclei scan failed: %s", e)
            if process and process.returncode is None:
                with contextlib.suppress(Exception):
                    process.kill()
        finally:
            # Ensure process is definitely dead
            if process and process.returncode is None:
                with contextlib.suppress(Exception):
                    process.kill()

        return results

    def _parse_result(self, line: str) -> NucleiResult | None:
        """Parse nuclei JSON output line."""
        try:
            data = json.loads(line)
            info = data.get("info", {})
            return NucleiResult(
                template_id=data.get("template-id", ""),
                template_name=info.get("name", ""),
                severity=self._parse_severity(info.get("severity", "unknown")),
                host=data.get("host", ""),
                matched_at=data.get("matched-at", data.get("host", "")),
                extracted_results=data.get("extracted-results", []),
                curl_command=data.get("curl-command", ""),
                description=info.get("description", ""),
                reference=info.get("reference", []),
                tags=info.get("tags", []),
            )
        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.exception("Error parsing nuclei result: %s", e)
            return None

    async def scan(
        self,
        targets: list[str],
        config: NucleiScanConfig | None = None,
        output_file: str | None = None,
    ) -> list[NucleiResult]:
        """Run Nuclei scan.

        Args:
            targets: List of target URLs/hosts
            config: Scan configuration
            output_file: Optional output file path

        Returns:
            List of NucleiResult objects

        """
        if not self.available:
            logger.error("Nuclei not available")
            return []

        config = config or NucleiScanConfig()
        targets_file = await _create_nuclei_targets_file(targets)
        if not targets_file:
            return []

        try:
            cmd = self._build_nuclei_command(targets_file, config, output_file)
            return await self._execute_nuclei_scan(cmd)
        finally:
            _cleanup_nuclei_temp_file(targets_file)


async def _create_nuclei_targets_file(targets: list[str]) -> str | None:
    """Create temporary file with targets."""

    def _write_temp_file() -> Any:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            return f.name

    try:
        return await asyncio.get_event_loop().run_in_executor(None, _write_temp_file)
    except Exception as e:
        logger.exception("Failed to create temp targets file: %s", e)
        return None


def _cleanup_nuclei_temp_file(targets_file: str) -> None:
    """Clean up temporary targets file."""
    with contextlib.suppress(OSError):
        os.unlink(targets_file)


def nuclei_results_to_findings(results: list[NucleiResult]) -> list[dict[str, Any]]:
    """Convert Nuclei results to finding dictionaries for report generation.

    Args:
        results: List of NucleiResult objects

    Returns:
        List of finding dictionaries

    """
    findings = []

    for result in results:
        finding = {
            "title": result.template_name or result.template_id,
            "severity": result.severity.value,
            "description": result.description
            or f"Detected by template: {result.template_id}",
            "affected_asset": result.host,
            "evidence": result.matched_at,
            "references": result.reference,
            "tags": result.tags,
        }

        # Add CVE if in template ID
        if result.template_id.upper().startswith("CVE-"):
            finding["cve_id"] = result.template_id.upper()

        findings.append(finding)

    return findings


# State integration
async def nuclei_scan_state_target(
    state: "AgentState",
    scanner: NucleiScanner | None = None,
    severity_filter: list[NucleiSeverity] | None = None,
) -> list[NucleiResult]:
    """Run Nuclei scan on state target.

    Args:
        state: AgentState instance
        scanner: Optional NucleiScanner instance
        severity_filter: Optional severity filter

    Returns:
        List of NucleiResult objects

    """
    if not state.target:
        logger.warning("No target set in state")
        return []

    scanner = scanner or NucleiScanner()

    if not scanner.available:
        logger.warning("Nuclei not available")
        return []

    config = NucleiScanConfig()
    if severity_filter:
        config.severity = severity_filter

    # Add http/https if not present
    target = state.target
    if not target.startswith(("http://", "https://")):
        targets = [f"http://{target}", f"https://{target}"]
    else:
        targets = [target]

    results = await scanner.scan(targets, config)

    # Update state with vulnerabilities
    from core.state import VulnerabilityInfo

    for result in results:
        if result.severity in [
            NucleiSeverity.CRITICAL,
            NucleiSeverity.HIGH,
            NucleiSeverity.MEDIUM,
        ]:
            # Extract port and service from result URL
            parsed_url = (
                urlparse(result.url)
                if hasattr(result, "url") and result.url
                else urlparse(state.target)
            )
            port = parsed_url.port or _get_default_port(parsed_url.scheme)
            service = parsed_url.scheme or "http"
            vuln = VulnerabilityInfo(
                vuln_id=result.template_id,
                service=service,
                port=port,
                severity=result.severity.value,
                exploitable=True,
            )
            state.add_vulnerability(vuln)

    return results
