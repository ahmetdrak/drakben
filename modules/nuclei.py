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
from typing import Any

logger = logging.getLogger(__name__)


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

    async def _kill_process_safe(self, process: asyncio.subprocess.Process | None) -> None:
        """Safely kill a subprocess."""
        if not process or process.returncode is not None:
            return
        with contextlib.suppress(Exception):
            process.terminate()
            await asyncio.sleep(0.1)
            if process.returncode is None:
                process.kill()

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

            if stderr and b"error" in stderr.lower():
                logger.debug("Nuclei stderr: %s", stderr.decode(errors="replace"))

            for line in stdout.decode(errors="replace").splitlines():
                res = self._parse_result(line)
                if res:
                    results.append(res)

        except asyncio.CancelledError:
            logger.warning("Nuclei scan cancelled, killing subprocess...")
            await self._kill_process_safe(process)
            raise
        except Exception as e:
            logger.exception("Nuclei scan failed: %s", e)
            await self._kill_process_safe(process)
        finally:
            await self._kill_process_safe(process)

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
        return await asyncio.get_running_loop().run_in_executor(None, _write_temp_file)
    except Exception as e:
        logger.exception("Failed to create temp targets file: %s", e)
        return None


def _cleanup_nuclei_temp_file(targets_file: str) -> None:
    """Clean up temporary targets file."""
    with contextlib.suppress(OSError):
        os.unlink(targets_file)


