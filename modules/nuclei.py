# modules/nuclei.py
# DRAKBEN Nuclei Scanner Integration
# Fast vulnerability scanning with Nuclei templates

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def _get_default_port(scheme: Optional[str]) -> int:
    """Get default port for scheme"""
    return 443 if scheme == "https" else 80


class NucleiSeverity(Enum):
    """Nuclei severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class NucleiTemplateType(Enum):
    """Nuclei template categories"""
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
    """Nuclei scan result"""
    template_id: str
    template_name: str
    severity: NucleiSeverity
    host: str
    matched_at: str
    extracted_results: List[str] = field(default_factory=list)
    curl_command: str = ""
    description: str = ""
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
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
            "tags": self.tags
        }


@dataclass
class NucleiScanConfig:
    """Nuclei scan configuration"""
    templates: List[str] = field(default_factory=list)
    template_types: List[NucleiTemplateType] = field(default_factory=list)
    severity: List[NucleiSeverity] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    exclude_tags: List[str] = field(default_factory=list)
    rate_limit: int = 150
    bulk_size: int = 25
    concurrency: int = 25
    timeout: int = 10
    retries: int = 1
    headers: Dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    max_host_errors: int = 30


class NucleiScanner:
    """
    Nuclei Scanner Integration.
    
    Features:
    - Template-based scanning
    - Severity filtering
    - Custom templates support
    - Async execution
    - Result parsing
    """
    
    def __init__(self, nuclei_path: str = "nuclei"):
        """
        Initialize Nuclei scanner.
        
        Args:
            nuclei_path: Path to nuclei binary
        """
        self.nuclei_path = nuclei_path
        self.templates_path: Optional[str] = None
        self.available = self._check_nuclei()
        
        if self.available:
            logger.info("Nuclei scanner initialized")
        else:
            logger.warning("Nuclei not found - scanner disabled")
    
    def _check_nuclei(self) -> bool:
        """Check if nuclei is available"""
        return shutil.which(self.nuclei_path) is not None
    
    def _parse_severity(self, severity_str: str) -> NucleiSeverity:
        """Parse severity string to enum"""
        severity_map = {
            "info": NucleiSeverity.INFO,
            "low": NucleiSeverity.LOW,
            "medium": NucleiSeverity.MEDIUM,
            "high": NucleiSeverity.HIGH,
            "critical": NucleiSeverity.CRITICAL
        }
        return severity_map.get(severity_str.lower(), NucleiSeverity.UNKNOWN)
    
    def _parse_result(self, line: str) -> Optional[NucleiResult]:
        """Parse nuclei JSON output line"""
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
                tags=info.get("tags", [])
            )
        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.error(f"Error parsing nuclei result: {e}")
            return None
    
    async def scan(
        self,
        targets: List[str],
        config: Optional[NucleiScanConfig] = None,
        output_file: Optional[str] = None
    ) -> List[NucleiResult]:
        """
        Run Nuclei scan.
        
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
            results = await self._execute_nuclei_scan(cmd, output_file)
            return results
        finally:
            _cleanup_nuclei_temp_file(targets_file)

async def _create_nuclei_targets_file(targets: List[str]) -> Optional[str]:
    """Create temporary file with targets"""
    import tempfile
    def _write_temp_file():
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(targets))
            return f.name

    try:
        return await asyncio.get_event_loop().run_in_executor(None, _write_temp_file)
    except Exception as e:
        logger.error(f"Failed to create temp targets file: {e}")
        return None

def _cleanup_nuclei_temp_file(targets_file: str) -> None:
    """Clean up temporary targets file"""
    import os
    try:
        os.unlink(targets_file)
    except (OSError, FileNotFoundError):
        pass
    
    async def scan_cves(
        self,
        targets: List[str],
        cve_ids: Optional[List[str]] = None
    ) -> List[NucleiResult]:
        """
        Scan for specific CVEs.
        
        Args:
            targets: List of targets
            cve_ids: Optional list of specific CVE IDs
            
        Returns:
            List of NucleiResult objects
        """
        config = NucleiScanConfig(
            template_types=[NucleiTemplateType.CVE]
        )
        
        if cve_ids:
            config.tags = cve_ids
        
        return await self.scan(targets, config)
    
    async def scan_technologies(
        self,
        targets: List[str]
    ) -> List[NucleiResult]:
        """
        Detect technologies on targets.
        
        Args:
            targets: List of targets
            
        Returns:
            List of NucleiResult objects
        """
        config = NucleiScanConfig(
            template_types=[NucleiTemplateType.TECHNOLOGIES]
        )
        
        return await self.scan(targets, config)
    
    async def scan_misconfigurations(
        self,
        targets: List[str]
    ) -> List[NucleiResult]:
        """
        Scan for misconfigurations.
        
        Args:
            targets: List of targets
            
        Returns:
            List of NucleiResult objects
        """
        config = NucleiScanConfig(
            template_types=[NucleiTemplateType.MISCONFIGURATIONS]
        )
        
        return await self.scan(targets, config)
    
    async def scan_default_logins(
        self,
        targets: List[str]
    ) -> List[NucleiResult]:
        """
        Scan for default credentials.
        
        Args:
            targets: List of targets
            
        Returns:
            List of NucleiResult objects
        """
        config = NucleiScanConfig(
            template_types=[NucleiTemplateType.DEFAULT_LOGINS]
        )
        
        return await self.scan(targets, config)
    
    async def scan_critical_high(
        self,
        targets: List[str]
    ) -> List[NucleiResult]:
        """
        Scan for critical and high severity issues only.
        
        Args:
            targets: List of targets
            
        Returns:
            List of NucleiResult objects
        """
        config = NucleiScanConfig(
            severity=[NucleiSeverity.CRITICAL, NucleiSeverity.HIGH]
        )
        
        return await self.scan(targets, config)
    
    async def update_templates(self) -> bool:
        """
        Update Nuclei templates.
        
        Returns:
            True if successful
        """
        if not self.available:
            return False
        
        try:
            process = await asyncio.create_subprocess_exec(
                self.nuclei_path,
                "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.wait()
            
            if process.returncode == 0:
                logger.info("Nuclei templates updated")
                return True
            else:
                logger.error("Failed to update Nuclei templates")
                return False
                
        except Exception as e:
            logger.error(f"Template update error: {e}")
            return False
    
    def get_template_count(self) -> int:
        """Get number of available templates"""
        if not self.available:
            return 0
        
        try:
            result = subprocess.run(
                [self.nuclei_path, "-tl"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Count lines in output
            return len(result.stdout.strip().split('\n'))
            
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            logger.debug(f"Error counting templates: {e}")
            return 0


def nuclei_results_to_findings(results: List[NucleiResult]) -> List[Dict[str, Any]]:
    """
    Convert Nuclei results to finding dictionaries for report generation.
    
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
            "description": result.description or f"Detected by template: {result.template_id}",
            "affected_asset": result.host,
            "evidence": result.matched_at,
            "references": result.reference,
            "tags": result.tags
        }
        
        # Add CVE if in template ID
        if result.template_id.upper().startswith("CVE-"):
            finding["cve_id"] = result.template_id.upper()
        
        findings.append(finding)
    
    return findings


# State integration
async def nuclei_scan_state_target(
    state: "AgentState",
    scanner: Optional[NucleiScanner] = None,
    severity_filter: Optional[List[NucleiSeverity]] = None
) -> List[NucleiResult]:
    """
    Run Nuclei scan on state target.
    
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
    if not target.startswith(('http://', 'https://')):
        targets = [f"http://{target}", f"https://{target}"]
    else:
        targets = [target]
    
    results = await scanner.scan(targets, config)
    
    # Update state with vulnerabilities
    from core.state import VulnerabilityInfo
    
    for result in results:
        if result.severity in [NucleiSeverity.CRITICAL, NucleiSeverity.HIGH, NucleiSeverity.MEDIUM]:
            # Extract port and service from result URL
            parsed_url = urlparse(result.url) if hasattr(result, 'url') and result.url else urlparse(state.target)
            port = parsed_url.port or _get_default_port(parsed_url.scheme)
            service = parsed_url.scheme or "http"
            vuln = VulnerabilityInfo(
                vuln_id=result.template_id,
                service=service,
                port=port,
                severity=result.severity.value,
                exploitable=True
            )
            state.add_vulnerability(vuln)
    
    return results
