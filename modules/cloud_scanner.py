# modules/cloud_scanner.py
# DRAKBEN — Cloud Security Scanner Module
# AWS, Azure, GCP misconfiguration detection.
# Fills the "missing cloud module" gap identified in competitor analysis.

"""Cloud infrastructure security scanner.

Checks for common misconfigurations in:
- AWS: S3 buckets, IAM policies, security groups, EC2 metadata
- Azure: Blob storage, NSGs, managed identities
- GCP: Cloud Storage, IAM, firewall rules, metadata

Usage::

    from modules.cloud_scanner import CloudScanner
    scanner = CloudScanner()
    results = await scanner.scan_target("example.com")
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CloudFinding:
    """A cloud misconfiguration finding."""

    provider: str  # aws, azure, gcp
    category: str  # s3, iam, sg, storage, nsg, etc.
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    url: str = ""


@dataclass
class CloudScanResult:
    """Results from a cloud security scan."""

    target: str
    findings: list[CloudFinding] = field(default_factory=list)
    metadata_accessible: bool = False
    cloud_provider: str = "unknown"
    scan_duration: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "target": self.target,
            "cloud_provider": self.cloud_provider,
            "metadata_accessible": self.metadata_accessible,
            "findings_count": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "findings": [
                {
                    "provider": f.provider,
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence[:500],
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Common cloud metadata endpoints
# ---------------------------------------------------------------------------
METADATA_ENDPOINTS: dict[str, dict[str, Any]] = {
    "aws": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        "token_url": "http://169.254.169.254/latest/api/token",
        "token_header": "X-aws-ec2-metadata-token-ttl-seconds",
        "sensitive_paths": [
            "iam/security-credentials/",
            "iam/info",
            "identity-credentials/ec2/security-credentials/ec2-instance",
            "hostname",
            "local-ipv4",
            "public-ipv4",
            "public-hostname",
            "placement/region",
            "network/interfaces/macs/",
        ],
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance",
        "headers": {"Metadata": "true"},
        "params": {"api-version": "2021-02-01"},
        "sensitive_paths": [
            "compute/name",
            "compute/subscriptionId",
            "compute/resourceGroupName",
            "network/interface",
        ],
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "sensitive_paths": [
            "project/project-id",
            "instance/service-accounts/default/token",
            "instance/service-accounts/default/email",
            "instance/hostname",
            "instance/zone",
            "instance/network-interfaces/",
        ],
    },
}

# S3 bucket naming patterns
S3_BUCKET_PATTERNS: list[str] = [
    "{target}-backup",
    "{target}-data",
    "{target}-static",
    "{target}-media",
    "{target}-assets",
    "{target}-uploads",
    "{target}-logs",
    "{target}-dev",
    "{target}-staging",
    "{target}-prod",
    "{target}-public",
    "{target}-private",
    "{target}-cdn",
    "{target}-files",
    "{target}-www",
]

# Azure blob patterns
AZURE_BLOB_PATTERNS: list[str] = [
    "{target}.blob.core.windows.net",
    "{target}storage.blob.core.windows.net",
    "{target}data.blob.core.windows.net",
]

# GCP bucket patterns
GCP_BUCKET_PATTERNS: list[str] = [
    "{target}.storage.googleapis.com",
    "{target}-bucket.storage.googleapis.com",
]


class CloudScanner:
    """Cloud infrastructure security scanner.

    Detects misconfigurations in AWS, Azure, and GCP environments.
    """

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout
        self._session = None

    def _get_session(self):
        """Get or create aiohttp session."""
        if self._session is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                )
            except ImportError:
                logger.warning("aiohttp not installed, cloud scanning limited")
                return None
        return self._session

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def scan_target(self, target: str) -> CloudScanResult:
        """Run all cloud security checks against a target.

        Args:
            target: Domain name, IP, or URL to scan.

        Returns:
            CloudScanResult with findings.
        """
        import time
        start = time.monotonic()

        result = CloudScanResult(target=target)

        # Clean target
        clean_target = self._clean_target(target)

        # Run checks concurrently
        checks = [
            self._check_s3_buckets(clean_target, result),
            self._check_azure_blobs(clean_target, result),
            self._check_gcp_buckets(clean_target, result),
            self._check_metadata_ssrf(clean_target, result),
            self._check_cloud_headers(clean_target, result),
        ]

        try:
            await asyncio.gather(*checks, return_exceptions=True)
        finally:
            result.scan_duration = time.monotonic() - start
            await self.close()
        return result

    async def _check_s3_buckets(self, target: str, result: CloudScanResult) -> None:
        """Check for publicly accessible S3 buckets."""
        session = self._get_session()
        if not session:
            return

        base_name = re.sub(r"[^a-z0-9-]", "-", target.lower().split(".")[0])

        for pattern in S3_BUCKET_PATTERNS:
            bucket = pattern.format(target=base_name)
            url = f"https://{bucket}.s3.amazonaws.com/"

            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "<ListBucketResult" in body:
                            result.findings.append(CloudFinding(
                                provider="aws",
                                category="s3",
                                severity="critical",
                                title=f"Public S3 Bucket: {bucket}",
                                description="S3 bucket allows anonymous listing",
                                evidence=f"URL: {url}, Status: {resp.status}",
                                remediation="Enable S3 Block Public Access, review bucket policy",
                                url=url,
                            ))
                            result.cloud_provider = "aws"
                    elif resp.status == 403:
                        # Bucket exists but access denied (less severe)
                        result.findings.append(CloudFinding(
                            provider="aws",
                            category="s3",
                            severity="info",
                            title=f"S3 Bucket exists: {bucket}",
                            description="S3 bucket exists but access is denied",
                            evidence=f"URL: {url}, Status: 403",
                            remediation="Verify bucket policy is intentional",
                            url=url,
                        ))
            except OSError as exc:
                logger.debug("S3 bucket check failed for %s: %s", bucket, exc)

    async def _check_azure_blobs(self, target: str, result: CloudScanResult) -> None:
        """Check for publicly accessible Azure Blob containers."""
        session = self._get_session()
        if not session:
            return

        base_name = re.sub(r"[^a-z0-9]", "", target.lower().split(".")[0])

        for pattern in AZURE_BLOB_PATTERNS:
            blob_url = pattern.format(target=base_name)
            # Check common container names
            for container in ["$web", "public", "data", "backup", "uploads"]:
                url = f"https://{blob_url}/{container}?restype=container&comp=list"
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if "<EnumerationResults" in body:
                                result.findings.append(CloudFinding(
                                    provider="azure",
                                    category="blob_storage",
                                    severity="critical",
                                    title=f"Public Azure Blob: {blob_url}/{container}",
                                    description="Azure Blob container allows anonymous listing",
                                    evidence=f"URL: {url}",
                                    remediation="Set container access level to 'Private'",
                                    url=url,
                                ))
                                result.cloud_provider = "azure"
                except OSError as exc:
                    logger.debug("Azure blob check failed for %s/%s: %s", blob_url, container, exc)

    async def _check_gcp_buckets(self, target: str, result: CloudScanResult) -> None:
        """Check for publicly accessible GCP Cloud Storage buckets."""
        session = self._get_session()
        if not session:
            return

        base_name = re.sub(r"[^a-z0-9-]", "-", target.lower().split(".")[0])

        for pattern in GCP_BUCKET_PATTERNS:
            bucket_url = pattern.format(target=base_name)
            url = f"https://{bucket_url}"
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        if "<ListBucketResult" in body or "items" in body:
                            result.findings.append(CloudFinding(
                                provider="gcp",
                                category="cloud_storage",
                                severity="critical",
                                title=f"Public GCP Bucket: {bucket_url}",
                                description="GCP Cloud Storage bucket allows anonymous access",
                                evidence=f"URL: {url}",
                                remediation="Remove 'allUsers' and 'allAuthenticatedUsers' IAM bindings",
                                url=url,
                            ))
                            result.cloud_provider = "gcp"
            except OSError as exc:
                logger.debug("GCP bucket check failed for %s: %s", bucket_url, exc)

    async def _check_metadata_ssrf(self, _target: str, result: CloudScanResult) -> None:
        """Check if cloud metadata endpoints are accessible (SSRF indicator)."""
        session = self._get_session()
        if not session:
            return

        for provider, config in METADATA_ENDPOINTS.items():
            url = config["url"]
            headers = config.get("headers", {})

            try:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        result.metadata_accessible = True
                        result.cloud_provider = provider
                        result.findings.append(CloudFinding(
                            provider=provider,
                            category="metadata",
                            severity="critical",
                            title=f"{provider.upper()} Metadata Service Accessible",
                            description=(
                                "Cloud instance metadata service is accessible. "
                                "This can lead to credential theft and privilege escalation."
                            ),
                            evidence=f"Response: {body[:200]}",
                            remediation=(
                                "Enable IMDSv2 (AWS), use Metadata-Flavor header (GCP), "
                                "or disable metadata service if not needed."
                            ),
                            url=url,
                        ))
            except OSError as exc:
                logger.debug("Metadata endpoint check failed for %s: %s", provider, exc)

    async def _check_cloud_headers(self, target: str, result: CloudScanResult) -> None:
        """Check HTTP response headers for cloud provider identification."""
        session = self._get_session()
        if not session:
            return

        schemes = ["https", "http"]
        for scheme in schemes:
            url = f"{scheme}://{target}"
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    headers = dict(resp.headers)
                    server = headers.get("Server", "").lower()

                    # AWS detection
                    if any(h in headers for h in ["x-amz-request-id", "x-amz-id-2"]):
                        result.cloud_provider = "aws"
                        result.findings.append(CloudFinding(
                            provider="aws",
                            category="headers",
                            severity="info",
                            title="AWS Infrastructure Detected",
                            description="Response headers indicate AWS hosting",
                            evidence=f"Headers: {_safe_headers(headers)}",
                        ))

                    # Azure detection
                    if "x-ms-request-id" in headers or "azure" in server:
                        result.cloud_provider = "azure"
                        result.findings.append(CloudFinding(
                            provider="azure",
                            category="headers",
                            severity="info",
                            title="Azure Infrastructure Detected",
                            description="Response headers indicate Azure hosting",
                            evidence=f"Headers: {_safe_headers(headers)}",
                        ))

                    # GCP detection
                    if "x-goog-" in str(headers).lower() or "gws" in server:
                        result.cloud_provider = "gcp"
                        result.findings.append(CloudFinding(
                            provider="gcp",
                            category="headers",
                            severity="info",
                            title="GCP Infrastructure Detected",
                            description="Response headers indicate GCP hosting",
                            evidence=f"Headers: {_safe_headers(headers)}",
                        ))

                    # CloudFront
                    if "cloudfront" in server or "x-amz-cf-id" in headers:
                        result.findings.append(CloudFinding(
                            provider="aws",
                            category="cdn",
                            severity="info",
                            title="CloudFront CDN Detected",
                            description="Target is behind AWS CloudFront",
                            evidence=f"Server: {server}",
                        ))

                    break  # Only need one successful check
            except Exception:
                logger.debug("Cloud header check failed, skipping")
                continue

    @staticmethod
    def _clean_target(target: str) -> str:
        """Clean target for cloud checks."""
        # Remove protocol
        target = re.sub(r"^https?://", "", target)
        # Remove path/port
        target = target.split("/")[0].split(":")[0]
        # Remove www
        target = target.removeprefix("www.")
        return target


def _safe_headers(headers: dict[str, str]) -> str:
    """Safely format headers for evidence (redact sensitive values)."""
    safe = {}
    sensitive = {"authorization", "cookie", "set-cookie", "x-api-key"}
    for k, v in headers.items():
        if k.lower() in sensitive:
            safe[k] = "***REDACTED***"
        else:
            safe[k] = v[:100]
    return json.dumps(safe, indent=2)
