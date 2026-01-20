"""
DRAKBEN - Cloud Security Scanner
AWS/Azure/GCP enumeration, S3/IAM scanning, metadata service exploitation
"""

import asyncio
import aiohttp
import json
import re
import socket
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any, Tuple
from enum import Enum
from datetime import datetime
from abc import ABC, abstractmethod


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALIBABA = "alibaba"
    DIGITAL_OCEAN = "digital_ocean"
    UNKNOWN = "unknown"


class ResourceType(Enum):
    """Cloud resource types"""
    COMPUTE = "compute"
    STORAGE = "storage"
    DATABASE = "database"
    NETWORK = "network"
    IAM = "iam"
    SECRETS = "secrets"
    CONTAINER = "container"
    SERVERLESS = "serverless"


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CloudCredential:
    """Cloud credentials"""
    provider: CloudProvider
    access_key: str = ""
    secret_key: str = ""
    session_token: str = ""
    region: str = ""
    account_id: str = ""
    role_arn: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "provider": self.provider.value,
            "access_key": self.access_key[:8] + "..." if self.access_key else "",
            "region": self.region,
            "account_id": self.account_id,
            "has_session_token": bool(self.session_token)
        }


@dataclass
class CloudResource:
    """Cloud resource"""
    provider: CloudProvider
    resource_type: ResourceType
    resource_id: str
    name: str
    region: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "provider": self.provider.value,
            "type": self.resource_type.value,
            "id": self.resource_id,
            "name": self.name,
            "region": self.region,
            "tags": self.tags,
            "metadata": self.metadata
        }


@dataclass
class SecurityFinding:
    """Security finding"""
    provider: CloudProvider
    resource: str
    finding_type: str
    severity: Severity
    title: str
    description: str
    remediation: str
    evidence: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "provider": self.provider.value,
            "resource": self.resource,
            "type": self.finding_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "timestamp": self.timestamp
        }


class MetadataService:
    """Cloud instance metadata service exploitation"""
    
    # Metadata service endpoints
    METADATA_ENDPOINTS = {
        CloudProvider.AWS: {
            "url": "http://169.254.169.254",
            "token_url": "http://169.254.169.254/latest/api/token",
            "paths": {
                "instance_id": "/latest/meta-data/instance-id",
                "hostname": "/latest/meta-data/hostname",
                "public_ip": "/latest/meta-data/public-ipv4",
                "private_ip": "/latest/meta-data/local-ipv4",
                "region": "/latest/meta-data/placement/region",
                "security_groups": "/latest/meta-data/security-groups",
                "iam_role": "/latest/meta-data/iam/security-credentials/",
                "user_data": "/latest/user-data"
            }
        },
        CloudProvider.AZURE: {
            "url": "http://169.254.169.254",
            "paths": {
                "instance": "/metadata/instance?api-version=2021-02-01",
                "identity": "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            }
        },
        CloudProvider.GCP: {
            "url": "http://metadata.google.internal",
            "paths": {
                "project_id": "/computeMetadata/v1/project/project-id",
                "zone": "/computeMetadata/v1/instance/zone",
                "hostname": "/computeMetadata/v1/instance/hostname",
                "service_accounts": "/computeMetadata/v1/instance/service-accounts/",
                "access_token": "/computeMetadata/v1/instance/service-accounts/default/token"
            }
        }
    }
    
    async def detect_cloud_provider(self) -> CloudProvider:
        """Detect which cloud provider we're running on"""
        async with aiohttp.ClientSession() as session:
            # Try AWS
            try:
                async with session.get(
                    "http://169.254.169.254/latest/meta-data/",
                    timeout=aiohttp.ClientTimeout(total=2)
                ) as resp:
                    if resp.status == 200:
                        return CloudProvider.AWS
            except:
                pass
            
            # Try Azure
            try:
                async with session.get(
                    "http://169.254.169.254/metadata/instance",
                    headers={"Metadata": "true"},
                    timeout=aiohttp.ClientTimeout(total=2)
                ) as resp:
                    if resp.status == 200:
                        return CloudProvider.AZURE
            except:
                pass
            
            # Try GCP
            try:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/",
                    headers={"Metadata-Flavor": "Google"},
                    timeout=aiohttp.ClientTimeout(total=2)
                ) as resp:
                    if resp.status == 200:
                        return CloudProvider.GCP
            except:
                pass
        
        return CloudProvider.UNKNOWN
    
    async def get_aws_credentials(self) -> Optional[CloudCredential]:
        """Retrieve AWS credentials from metadata service"""
        try:
            async with aiohttp.ClientSession() as session:
                # Get IMDSv2 token
                try:
                    async with session.put(
                        "http://169.254.169.254/latest/api/token",
                        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        token = await resp.text()
                        headers = {"X-aws-ec2-metadata-token": token}
                except:
                    headers = {}
                
                # Get IAM role name
                async with session.get(
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    role_name = await resp.text()
                
                if not role_name:
                    return None
                
                # Get credentials
                async with session.get(
                    f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    creds = await resp.json()
                
                return CloudCredential(
                    provider=CloudProvider.AWS,
                    access_key=creds.get("AccessKeyId", ""),
                    secret_key=creds.get("SecretAccessKey", ""),
                    session_token=creds.get("Token", ""),
                    role_arn=role_name
                )
                
        except Exception:
            return None
    
    async def get_azure_token(self) -> Optional[Dict]:
        """Get Azure managed identity token"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://169.254.169.254/metadata/identity/oauth2/token",
                    params={
                        "api-version": "2018-02-01",
                        "resource": "https://management.azure.com/"
                    },
                    headers={"Metadata": "true"},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return await resp.json()
        except:
            return None
    
    async def get_gcp_token(self) -> Optional[Dict]:
        """Get GCP service account token"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    headers={"Metadata-Flavor": "Google"},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return await resp.json()
        except:
            return None
    
    async def get_all_metadata(self, provider: CloudProvider) -> Dict:
        """Get all available metadata"""
        metadata = {}
        
        if provider not in self.METADATA_ENDPOINTS:
            return metadata
        
        endpoint_info = self.METADATA_ENDPOINTS[provider]
        base_url = endpoint_info["url"]
        
        # Set headers based on provider
        headers = {}
        if provider == CloudProvider.GCP:
            headers["Metadata-Flavor"] = "Google"
        elif provider == CloudProvider.AZURE:
            headers["Metadata"] = "true"
        
        async with aiohttp.ClientSession() as session:
            for name, path in endpoint_info.get("paths", {}).items():
                try:
                    async with session.get(
                        f"{base_url}{path}",
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            content_type = resp.headers.get("Content-Type", "")
                            if "json" in content_type:
                                metadata[name] = await resp.json()
                            else:
                                metadata[name] = await resp.text()
                except:
                    pass
        
        return metadata


class S3Scanner:
    """AWS S3 bucket scanner"""
    
    # Common bucket misconfigurations
    BUCKET_CHECKS = [
        "public_read",
        "public_write",
        "public_read_acp",
        "public_write_acp",
        "authenticated_read",
        "versioning_disabled",
        "logging_disabled",
        "encryption_disabled",
        "mfa_delete_disabled"
    ]
    
    def __init__(self, credentials: Optional[CloudCredential] = None):
        self.credentials = credentials
    
    async def check_bucket_exists(self, bucket_name: str) -> bool:
        """Check if S3 bucket exists"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    f"https://{bucket_name}.s3.amazonaws.com",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status in [200, 403]
        except:
            return False
    
    async def check_public_access(self, bucket_name: str) -> Dict:
        """Check bucket for public access"""
        results = {
            "bucket": bucket_name,
            "public_read": False,
            "public_list": False,
            "public_write": False,
            "findings": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                # Check if we can list bucket contents
                async with session.get(
                    f"https://{bucket_name}.s3.amazonaws.com",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if "<Contents>" in content or "<Key>" in content:
                            results["public_list"] = True
                            results["findings"].append(SecurityFinding(
                                provider=CloudProvider.AWS,
                                resource=f"s3://{bucket_name}",
                                finding_type="public_bucket",
                                severity=Severity.CRITICAL,
                                title="S3 Bucket Publicly Listable",
                                description=f"Bucket {bucket_name} allows public listing",
                                remediation="Enable S3 Block Public Access settings"
                            ))
                
                # Check if we can read objects
                async with session.get(
                    f"https://{bucket_name}.s3.amazonaws.com/test",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status != 403:
                        results["public_read"] = True
                
                # Check if we can write (PUT)
                try:
                    async with session.put(
                        f"https://{bucket_name}.s3.amazonaws.com/drakben_test_file.txt",
                        data=b"test",
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            results["public_write"] = True
                            results["findings"].append(SecurityFinding(
                                provider=CloudProvider.AWS,
                                resource=f"s3://{bucket_name}",
                                finding_type="public_write",
                                severity=Severity.CRITICAL,
                                title="S3 Bucket Publicly Writable",
                                description=f"Bucket {bucket_name} allows public write access",
                                remediation="Remove public write permissions immediately"
                            ))
                except:
                    pass
                    
        except Exception:
            pass
        
        return results
    
    async def enumerate_bucket_objects(self, bucket_name: str, 
                                       max_objects: int = 100) -> List[Dict]:
        """Enumerate objects in a public bucket"""
        objects = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{bucket_name}.s3.amazonaws.com",
                    params={"max-keys": max_objects},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        
                        # Parse XML response
                        key_pattern = r"<Key>([^<]+)</Key>"
                        size_pattern = r"<Size>(\d+)</Size>"
                        
                        keys = re.findall(key_pattern, content)
                        sizes = re.findall(size_pattern, content)
                        
                        for i, key in enumerate(keys):
                            obj = {
                                "key": key,
                                "size": int(sizes[i]) if i < len(sizes) else 0,
                                "url": f"https://{bucket_name}.s3.amazonaws.com/{key}"
                            }
                            
                            # Flag sensitive files
                            sensitive_patterns = [
                                r"\.env$", r"\.git/", r"\.aws/",
                                r"credentials", r"secrets?", r"password",
                                r"\.pem$", r"\.key$", r"backup",
                                r"database", r"\.sql$", r"\.db$"
                            ]
                            
                            for pattern in sensitive_patterns:
                                if re.search(pattern, key.lower()):
                                    obj["sensitive"] = True
                                    break
                            
                            objects.append(obj)
                            
        except Exception:
            pass
        
        return objects
    
    async def scan_common_buckets(self, company_name: str) -> List[Dict]:
        """Scan for common bucket naming patterns"""
        suffixes = [
            "", "-dev", "-prod", "-staging", "-test",
            "-backup", "-backups", "-data", "-files",
            "-assets", "-static", "-media", "-logs",
            "-config", "-configs", "-private", "-public"
        ]
        
        prefixes = [
            "", "www-", "api-", "app-", "cdn-",
            "s3-", "bucket-", "storage-"
        ]
        
        found_buckets = []
        
        for prefix in prefixes:
            for suffix in suffixes:
                bucket_name = f"{prefix}{company_name}{suffix}"
                
                if await self.check_bucket_exists(bucket_name):
                    access_info = await self.check_public_access(bucket_name)
                    found_buckets.append({
                        "name": bucket_name,
                        "exists": True,
                        **access_info
                    })
        
        return found_buckets


class IAMAnalyzer:
    """IAM policy and permission analyzer"""
    
    # Dangerous IAM actions
    DANGEROUS_ACTIONS = [
        "iam:*",
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
        "sts:AssumeRole",
        "ec2:*",
        "s3:*",
        "lambda:*",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter*"
    ]
    
    # Privilege escalation paths
    PRIVESC_PATHS = {
        "iam:CreateAccessKey": "Can create access keys for other users",
        "iam:CreateLoginProfile": "Can create console login for users",
        "iam:UpdateLoginProfile": "Can change user passwords",
        "iam:AttachUserPolicy": "Can attach admin policy to self",
        "iam:PutUserPolicy": "Can add inline policy with any permissions",
        "iam:CreatePolicyVersion": "Can create new admin policy version",
        "iam:SetDefaultPolicyVersion": "Can set older policy version as default",
        "iam:PassRole": "Can pass powerful role to service",
        "lambda:CreateFunction": "With iam:PassRole, can execute code as role",
        "lambda:UpdateFunctionCode": "Can modify Lambda to execute arbitrary code",
        "ec2:RunInstances": "With iam:PassRole, can launch instance with role",
        "sts:AssumeRole": "Can assume more privileged roles",
        "glue:CreateDevEndpoint": "Can create endpoint with role",
        "cloudformation:CreateStack": "With iam:PassRole, can create resources"
    }
    
    def analyze_policy(self, policy: Dict) -> List[SecurityFinding]:
        """Analyze IAM policy for security issues"""
        findings = []
        
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for stmt in statements:
            effect = stmt.get("Effect", "")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for overly permissive policies
            if effect == "Allow":
                # Check for admin access
                if "*" in actions and "*" in resources:
                    findings.append(SecurityFinding(
                        provider=CloudProvider.AWS,
                        resource="IAM Policy",
                        finding_type="overly_permissive",
                        severity=Severity.CRITICAL,
                        title="Full Admin Access Policy",
                        description="Policy grants full administrative access",
                        remediation="Apply least privilege principle"
                    ))
                
                # Check for dangerous actions
                for action in actions:
                    if action in self.DANGEROUS_ACTIONS:
                        findings.append(SecurityFinding(
                            provider=CloudProvider.AWS,
                            resource="IAM Policy",
                            finding_type="dangerous_action",
                            severity=Severity.HIGH,
                            title=f"Dangerous IAM Action: {action}",
                            description=f"Policy allows dangerous action: {action}",
                            remediation="Review and restrict this permission"
                        ))
                    
                    # Check for privilege escalation
                    if action in self.PRIVESC_PATHS:
                        findings.append(SecurityFinding(
                            provider=CloudProvider.AWS,
                            resource="IAM Policy",
                            finding_type="privesc_path",
                            severity=Severity.HIGH,
                            title=f"Privilege Escalation Path: {action}",
                            description=self.PRIVESC_PATHS[action],
                            remediation="Remove or restrict this permission"
                        ))
        
        return findings
    
    def find_privesc_paths(self, user_permissions: List[str]) -> List[Dict]:
        """Find privilege escalation paths from user permissions"""
        paths = []
        
        for perm in user_permissions:
            # Normalize permission
            perm_lower = perm.lower()
            
            for dangerous_action, description in self.PRIVESC_PATHS.items():
                if perm_lower == dangerous_action.lower() or perm == "*":
                    paths.append({
                        "permission": perm,
                        "attack": dangerous_action,
                        "description": description,
                        "exploitable": True
                    })
        
        return paths


class CloudScanner:
    """Main cloud security scanner"""
    
    def __init__(self):
        self.metadata_service = MetadataService()
        self.s3_scanner = S3Scanner()
        self.iam_analyzer = IAMAnalyzer()
        self.findings: List[SecurityFinding] = []
        self.resources: List[CloudResource] = []
    
    async def scan(self, target: str = "") -> Dict:
        """Perform cloud security scan"""
        results = {
            "scan_start": datetime.now().isoformat(),
            "provider": None,
            "credentials": None,
            "metadata": {},
            "resources": [],
            "findings": [],
            "scan_end": None
        }
        
        # Detect cloud provider
        provider = await self.metadata_service.detect_cloud_provider()
        results["provider"] = provider.value
        
        if provider == CloudProvider.UNKNOWN:
            results["error"] = "Not running in a cloud environment"
            results["scan_end"] = datetime.now().isoformat()
            return results
        
        # Get metadata
        results["metadata"] = await self.metadata_service.get_all_metadata(provider)
        
        # Get credentials
        if provider == CloudProvider.AWS:
            creds = await self.metadata_service.get_aws_credentials()
            if creds:
                results["credentials"] = creds.to_dict()
                self.findings.append(SecurityFinding(
                    provider=provider,
                    resource="Metadata Service",
                    finding_type="credentials_exposed",
                    severity=Severity.HIGH,
                    title="AWS Credentials Retrieved from Metadata",
                    description="Successfully retrieved IAM role credentials from instance metadata",
                    remediation="Use IMDSv2 and restrict metadata access"
                ))
        
        elif provider == CloudProvider.AZURE:
            token = await self.metadata_service.get_azure_token()
            if token:
                results["credentials"] = {"azure_token": "retrieved"}
                self.findings.append(SecurityFinding(
                    provider=provider,
                    resource="Metadata Service",
                    finding_type="credentials_exposed",
                    severity=Severity.HIGH,
                    title="Azure Token Retrieved from Metadata",
                    description="Successfully retrieved managed identity token",
                    remediation="Review managed identity permissions"
                ))
        
        elif provider == CloudProvider.GCP:
            token = await self.metadata_service.get_gcp_token()
            if token:
                results["credentials"] = {"gcp_token": "retrieved"}
                self.findings.append(SecurityFinding(
                    provider=provider,
                    resource="Metadata Service",
                    finding_type="credentials_exposed",
                    severity=Severity.HIGH,
                    title="GCP Token Retrieved from Metadata",
                    description="Successfully retrieved service account token",
                    remediation="Review service account permissions"
                ))
        
        # If target is specified, scan for S3 buckets
        if target and provider == CloudProvider.AWS:
            buckets = await self.s3_scanner.scan_common_buckets(target)
            for bucket in buckets:
                if bucket.get("findings"):
                    self.findings.extend(bucket["findings"])
                results["resources"].append({
                    "type": "s3_bucket",
                    "name": bucket["name"],
                    "public_access": bucket.get("public_list", False) or bucket.get("public_write", False)
                })
        
        results["findings"] = [f.to_dict() for f in self.findings]
        results["scan_end"] = datetime.now().isoformat()
        
        return results
    
    async def scan_s3_bucket(self, bucket_name: str) -> Dict:
        """Scan specific S3 bucket"""
        results = {
            "bucket": bucket_name,
            "exists": False,
            "public_access": {},
            "objects": [],
            "findings": []
        }
        
        if await self.s3_scanner.check_bucket_exists(bucket_name):
            results["exists"] = True
            results["public_access"] = await self.s3_scanner.check_public_access(bucket_name)
            
            if results["public_access"].get("public_list"):
                results["objects"] = await self.s3_scanner.enumerate_bucket_objects(bucket_name)
                
                # Check for sensitive files
                for obj in results["objects"]:
                    if obj.get("sensitive"):
                        self.findings.append(SecurityFinding(
                            provider=CloudProvider.AWS,
                            resource=f"s3://{bucket_name}/{obj['key']}",
                            finding_type="sensitive_file_exposed",
                            severity=Severity.CRITICAL,
                            title="Sensitive File Publicly Accessible",
                            description=f"Potentially sensitive file exposed: {obj['key']}",
                            remediation="Remove public access and review file contents"
                        ))
            
            if results["public_access"].get("findings"):
                self.findings.extend(results["public_access"]["findings"])
        
        results["findings"] = [f.to_dict() for f in self.findings]
        return results
    
    def get_summary(self) -> Dict:
        """Get scan summary"""
        severity_counts = {s.value: 0 for s in Severity}
        
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        
        return {
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "resources_scanned": len(self.resources)
        }


# Global scanner instance
_scanner: Optional[CloudScanner] = None


def get_scanner() -> CloudScanner:
    """Get global cloud scanner instance"""
    global _scanner
    if _scanner is None:
        _scanner = CloudScanner()
    return _scanner


async def quick_scan(target: str = "") -> Dict:
    """Quick cloud security scan"""
    scanner = get_scanner()
    return await scanner.scan(target)


async def scan_bucket(bucket_name: str) -> Dict:
    """Scan S3 bucket"""
    scanner = get_scanner()
    return await scanner.scan_s3_bucket(bucket_name)
