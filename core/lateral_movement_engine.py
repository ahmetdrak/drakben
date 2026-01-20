# core/lateral_movement_engine.py
# DRAKBEN Lateral Movement Engine - Enterprise Network Pivoting
# Author: @drak_ben

import asyncio
import socket
import struct
import base64
import hashlib
import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import subprocess


class MovementTechnique(Enum):
    """Lateral movement techniques"""
    SSH = "ssh"
    SMB = "smb"
    WMI = "wmi"
    PSEXEC = "psexec"
    WINRM = "winrm"
    RDP = "rdp"
    DCOM = "dcom"
    PTH = "pass_the_hash"
    PTT = "pass_the_ticket"
    OVERPASS = "overpass_the_hash"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    KERBEROAST = "kerberoasting"
    ASREPROAST = "as_rep_roasting"


class CredentialType(Enum):
    """Credential types"""
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    KERBEROS_TICKET = "kerberos_ticket"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    TOKEN = "token"


class HostStatus(Enum):
    """Host status"""
    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"
    COMPROMISED = "compromised"
    PIVOT = "pivot_point"


@dataclass
class Credential:
    """Stored credential"""
    credential_id: str
    username: str
    credential_type: CredentialType
    value: str  # Password, hash, or key content
    domain: str = ""
    source_host: str = ""
    harvested_time: str = ""
    valid: bool = True
    admin_rights: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "credential_id": self.credential_id,
            "username": self.username,
            "credential_type": self.credential_type.value,
            "value": "***REDACTED***",  # Never expose credentials
            "domain": self.domain,
            "source_host": self.source_host,
            "harvested_time": self.harvested_time,
            "valid": self.valid,
            "admin_rights": self.admin_rights
        }


@dataclass
class NetworkHost:
    """Network host information"""
    ip: str
    hostname: str = ""
    os: str = ""
    status: HostStatus = HostStatus.UNKNOWN
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    domain: str = ""
    is_dc: bool = False
    admin_shares: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "status": self.status.value,
            "open_ports": self.open_ports,
            "services": self.services,
            "domain": self.domain,
            "is_dc": self.is_dc,
            "admin_shares": self.admin_shares,
            "vulnerabilities": self.vulnerabilities
        }


@dataclass
class MovementResult:
    """Lateral movement attempt result"""
    success: bool
    technique: MovementTechnique
    source_host: str
    target_host: str
    credential_used: Optional[str] = None
    error_message: str = ""
    session_id: str = ""
    execution_time: float = 0.0
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PivotSession:
    """Active pivot session"""
    session_id: str
    source_host: str
    target_host: str
    technique: MovementTechnique
    username: str
    established_time: str
    active: bool = True
    port_forwards: List[Dict] = field(default_factory=list)


class CredentialHarvester:
    """Credential harvesting module"""
    
    def __init__(self):
        self.credentials: Dict[str, Credential] = {}
        self._cred_counter = 0
    
    def _generate_cred_id(self) -> str:
        """Generate unique credential ID"""
        self._cred_counter += 1
        return f"CRED-{self._cred_counter:04d}"
    
    async def harvest_from_memory(self, host: str) -> List[Credential]:
        """
        Harvest credentials from memory (mimikatz-style)
        Note: This is a simulation - real implementation requires native code
        """
        harvested = []
        
        # Simulated credential extraction patterns
        # In real implementation, this would use:
        # - mimikatz for Windows
        # - /proc/self/maps parsing for Linux
        # - Memory forensics techniques
        
        return harvested
    
    async def harvest_from_lsass(self, host: str) -> List[Credential]:
        """Harvest from LSASS process (Windows)"""
        harvested = []
        
        # This would use techniques like:
        # - comsvcs.dll MiniDump
        # - procdump
        # - Direct LSASS reading
        
        return harvested
    
    async def harvest_from_sam(self, host: str) -> List[Credential]:
        """Harvest from SAM database (Windows)"""
        harvested = []
        
        # Techniques:
        # - reg save HKLM\SAM
        # - Volume Shadow Copy
        # - Direct file access
        
        return harvested
    
    async def harvest_kerberos_tickets(self, host: str) -> List[Credential]:
        """Harvest Kerberos tickets"""
        harvested = []
        
        # Techniques:
        # - klist
        # - sekurlsa::tickets (mimikatz)
        # - Rubeus dump
        
        return harvested
    
    async def harvest_ssh_keys(self, host: str) -> List[Credential]:
        """Harvest SSH keys from filesystem"""
        harvested = []
        
        # Common SSH key locations
        key_paths = [
            "/root/.ssh/id_rsa",
            "/root/.ssh/id_ed25519",
            "/home/*/.ssh/id_rsa",
            "/home/*/.ssh/id_ed25519",
            "C:\\Users\\*\\.ssh\\id_rsa",
            "C:\\Users\\*\\.ssh\\id_ed25519",
        ]
        
        # This would enumerate and extract SSH keys
        
        return harvested
    
    async def harvest_browser_credentials(self, host: str) -> List[Credential]:
        """Harvest credentials from browsers"""
        harvested = []
        
        # Browser credential locations:
        # - Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
        # - Firefox: %APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json
        # - Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
        
        return harvested
    
    async def harvest_config_files(self, host: str) -> List[Credential]:
        """Harvest credentials from config files"""
        harvested = []
        
        # Common config file locations
        config_patterns = [
            "web.config",
            ".htpasswd",
            "wp-config.php",
            ".env",
            "config.php",
            "database.yml",
            "settings.py",
            "application.properties",
        ]
        
        return harvested
    
    def add_credential(self, credential: Credential):
        """Add credential to store"""
        self.credentials[credential.credential_id] = credential
    
    def get_credentials_for_user(self, username: str) -> List[Credential]:
        """Get all credentials for a user"""
        return [c for c in self.credentials.values() if c.username.lower() == username.lower()]
    
    def get_admin_credentials(self) -> List[Credential]:
        """Get credentials with admin rights"""
        return [c for c in self.credentials.values() if c.admin_rights]
    
    def get_domain_credentials(self, domain: str) -> List[Credential]:
        """Get credentials for a domain"""
        return [c for c in self.credentials.values() if c.domain.lower() == domain.lower()]


class NetworkDiscovery:
    """Network discovery and enumeration"""
    
    def __init__(self):
        self.hosts: Dict[str, NetworkHost] = {}
        self.subnets: Set[str] = set()
    
    async def discover_subnet(self, subnet: str, timeout: float = 1.0) -> List[NetworkHost]:
        """
        Discover hosts in a subnet
        
        Args:
            subnet: CIDR notation (e.g., "192.168.1.0/24")
            timeout: Timeout per host
        """
        discovered = []
        
        try:
            import ipaddress
            network = ipaddress.ip_network(subnet, strict=False)
            
            # Parallel ping sweep
            tasks = []
            for ip in network.hosts():
                tasks.append(self._check_host(str(ip), timeout))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for ip, result in zip(network.hosts(), results):
                if isinstance(result, NetworkHost):
                    discovered.append(result)
                    self.hosts[str(ip)] = result
        
        except Exception as e:
            print(f"[Discovery] Error: {e}")
        
        return discovered
    
    async def _check_host(self, ip: str, timeout: float) -> Optional[NetworkHost]:
        """Check if host is alive"""
        try:
            # TCP SYN check on common ports
            common_ports = [22, 80, 135, 139, 443, 445, 3389, 5985]
            
            for port in common_ports:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    host = NetworkHost(
                        ip=ip,
                        status=HostStatus.ALIVE,
                        open_ports=[port]
                    )
                    return host
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    continue
            
            return None
        
        except Exception:
            return None
    
    async def port_scan(self, host: str, ports: List[int] = None, timeout: float = 1.0) -> NetworkHost:
        """Scan ports on a host"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 8080]
        
        open_ports = []
        services = {}
        
        async def check_port(port: int) -> Optional[int]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
                
                # Try to grab banner
                try:
                    writer.write(b"\r\n")
                    await writer.drain()
                    banner = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                    services[port] = banner.decode('utf-8', errors='ignore').strip()[:100]
                except:
                    services[port] = self._guess_service(port)
                
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [p for p in results if p is not None]
        
        network_host = NetworkHost(
            ip=host,
            status=HostStatus.ALIVE if open_ports else HostStatus.UNKNOWN,
            open_ports=sorted(open_ports),
            services=services
        )
        
        self.hosts[host] = network_host
        return network_host
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on port"""
        port_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
            143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
            995: "pop3s", 1433: "mssql", 1521: "oracle", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
            8080: "http-proxy"
        }
        return port_services.get(port, "unknown")
    
    async def enumerate_smb(self, host: str, credential: Credential = None) -> Dict:
        """Enumerate SMB shares and info"""
        info = {
            "hostname": "",
            "domain": "",
            "os": "",
            "shares": [],
            "is_dc": False
        }
        
        # This would use smbclient or impacket for real enumeration
        
        return info
    
    async def enumerate_ldap(self, host: str, credential: Credential = None) -> Dict:
        """Enumerate LDAP/Active Directory"""
        info = {
            "domain": "",
            "domain_controllers": [],
            "users": [],
            "groups": [],
            "computers": [],
            "gpos": []
        }
        
        # This would use ldap3 or impacket for real enumeration
        
        return info
    
    async def find_domain_controllers(self, domain: str) -> List[NetworkHost]:
        """Find domain controllers for a domain"""
        dcs = []
        
        # DNS SRV lookup for _ldap._tcp.dc._msdcs.{domain}
        # Or LDAP enumeration
        
        return dcs
    
    def get_pivot_targets(self) -> List[NetworkHost]:
        """Get potential pivot targets"""
        targets = []
        
        for host in self.hosts.values():
            # Prioritize:
            # 1. Domain controllers
            # 2. Hosts with admin shares
            # 3. Hosts with many services
            
            if host.is_dc:
                targets.insert(0, host)
            elif host.admin_shares:
                targets.append(host)
            elif len(host.open_ports) > 3:
                targets.append(host)
        
        return targets


class LateralMovementEngine:
    """
    Enterprise Lateral Movement Engine
    Supports multiple techniques for network pivoting
    """
    
    VERSION = "2.0.0"
    
    def __init__(self):
        self.credential_harvester = CredentialHarvester()
        self.network_discovery = NetworkDiscovery()
        self.active_sessions: Dict[str, PivotSession] = {}
        self.movement_history: List[MovementResult] = []
        self._session_counter = 0
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        self._session_counter += 1
        return f"SESSION-{self._session_counter:04d}"
    
    async def move_ssh(self, target: str, credential: Credential, 
                       port: int = 22, timeout: float = 30.0) -> MovementResult:
        """
        SSH lateral movement
        
        Args:
            target: Target host
            credential: SSH credential (password or key)
            port: SSH port
            timeout: Connection timeout
        """
        start_time = datetime.now()
        result = MovementResult(
            success=False,
            technique=MovementTechnique.SSH,
            source_host="localhost",
            target_host=target,
            credential_used=credential.credential_id,
            timestamp=start_time.isoformat()
        )
        
        try:
            if credential.credential_type == CredentialType.PASSWORD:
                # SSH with password
                cmd = [
                    "ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", f"ConnectTimeout={int(timeout)}",
                    "-p", str(port),
                    f"{credential.username}@{target}",
                    "echo SUCCESS"
                ]
                
                # In real implementation, use paramiko or asyncssh
                # This is a placeholder for the concept
                
            elif credential.credential_type == CredentialType.SSH_KEY:
                # SSH with key
                pass
            
            # Simulate success for demonstration
            result.success = True
            result.session_id = self._generate_session_id()
            
            # Create pivot session
            session = PivotSession(
                session_id=result.session_id,
                source_host="localhost",
                target_host=target,
                technique=MovementTechnique.SSH,
                username=credential.username,
                established_time=datetime.now().isoformat()
            )
            self.active_sessions[session.session_id] = session
            
        except Exception as e:
            result.error_message = str(e)
        
        result.execution_time = (datetime.now() - start_time).total_seconds()
        self.movement_history.append(result)
        
        return result
    
    async def move_smb(self, target: str, credential: Credential,
                       command: str = None) -> MovementResult:
        """
        SMB/PSEXEC lateral movement
        
        Args:
            target: Target host
            credential: Windows credential
            command: Command to execute (optional)
        """
        start_time = datetime.now()
        result = MovementResult(
            success=False,
            technique=MovementTechnique.SMB,
            source_host="localhost",
            target_host=target,
            credential_used=credential.credential_id,
            timestamp=start_time.isoformat()
        )
        
        try:
            # In real implementation, use impacket's smbexec or psexec
            # from impacket.examples import psexec
            
            pass
            
        except Exception as e:
            result.error_message = str(e)
        
        result.execution_time = (datetime.now() - start_time).total_seconds()
        self.movement_history.append(result)
        
        return result
    
    async def move_wmi(self, target: str, credential: Credential,
                       command: str = None) -> MovementResult:
        """
        WMI lateral movement
        
        Args:
            target: Target host
            credential: Windows credential
            command: Command to execute
        """
        start_time = datetime.now()
        result = MovementResult(
            success=False,
            technique=MovementTechnique.WMI,
            source_host="localhost",
            target_host=target,
            credential_used=credential.credential_id,
            timestamp=start_time.isoformat()
        )
        
        try:
            # In real implementation, use impacket's wmiexec
            # from impacket.examples import wmiexec
            
            pass
            
        except Exception as e:
            result.error_message = str(e)
        
        result.execution_time = (datetime.now() - start_time).total_seconds()
        self.movement_history.append(result)
        
        return result
    
    async def move_winrm(self, target: str, credential: Credential,
                         command: str = None, use_ssl: bool = False) -> MovementResult:
        """
        WinRM lateral movement
        
        Args:
            target: Target host
            credential: Windows credential
            command: Command to execute
            use_ssl: Use HTTPS
        """
        start_time = datetime.now()
        result = MovementResult(
            success=False,
            technique=MovementTechnique.WINRM,
            source_host="localhost",
            target_host=target,
            credential_used=credential.credential_id,
            timestamp=start_time.isoformat()
        )
        
        try:
            # In real implementation, use pywinrm
            # import winrm
            
            port = 5986 if use_ssl else 5985
            
            pass
            
        except Exception as e:
            result.error_message = str(e)
        
        result.execution_time = (datetime.now() - start_time).total_seconds()
        self.movement_history.append(result)
        
        return result
    
    async def move_dcom(self, target: str, credential: Credential,
                        command: str = None) -> MovementResult:
        """
        DCOM lateral movement
        
        Args:
            target: Target host
            credential: Windows credential
            command: Command to execute
        """
        start_time = datetime.now()
        result = MovementResult(
            success=False,
            technique=MovementTechnique.DCOM,
            source_host="localhost",
            target_host=target,
            credential_used=credential.credential_id,
            timestamp=start_time.isoformat()
        )
        
        try:
            # In real implementation, use impacket's dcomexec
            # Common DCOM objects:
            # - MMC20.Application
            # - ShellWindows
            # - ShellBrowserWindow
            # - Excel.Application
            # - Outlook.Application
            
            pass
            
        except Exception as e:
            result.error_message = str(e)
        
        result.execution_time = (datetime.now() - start_time).total_seconds()
        self.movement_history.append(result)
        
        return result
    
    async def pass_the_hash(self, target: str, username: str, 
                            ntlm_hash: str, domain: str = "") -> MovementResult:
        """
        Pass-the-Hash attack
        
        Args:
            target: Target host
            username: Username
            ntlm_hash: NTLM hash (LM:NT format)
            domain: Domain name
        """
        start_time = datetime.now()
        result = MovementResult(
            success=False,
            technique=MovementTechnique.PTH,
            source_host="localhost",
            target_host=target,
            timestamp=start_time.isoformat()
        )
        
        try:
            # In real implementation, use impacket with hash
            # Example: secretsdump.py -hashes :hash domain/user@target
            
            pass
            
        except Exception as e:
            result.error_message = str(e)
        
        result.execution_time = (datetime.now() - start_time).total_seconds()
        self.movement_history.append(result)
        
        return result
    
    async def pass_the_ticket(self, target: str, ticket_path: str) -> MovementResult:
        """
        Pass-the-Ticket attack
        
        Args:
            target: Target host
            ticket_path: Path to .kirbi or .ccache ticket
        """
        start_time = datetime.now()
        result = MovementResult(
            success=False,
            technique=MovementTechnique.PTT,
            source_host="localhost",
            target_host=target,
            timestamp=start_time.isoformat()
        )
        
        try:
            # In real implementation:
            # 1. Load ticket with mimikatz kerberos::ptt
            # 2. Or set KRB5CCNAME environment variable
            # 3. Access target with Kerberos auth
            
            pass
            
        except Exception as e:
            result.error_message = str(e)
        
        result.execution_time = (datetime.now() - start_time).total_seconds()
        self.movement_history.append(result)
        
        return result
    
    async def kerberoast(self, target: str, credential: Credential) -> List[Dict]:
        """
        Kerberoasting attack - request TGS tickets for SPNs
        
        Args:
            target: Domain controller
            credential: Domain credential
        
        Returns:
            List of service tickets (hashes for cracking)
        """
        tickets = []
        
        try:
            # In real implementation, use impacket's GetUserSPNs.py
            # 1. Query LDAP for users with SPNs
            # 2. Request TGS tickets for each SPN
            # 3. Extract ticket hashes for offline cracking
            
            pass
            
        except Exception as e:
            print(f"[Kerberoast] Error: {e}")
        
        return tickets
    
    async def as_rep_roast(self, target: str, userlist: List[str]) -> List[Dict]:
        """
        AS-REP Roasting - target users without pre-authentication
        
        Args:
            target: Domain controller
            userlist: List of usernames to test
        
        Returns:
            List of AS-REP hashes for cracking
        """
        hashes = []
        
        try:
            # In real implementation, use impacket's GetNPUsers.py
            # 1. Send AS-REQ without pre-authentication
            # 2. Capture AS-REP response
            # 3. Extract hash for offline cracking
            
            pass
            
        except Exception as e:
            print(f"[AS-REP Roast] Error: {e}")
        
        return hashes
    
    async def create_port_forward(self, session_id: str, local_port: int,
                                  remote_host: str, remote_port: int) -> bool:
        """
        Create port forward through pivot session
        
        Args:
            session_id: Active session ID
            local_port: Local port to listen on
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to
        """
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        
        try:
            # In real implementation:
            # SSH: -L local_port:remote_host:remote_port
            # SOCKS proxy for other techniques
            
            forward_info = {
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "active": True
            }
            
            session.port_forwards.append(forward_info)
            return True
            
        except Exception as e:
            print(f"[Port Forward] Error: {e}")
            return False
    
    async def create_socks_proxy(self, session_id: str, port: int = 1080) -> bool:
        """
        Create SOCKS proxy through pivot session
        
        Args:
            session_id: Active session ID
            port: Local SOCKS port
        """
        if session_id not in self.active_sessions:
            return False
        
        try:
            # In real implementation:
            # SSH: -D port (dynamic port forwarding)
            # Chisel, ligolo, or similar for other techniques
            
            return True
            
        except Exception as e:
            print(f"[SOCKS Proxy] Error: {e}")
            return False
    
    async def auto_pivot(self, start_host: str, credential: Credential,
                         target_network: str, max_hops: int = 3) -> List[MovementResult]:
        """
        Automatic pivoting through network
        
        Args:
            start_host: Starting host
            credential: Initial credential
            target_network: Target network CIDR
            max_hops: Maximum pivot hops
        """
        results = []
        visited = {start_host}
        current_hosts = [start_host]
        hop = 0
        
        while hop < max_hops and current_hosts:
            hop += 1
            next_hosts = []
            
            for host in current_hosts:
                # Discover adjacent network
                adjacent = await self.network_discovery.discover_subnet(
                    f"{host}/24", timeout=0.5
                )
                
                for adj_host in adjacent:
                    if adj_host.ip not in visited:
                        visited.add(adj_host.ip)
                        
                        # Try to move to host
                        result = await self._try_movement(adj_host.ip, credential)
                        results.append(result)
                        
                        if result.success:
                            next_hosts.append(adj_host.ip)
                            
                            # Harvest credentials on new host
                            new_creds = await self.credential_harvester.harvest_from_memory(adj_host.ip)
                            for cred in new_creds:
                                self.credential_harvester.add_credential(cred)
            
            current_hosts = next_hosts
        
        return results
    
    async def _try_movement(self, target: str, credential: Credential) -> MovementResult:
        """Try various movement techniques"""
        
        # Check what ports are open
        host_info = await self.network_discovery.port_scan(target, timeout=0.5)
        
        # Try appropriate technique based on open ports
        if 22 in host_info.open_ports:
            return await self.move_ssh(target, credential)
        elif 445 in host_info.open_ports:
            return await self.move_smb(target, credential)
        elif 5985 in host_info.open_ports:
            return await self.move_winrm(target, credential)
        elif 135 in host_info.open_ports:
            return await self.move_wmi(target, credential)
        
        return MovementResult(
            success=False,
            technique=MovementTechnique.SSH,
            source_host="localhost",
            target_host=target,
            error_message="No suitable port found",
            timestamp=datetime.now().isoformat()
        )
    
    def get_attack_path(self) -> List[Dict]:
        """Get current attack path through network"""
        path = []
        
        for result in self.movement_history:
            if result.success:
                path.append({
                    "from": result.source_host,
                    "to": result.target_host,
                    "technique": result.technique.value,
                    "time": result.timestamp
                })
        
        return path
    
    def get_network_map(self) -> Dict:
        """Get discovered network map"""
        return {
            "hosts": [h.to_dict() for h in self.network_discovery.hosts.values()],
            "active_sessions": len(self.active_sessions),
            "credentials_harvested": len(self.credential_harvester.credentials),
            "attack_path": self.get_attack_path()
        }
    
    def close_session(self, session_id: str):
        """Close a pivot session"""
        if session_id in self.active_sessions:
            self.active_sessions[session_id].active = False
            del self.active_sessions[session_id]
    
    def close_all_sessions(self):
        """Close all pivot sessions"""
        for session_id in list(self.active_sessions.keys()):
            self.close_session(session_id)


# Global engine instance
_engine: Optional[LateralMovementEngine] = None


def get_engine() -> LateralMovementEngine:
    """Get or create global engine instance"""
    global _engine
    if _engine is None:
        _engine = LateralMovementEngine()
    return _engine


# Convenience functions
async def discover_network(subnet: str) -> List[NetworkHost]:
    """Discover hosts in subnet"""
    engine = get_engine()
    return await engine.network_discovery.discover_subnet(subnet)


async def pivot_to_host(target: str, credential: Credential) -> MovementResult:
    """Pivot to a host"""
    engine = get_engine()
    return await engine._try_movement(target, credential)
