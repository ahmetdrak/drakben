"""
DRAKBEN - Active Directory & BloodHound Integration
LDAP enumeration, GPO abuse, attack path mapping
"""

import asyncio
import socket
import struct
import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
from datetime import datetime


class ADObjectType(Enum):
    """Active Directory object types"""
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    OU = "organizational_unit"
    GPO = "gpo"
    DOMAIN = "domain"
    TRUST = "trust"


class PrivilegeLevel(Enum):
    """AD privilege levels"""
    DOMAIN_ADMIN = "domain_admin"
    ENTERPRISE_ADMIN = "enterprise_admin"
    SCHEMA_ADMIN = "schema_admin"
    ADMINISTRATOR = "administrator"
    BACKUP_OPERATOR = "backup_operator"
    ACCOUNT_OPERATOR = "account_operator"
    SERVER_OPERATOR = "server_operator"
    PRINT_OPERATOR = "print_operator"
    STANDARD_USER = "standard_user"


class AttackTechnique(Enum):
    """AD attack techniques"""
    KERBEROASTING = "kerberoasting"
    ASREP_ROASTING = "asrep_roasting"
    PASS_THE_HASH = "pass_the_hash"
    PASS_THE_TICKET = "pass_the_ticket"
    GOLDEN_TICKET = "golden_ticket"
    SILVER_TICKET = "silver_ticket"
    DCSYNC = "dcsync"
    GPO_ABUSE = "gpo_abuse"
    ACL_ABUSE = "acl_abuse"
    DELEGATION_ABUSE = "delegation_abuse"
    CONSTRAINED_DELEGATION = "constrained_delegation"
    UNCONSTRAINED_DELEGATION = "unconstrained_delegation"
    RBCD = "resource_based_constrained_delegation"
    SHADOW_CREDENTIALS = "shadow_credentials"
    ADCS_ABUSE = "adcs_abuse"
    PRINTNIGHTMARE = "printnightmare"
    ZEROLOGON = "zerologon"
    PETITPOTAM = "petitpotam"


@dataclass
class ADUser:
    """Active Directory user"""
    sam_account_name: str
    distinguished_name: str
    sid: str
    enabled: bool = True
    admin_count: int = 0
    spn: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    password_last_set: str = ""
    last_logon: str = ""
    description: str = ""
    dont_req_preauth: bool = False
    password_not_required: bool = False
    trusted_for_delegation: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "sam_account_name": self.sam_account_name,
            "distinguished_name": self.distinguished_name,
            "sid": self.sid,
            "enabled": self.enabled,
            "admin_count": self.admin_count,
            "spn": self.spn,
            "member_of": self.member_of,
            "password_last_set": self.password_last_set,
            "last_logon": self.last_logon,
            "description": self.description,
            "dont_req_preauth": self.dont_req_preauth,
            "password_not_required": self.password_not_required,
            "trusted_for_delegation": self.trusted_for_delegation
        }


@dataclass
class ADGroup:
    """Active Directory group"""
    sam_account_name: str
    distinguished_name: str
    sid: str
    members: List[str] = field(default_factory=list)
    member_of: List[str] = field(default_factory=list)
    admin_count: int = 0
    description: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "sam_account_name": self.sam_account_name,
            "distinguished_name": self.distinguished_name,
            "sid": self.sid,
            "members": self.members,
            "member_of": self.member_of,
            "admin_count": self.admin_count,
            "description": self.description
        }


@dataclass
class ADComputer:
    """Active Directory computer"""
    sam_account_name: str
    distinguished_name: str
    sid: str
    dns_hostname: str = ""
    operating_system: str = ""
    os_version: str = ""
    enabled: bool = True
    trusted_for_delegation: bool = False
    allowed_to_delegate_to: List[str] = field(default_factory=list)
    local_admins: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "sam_account_name": self.sam_account_name,
            "distinguished_name": self.distinguished_name,
            "sid": self.sid,
            "dns_hostname": self.dns_hostname,
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "enabled": self.enabled,
            "trusted_for_delegation": self.trusted_for_delegation,
            "allowed_to_delegate_to": self.allowed_to_delegate_to,
            "local_admins": self.local_admins
        }


@dataclass
class GPOInfo:
    """Group Policy Object information"""
    name: str
    display_name: str
    gpo_guid: str
    gpc_path: str
    linked_to: List[str] = field(default_factory=list)
    acl: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "gpo_guid": self.gpo_guid,
            "gpc_path": self.gpc_path,
            "linked_to": self.linked_to,
            "acl": self.acl
        }


@dataclass
class AttackPath:
    """Attack path to target"""
    source: str
    target: str
    path: List[Dict] = field(default_factory=list)
    techniques: List[AttackTechnique] = field(default_factory=list)
    complexity: str = "medium"
    
    def to_dict(self) -> Dict:
        return {
            "source": self.source,
            "target": self.target,
            "path": self.path,
            "techniques": [t.value for t in self.techniques],
            "complexity": self.complexity,
            "path_length": len(self.path)
        }


class LDAPClient:
    """Lightweight LDAP client for AD enumeration"""
    
    # Well-known SIDs
    WELL_KNOWN_SIDS = {
        "S-1-5-32-544": "Administrators",
        "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators",
        "S-1-5-32-550": "Print Operators",
        "S-1-5-32-551": "Backup Operators",
        "S-1-5-21-*-512": "Domain Admins",
        "S-1-5-21-*-519": "Enterprise Admins",
        "S-1-5-21-*-518": "Schema Admins",
        "S-1-5-21-*-500": "Administrator",
        "S-1-5-21-*-502": "KRBTGT",
    }
    
    def __init__(self, dc_ip: str, domain: str, username: str = "", password: str = ""):
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.base_dn = self._domain_to_dn(domain)
        self.connected = False
    
    def _domain_to_dn(self, domain: str) -> str:
        """Convert domain to distinguished name"""
        parts = domain.split(".")
        return ",".join([f"DC={p}" for p in parts])
    
    async def connect(self) -> bool:
        """Establish connection to DC"""
        try:
            # Test connectivity
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.dc_ip, 389))
            sock.close()
            
            if result == 0:
                self.connected = True
                return True
            return False
        except Exception:
            return False
    
    async def enumerate_users(self) -> List[ADUser]:
        """Enumerate domain users"""
        users = []
        
        # Simulated user enumeration (in real implementation, use ldap3 or impacket)
        # This demonstrates the structure
        sample_users = [
            ADUser(
                sam_account_name="Administrator",
                distinguished_name=f"CN=Administrator,CN=Users,{self.base_dn}",
                sid="S-1-5-21-DOMAIN-500",
                enabled=True,
                admin_count=1,
                member_of=["Domain Admins", "Administrators"]
            ),
            ADUser(
                sam_account_name="krbtgt",
                distinguished_name=f"CN=krbtgt,CN=Users,{self.base_dn}",
                sid="S-1-5-21-DOMAIN-502",
                enabled=False,
                admin_count=1
            ),
        ]
        
        return sample_users
    
    async def enumerate_groups(self) -> List[ADGroup]:
        """Enumerate domain groups"""
        groups = []
        
        privileged_groups = [
            ("Domain Admins", "S-1-5-21-DOMAIN-512"),
            ("Enterprise Admins", "S-1-5-21-DOMAIN-519"),
            ("Schema Admins", "S-1-5-21-DOMAIN-518"),
            ("Administrators", "S-1-5-32-544"),
            ("Account Operators", "S-1-5-32-548"),
            ("Backup Operators", "S-1-5-32-551"),
            ("Server Operators", "S-1-5-32-549"),
            ("Print Operators", "S-1-5-32-550"),
        ]
        
        for name, sid in privileged_groups:
            groups.append(ADGroup(
                sam_account_name=name,
                distinguished_name=f"CN={name},CN=Users,{self.base_dn}",
                sid=sid,
                admin_count=1
            ))
        
        return groups
    
    async def enumerate_computers(self) -> List[ADComputer]:
        """Enumerate domain computers"""
        computers = []
        
        # Domain Controller
        computers.append(ADComputer(
            sam_account_name="DC01$",
            distinguished_name=f"CN=DC01,OU=Domain Controllers,{self.base_dn}",
            sid="S-1-5-21-DOMAIN-1001",
            dns_hostname=f"dc01.{self.domain}",
            operating_system="Windows Server 2019",
            trusted_for_delegation=True
        ))
        
        return computers
    
    async def enumerate_gpos(self) -> List[GPOInfo]:
        """Enumerate Group Policy Objects"""
        gpos = []
        
        default_gpos = [
            ("Default Domain Policy", "{31B2F340-016D-11D2-945F-00C04FB984F9}"),
            ("Default Domain Controllers Policy", "{6AC1786C-016F-11D2-945F-00C04FB984F9}"),
        ]
        
        for name, guid in default_gpos:
            gpos.append(GPOInfo(
                name=name,
                display_name=name,
                gpo_guid=guid,
                gpc_path=f"\\\\{self.domain}\\sysvol\\{self.domain}\\Policies\\{guid}",
                linked_to=[self.base_dn]
            ))
        
        return gpos
    
    async def find_kerberoastable_users(self, users: List[ADUser]) -> List[ADUser]:
        """Find users with SPNs (Kerberoastable)"""
        return [u for u in users if u.spn and u.enabled]
    
    async def find_asrep_roastable_users(self, users: List[ADUser]) -> List[ADUser]:
        """Find users with 'Do not require Kerberos preauthentication'"""
        return [u for u in users if u.dont_req_preauth and u.enabled]
    
    async def find_delegation_abuse(self, computers: List[ADComputer]) -> List[Dict]:
        """Find computers with delegation misconfigurations"""
        abuses = []
        
        for computer in computers:
            if computer.trusted_for_delegation:
                abuses.append({
                    "computer": computer.sam_account_name,
                    "type": "unconstrained_delegation",
                    "risk": "critical",
                    "description": "Computer trusted for unconstrained delegation"
                })
            
            if computer.allowed_to_delegate_to:
                abuses.append({
                    "computer": computer.sam_account_name,
                    "type": "constrained_delegation",
                    "targets": computer.allowed_to_delegate_to,
                    "risk": "high"
                })
        
        return abuses


class BloodHoundIngestor:
    """BloodHound-compatible data collector"""
    
    def __init__(self, ldap_client: LDAPClient):
        self.ldap = ldap_client
        self.data = {
            "users": [],
            "groups": [],
            "computers": [],
            "domains": [],
            "gpos": [],
            "ous": []
        }
    
    async def collect_all(self) -> Dict:
        """Collect all AD data"""
        # Collect users
        users = await self.ldap.enumerate_users()
        self.data["users"] = [self._user_to_bloodhound(u) for u in users]
        
        # Collect groups
        groups = await self.ldap.enumerate_groups()
        self.data["groups"] = [self._group_to_bloodhound(g) for g in groups]
        
        # Collect computers
        computers = await self.ldap.enumerate_computers()
        self.data["computers"] = [self._computer_to_bloodhound(c) for c in computers]
        
        # Collect domain info
        self.data["domains"] = [{
            "name": self.ldap.domain.upper(),
            "domain_sid": "S-1-5-21-DOMAIN",
            "collected": True
        }]
        
        return self.data
    
    def _user_to_bloodhound(self, user: ADUser) -> Dict:
        """Convert user to BloodHound format"""
        return {
            "ObjectIdentifier": user.sid,
            "PrincipalName": f"{user.sam_account_name}@{self.ldap.domain.upper()}",
            "Properties": {
                "name": f"{user.sam_account_name}@{self.ldap.domain.upper()}",
                "domain": self.ldap.domain.upper(),
                "objectid": user.sid,
                "enabled": user.enabled,
                "admincount": user.admin_count > 0,
                "hasspn": len(user.spn) > 0,
                "dontreqpreauth": user.dont_req_preauth,
                "unconstraineddelegation": user.trusted_for_delegation,
                "description": user.description
            },
            "MemberOf": user.member_of,
            "SPNTargets": user.spn
        }
    
    def _group_to_bloodhound(self, group: ADGroup) -> Dict:
        """Convert group to BloodHound format"""
        return {
            "ObjectIdentifier": group.sid,
            "PrincipalName": f"{group.sam_account_name}@{self.ldap.domain.upper()}",
            "Properties": {
                "name": f"{group.sam_account_name}@{self.ldap.domain.upper()}",
                "domain": self.ldap.domain.upper(),
                "objectid": group.sid,
                "admincount": group.admin_count > 0,
                "description": group.description
            },
            "Members": group.members
        }
    
    def _computer_to_bloodhound(self, computer: ADComputer) -> Dict:
        """Convert computer to BloodHound format"""
        return {
            "ObjectIdentifier": computer.sid,
            "PrincipalName": f"{computer.sam_account_name}@{self.ldap.domain.upper()}",
            "Properties": {
                "name": f"{computer.dns_hostname.upper()}",
                "domain": self.ldap.domain.upper(),
                "objectid": computer.sid,
                "enabled": computer.enabled,
                "operatingsystem": computer.operating_system,
                "unconstraineddelegation": computer.trusted_for_delegation
            },
            "AllowedToDelegate": computer.allowed_to_delegate_to,
            "LocalAdmins": computer.local_admins
        }
    
    def export_json(self, output_dir: str) -> List[str]:
        """Export data as BloodHound JSON files"""
        files = []
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        for data_type, data in self.data.items():
            if data:
                filename = f"{timestamp}_{data_type}.json"
                filepath = os.path.join(output_dir, filename)
                
                export_data = {
                    "data": data,
                    "meta": {
                        "type": data_type,
                        "count": len(data),
                        "version": 5
                    }
                }
                
                # In real implementation, write to file
                files.append(filepath)
        
        return files


class GPOAnalyzer:
    """Analyzes GPOs for abuse opportunities"""
    
    # Dangerous GPO permissions
    DANGEROUS_PERMISSIONS = [
        "GenericAll",
        "GenericWrite",
        "WriteProperty",
        "WriteDacl",
        "WriteOwner"
    ]
    
    # Interesting GPO settings
    INTERESTING_SETTINGS = [
        "Scheduled Tasks",
        "Immediate Scheduled Tasks",
        "Restricted Groups",
        "Local Users and Groups",
        "Registry Settings",
        "Files",
        "Scripts"
    ]
    
    def analyze_gpo_permissions(self, gpo: GPOInfo) -> List[Dict]:
        """Analyze GPO for permission issues"""
        issues = []
        
        for ace in gpo.acl:
            principal = ace.get("principal", "")
            permission = ace.get("permission", "")
            
            if permission in self.DANGEROUS_PERMISSIONS:
                # Check if non-admin has dangerous permission
                if "Domain Users" in principal or "Authenticated Users" in principal:
                    issues.append({
                        "gpo": gpo.name,
                        "issue": "weak_permissions",
                        "principal": principal,
                        "permission": permission,
                        "risk": "critical",
                        "description": f"Non-admin '{principal}' has '{permission}' on GPO"
                    })
        
        return issues
    
    def find_gpo_abuse_paths(self, gpos: List[GPOInfo], 
                             computers: List[ADComputer]) -> List[Dict]:
        """Find paths to abuse GPOs for lateral movement"""
        abuse_paths = []
        
        for gpo in gpos:
            for linked_ou in gpo.linked_to:
                # Find computers in linked OU
                affected_computers = [
                    c for c in computers 
                    if linked_ou in c.distinguished_name
                ]
                
                if affected_computers:
                    abuse_paths.append({
                        "gpo": gpo.name,
                        "linked_to": linked_ou,
                        "affected_computers": [c.sam_account_name for c in affected_computers],
                        "attack": "gpo_abuse",
                        "description": "Modify GPO to execute code on linked computers"
                    })
        
        return abuse_paths


class AttackPathFinder:
    """Finds attack paths to high-value targets"""
    
    def __init__(self):
        self.graph: Dict[str, List[Dict]] = {}
    
    def build_graph(self, users: List[ADUser], groups: List[ADGroup], 
                    computers: List[ADComputer]) -> None:
        """Build attack graph from AD objects"""
        # Add user -> group edges
        for user in users:
            user_node = f"USER:{user.sam_account_name}"
            self.graph[user_node] = []
            
            for group_name in user.member_of:
                self.graph[user_node].append({
                    "target": f"GROUP:{group_name}",
                    "relation": "MemberOf",
                    "technique": None
                })
        
        # Add group -> group edges (nested groups)
        for group in groups:
            group_node = f"GROUP:{group.sam_account_name}"
            if group_node not in self.graph:
                self.graph[group_node] = []
            
            for member_of in group.member_of:
                self.graph[group_node].append({
                    "target": f"GROUP:{member_of}",
                    "relation": "MemberOf",
                    "technique": None
                })
        
        # Add computer -> admin edges
        for computer in computers:
            comp_node = f"COMPUTER:{computer.sam_account_name}"
            if comp_node not in self.graph:
                self.graph[comp_node] = []
            
            for admin in computer.local_admins:
                self.graph[comp_node].append({
                    "target": f"USER:{admin}",
                    "relation": "AdminTo",
                    "technique": AttackTechnique.PASS_THE_HASH
                })
    
    def find_path_to_da(self, start_user: str) -> Optional[AttackPath]:
        """Find shortest path from user to Domain Admin"""
        start_node = f"USER:{start_user}"
        target_node = "GROUP:Domain Admins"
        
        # BFS to find shortest path
        visited = set()
        queue = [(start_node, [])]
        
        while queue:
            current, path = queue.pop(0)
            
            if current == target_node:
                return AttackPath(
                    source=start_user,
                    target="Domain Admins",
                    path=path,
                    techniques=self._extract_techniques(path),
                    complexity=self._calculate_complexity(path)
                )
            
            if current in visited:
                continue
            
            visited.add(current)
            
            for edge in self.graph.get(current, []):
                new_path = path + [{
                    "from": current,
                    "to": edge["target"],
                    "relation": edge["relation"]
                }]
                queue.append((edge["target"], new_path))
        
        return None
    
    def _extract_techniques(self, path: List[Dict]) -> List[AttackTechnique]:
        """Extract attack techniques from path"""
        techniques = []
        for edge in path:
            if edge.get("technique"):
                techniques.append(edge["technique"])
        return techniques
    
    def _calculate_complexity(self, path: List[Dict]) -> str:
        """Calculate path complexity"""
        length = len(path)
        if length <= 2:
            return "low"
        elif length <= 4:
            return "medium"
        else:
            return "high"


class ADEnumerator:
    """Main Active Directory enumeration engine"""
    
    def __init__(self, dc_ip: str, domain: str, username: str = "", password: str = ""):
        self.ldap = LDAPClient(dc_ip, domain, username, password)
        self.ingestor = BloodHoundIngestor(self.ldap)
        self.gpo_analyzer = GPOAnalyzer()
        self.path_finder = AttackPathFinder()
        
        self.users: List[ADUser] = []
        self.groups: List[ADGroup] = []
        self.computers: List[ADComputer] = []
        self.gpos: List[GPOInfo] = []
    
    async def enumerate_all(self) -> Dict:
        """Perform full AD enumeration"""
        results = {
            "domain": self.ldap.domain,
            "dc_ip": self.ldap.dc_ip,
            "enumeration_time": datetime.now().isoformat(),
            "statistics": {},
            "high_value_targets": [],
            "attack_paths": [],
            "vulnerabilities": [],
            "gpo_issues": []
        }
        
        # Connect to DC
        if not await self.ldap.connect():
            results["error"] = "Failed to connect to Domain Controller"
            return results
        
        # Enumerate objects
        self.users = await self.ldap.enumerate_users()
        self.groups = await self.ldap.enumerate_groups()
        self.computers = await self.ldap.enumerate_computers()
        self.gpos = await self.ldap.enumerate_gpos()
        
        results["statistics"] = {
            "users": len(self.users),
            "groups": len(self.groups),
            "computers": len(self.computers),
            "gpos": len(self.gpos)
        }
        
        # Find high-value targets
        results["high_value_targets"] = self._find_high_value_targets()
        
        # Find attack paths
        self.path_finder.build_graph(self.users, self.groups, self.computers)
        
        for user in self.users:
            if user.admin_count == 0:  # Non-admin users
                path = self.path_finder.find_path_to_da(user.sam_account_name)
                if path:
                    results["attack_paths"].append(path.to_dict())
        
        # Find vulnerabilities
        results["vulnerabilities"] = await self._find_vulnerabilities()
        
        # Analyze GPOs
        for gpo in self.gpos:
            issues = self.gpo_analyzer.analyze_gpo_permissions(gpo)
            results["gpo_issues"].extend(issues)
        
        return results
    
    def _find_high_value_targets(self) -> List[Dict]:
        """Identify high-value targets"""
        targets = []
        
        # Domain Admins
        for user in self.users:
            if "Domain Admins" in user.member_of:
                targets.append({
                    "type": "user",
                    "name": user.sam_account_name,
                    "reason": "Domain Admin",
                    "priority": "critical"
                })
        
        # Domain Controllers
        for computer in self.computers:
            if "Domain Controllers" in computer.distinguished_name:
                targets.append({
                    "type": "computer",
                    "name": computer.sam_account_name,
                    "reason": "Domain Controller",
                    "priority": "critical"
                })
        
        return targets
    
    async def _find_vulnerabilities(self) -> List[Dict]:
        """Find AD-related vulnerabilities"""
        vulns = []
        
        # Kerberoastable users
        kerberoastable = await self.ldap.find_kerberoastable_users(self.users)
        for user in kerberoastable:
            vulns.append({
                "type": AttackTechnique.KERBEROASTING.value,
                "target": user.sam_account_name,
                "spn": user.spn,
                "risk": "high",
                "description": "User has SPN set, vulnerable to Kerberoasting"
            })
        
        # ASREP Roastable users
        asrep = await self.ldap.find_asrep_roastable_users(self.users)
        for user in asrep:
            vulns.append({
                "type": AttackTechnique.ASREP_ROASTING.value,
                "target": user.sam_account_name,
                "risk": "high",
                "description": "User does not require Kerberos pre-authentication"
            })
        
        # Delegation issues
        delegation_issues = await self.ldap.find_delegation_abuse(self.computers)
        vulns.extend(delegation_issues)
        
        return vulns
    
    async def export_bloodhound(self, output_dir: str) -> List[str]:
        """Export data in BloodHound format"""
        await self.ingestor.collect_all()
        return self.ingestor.export_json(output_dir)


# Global instance
_enumerator: Optional[ADEnumerator] = None


def get_enumerator(dc_ip: str, domain: str, 
                   username: str = "", password: str = "") -> ADEnumerator:
    """Get AD enumerator instance"""
    global _enumerator
    _enumerator = ADEnumerator(dc_ip, domain, username, password)
    return _enumerator


async def quick_enum(dc_ip: str, domain: str) -> Dict:
    """Quick AD enumeration"""
    enum = get_enumerator(dc_ip, domain)
    return await enum.enumerate_all()
