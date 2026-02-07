"""DRAKBEN Advanced AD Extensions - BloodHound Integration & Token Impersonation
Author: @drak_ben
Description: Advanced Active Directory attack features.

This module provides:
- BloodHound-style graph analysis integration
- Impacket native integration support
- Token impersonation techniques
- DCSync attack preparation
- Golden/Silver ticket generation helpers
"""

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
    """BloodHound-style relationship types."""

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
    """Impacket tools for AD attacks."""

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
    """Windows token privileges."""

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
    """BloodHound graph node (User, Computer, Group, etc.)."""

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
    """BloodHound graph edge (relationship)."""

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
    """Chain of attacks from source to target."""

    source: BloodHoundNode
    target: BloodHoundNode
    edges: list[BloodHoundEdge]
    cost: float  # Lower is better
    techniques: list[str]

    def __len__(self) -> int:
        return len(self.edges)


@dataclass
class TokenInfo:
    """Windows token information."""

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
    """BloodHound-style graph analysis for AD attack paths.

    Features:
    - Build attack graph from collected data
    - Find shortest path to high-value targets
    - Identify privilege escalation paths
    - Export to BloodHound compatible format
    """

    def __init__(self) -> None:
        self.nodes: dict[str, BloodHoundNode] = {}
        self.edges: list[BloodHoundEdge] = []
        self._adjacency: dict[str, list[BloodHoundEdge]] = {}

        logger.info("BloodHound analyzer initialized")

    def add_node(self, node: BloodHoundNode) -> None:
        """Add node to the graph."""
        self.nodes[node.object_id] = node
        if node.object_id not in self._adjacency:
            self._adjacency[node.object_id] = []

    def add_edge(self, edge: BloodHoundEdge) -> None:
        """Add edge (relationship) to the graph."""
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
        """Add user node to graph."""
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
        """Add computer node to graph."""
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
        self,
        sid: str,
        name: str,
        domain: str,
        high_value: bool = False,
    ) -> BloodHoundNode:
        """Add group node to graph."""
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

    def find_shortest_path(self, source_id: str, target_id: str) -> AttackChain | None:
        """Find shortest attack path using BFS.

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

        queue: deque[tuple[str, list]] = deque([(source_id, [])])
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
                    queue.append((edge.target, [*path, edge]))

        return None

    def _edge_to_technique(self, edge: BloodHoundEdge) -> str:
        """Convert edge relationship to attack technique description."""
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
        """Get graph statistics."""
        node_types: dict[str, int] = {}
        for node in self.nodes.values():
            node_types[node.node_type] = node_types.get(node.node_type, 0) + 1

        relationship_types: dict[str, int] = {}
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
    """Wrapper for Impacket tools.

    Provides:
    - Command generation for all Impacket tools
    - Output parsing
    - Credential handling
    """

    def __init__(self, impacket_path: str | None = None) -> None:
        """Initialize Impacket wrapper.

        Args:
            impacket_path: Path to impacket scripts (auto-detect if None)

        """
        self.impacket_path = impacket_path or self._find_impacket()
        self.available_tools: list[ImpacketTool] = []

        if self.impacket_path:
            self._check_available_tools()

        logger.info(
            f"Impacket wrapper initialized: {len(self.available_tools)} tools available",
        )

    def _find_impacket(self) -> str | None:
        """Try to find impacket installation."""
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
                ["which", ImpacketTool.PSEXEC.value],
                capture_output=True,
                text=True, check=False,
            )
            if result.returncode == 0:
                return os.path.dirname(result.stdout.strip())
        except Exception as e:
            logger.debug("Failed to find impacket in PATH: %s", e)

        return None

    def _check_available_tools(self) -> None:
        """Check which Impacket tools are available."""
        if self.impacket_path is None:
            return
        for tool in ImpacketTool:
            tool_path = os.path.join(self.impacket_path, tool.value)
            if os.path.exists(tool_path):
                self.available_tools.append(tool)

    def is_available(self, tool: ImpacketTool) -> bool:
        """Check if a specific tool is available."""
        return tool in self.available_tools


# =============================================================================
# TOKEN IMPERSONATION
# =============================================================================


class TokenImpersonator:
    """Windows Token Impersonation techniques.

    Techniques:
    - Token duplication
    - Process token stealing
    - Named pipe impersonation
    - Potato attacks helper
    """

    def __init__(self) -> None:
        self.captured_tokens: list[TokenInfo] = []
        self.current_token: TokenInfo | None = None
        logger.info("Token impersonator initialized")


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================

_impacket_wrapper: ImpacketWrapper | None = None
_token_impersonator: TokenImpersonator | None = None
