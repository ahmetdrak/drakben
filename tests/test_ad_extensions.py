# tests/test_ad_extensions.py
# Test suite for modules/ad_extensions.py
"""Tests for AD Extensions module - BloodHound integration & Token Impersonation."""

from modules.ad_extensions import (
    AttackChain,
    BloodHoundAnalyzer,
    BloodHoundEdge,
    BloodHoundNode,
    BloodHoundRelationship,
    ImpacketTool,
    TokenInfo,
    TokenPrivilege,
)

# =============================================================================
# Enum Tests
# =============================================================================


class TestBloodHoundRelationship:
    """Tests for BloodHoundRelationship enum."""

    def test_member_of(self) -> None:
        """Test MemberOf relationship."""
        rel = BloodHoundRelationship.MEMBER_OF
        assert rel.value == "MemberOf"

    def test_admin_to(self) -> None:
        """Test AdminTo relationship."""
        rel = BloodHoundRelationship.ADMIN_TO
        assert rel.value == "AdminTo"

    def test_dcsync(self) -> None:
        """Test DCSync relationship."""
        rel = BloodHoundRelationship.DCSYNC
        assert rel.value == "DCSync"

    def test_all_relationships_have_values(self) -> None:
        """Test all relationships have string values."""
        for rel in BloodHoundRelationship:
            assert isinstance(rel.value, str)
            assert len(rel.value) > 0


class TestImpacketTool:
    """Tests for ImpacketTool enum."""

    def test_psexec(self) -> None:
        """Test psexec tool."""
        tool = ImpacketTool.PSEXEC
        assert tool.value == "psexec.py"

    def test_secretsdump(self) -> None:
        """Test secretsdump tool."""
        tool = ImpacketTool.SECRETSDUMP
        assert tool.value == "secretsdump.py"

    def test_all_tools_are_python_scripts(self) -> None:
        """Test all tools end with .py."""
        for tool in ImpacketTool:
            assert tool.value.endswith(".py")


class TestTokenPrivilege:
    """Tests for TokenPrivilege enum."""

    def test_debug_privilege(self) -> None:
        """Test SeDebugPrivilege."""
        priv = TokenPrivilege.DEBUG
        assert priv.value == "SeDebugPrivilege"

    def test_impersonate_privilege(self) -> None:
        """Test SeImpersonatePrivilege."""
        priv = TokenPrivilege.IMPERSONATE
        assert priv.value == "SeImpersonatePrivilege"


# =============================================================================
# BloodHoundNode Tests
# =============================================================================


class TestBloodHoundNode:
    """Tests for BloodHoundNode dataclass."""

    def test_creation_basic(self) -> None:
        """Test basic creation."""
        node = BloodHoundNode(
            object_id="S-1-5-21-123-456-789-1001",
            name="ADMIN@DOMAIN.COM",
            node_type="User",
        )
        assert node.object_id == "S-1-5-21-123-456-789-1001"
        assert node.name == "ADMIN@DOMAIN.COM"
        assert node.node_type == "User"
        assert node.enabled is True
        assert node.admin_count is False
        assert node.high_value is False
        assert node.owned is False

    def test_creation_with_properties(self) -> None:
        """Test creation with properties."""
        node = BloodHoundNode(
            object_id="S-1-5-21-123-456-789-1002",
            name="DC01.DOMAIN.COM",
            node_type="Computer",
            properties={"os": "Windows Server 2019"},
            high_value=True,
        )
        assert node.properties["os"] == "Windows Server 2019"
        assert node.high_value is True

    def test_to_dict(self) -> None:
        """Test dictionary conversion."""
        node = BloodHoundNode(
            object_id="S-1-5-21-123-456-789-1003",
            name="DOMAIN ADMINS@DOMAIN.COM",
            node_type="Group",
            admin_count=True,
            high_value=True,
        )
        d = node.to_dict()
        assert d["ObjectId"] == "S-1-5-21-123-456-789-1003"
        assert d["Name"] == "DOMAIN ADMINS@DOMAIN.COM"
        assert d["Type"] == "Group"
        assert d["AdminCount"] is True
        assert d["HighValue"] is True


# =============================================================================
# BloodHoundEdge Tests
# =============================================================================


class TestBloodHoundEdge:
    """Tests for BloodHoundEdge dataclass."""

    def test_creation(self) -> None:
        """Test edge creation."""
        edge = BloodHoundEdge(
            source="S-1-5-21-123-456-789-1001",
            target="S-1-5-21-123-456-789-512",
            relationship=BloodHoundRelationship.MEMBER_OF,
        )
        assert edge.source == "S-1-5-21-123-456-789-1001"
        assert edge.target == "S-1-5-21-123-456-789-512"
        assert edge.relationship == BloodHoundRelationship.MEMBER_OF

    def test_to_dict(self) -> None:
        """Test dictionary conversion."""
        edge = BloodHoundEdge(
            source="source-sid",
            target="target-sid",
            relationship=BloodHoundRelationship.ADMIN_TO,
            properties={"via": "local admin"},
        )
        d = edge.to_dict()
        assert d["Source"] == "source-sid"
        assert d["Target"] == "target-sid"
        assert d["Relationship"] == "AdminTo"
        assert d["Properties"]["via"] == "local admin"


# =============================================================================
# AttackChain Tests
# =============================================================================


class TestAttackChain:
    """Tests for AttackChain dataclass."""

    def test_creation(self) -> None:
        """Test attack chain creation."""
        source = BloodHoundNode("src", "USER@DOMAIN", "User")
        target = BloodHoundNode("tgt", "ADMIN@DOMAIN", "User", high_value=True)
        edge = BloodHoundEdge("src", "tgt", BloodHoundRelationship.ADMIN_TO)

        chain = AttackChain(
            source=source,
            target=target,
            edges=[edge],
            cost=1.0,
            techniques=["local_admin"],
        )
        assert chain.source == source
        assert chain.target == target
        assert len(chain.edges) == 1
        assert abs(chain.cost - 1.0) < 0.001  # Use epsilon comparison

    def test_len(self) -> None:
        """Test chain length."""
        source = BloodHoundNode("src", "USER@DOMAIN", "User")
        target = BloodHoundNode("tgt", "ADMIN@DOMAIN", "User")
        edges = [
            BloodHoundEdge("src", "mid", BloodHoundRelationship.MEMBER_OF),
            BloodHoundEdge("mid", "tgt", BloodHoundRelationship.ADMIN_TO),
        ]

        chain = AttackChain(source, target, edges, 2.0, ["member", "admin"])
        assert len(chain) == 2


# =============================================================================
# TokenInfo Tests
# =============================================================================


class TestTokenInfo:
    """Tests for TokenInfo dataclass."""

    def test_creation(self) -> None:
        """Test token info creation."""
        token = TokenInfo(
            username="admin",
            domain="CORP",
            sid="S-1-5-21-123-456-789-500",
            privileges=[TokenPrivilege.DEBUG, TokenPrivilege.IMPERSONATE],
            groups=["Domain Admins", "Administrators"],
            impersonation_level="SecurityDelegation",
            is_elevated=True,
        )
        assert token.username == "admin"
        assert token.domain == "CORP"
        assert TokenPrivilege.DEBUG in token.privileges
        assert len(token.groups) == 2
        assert token.is_elevated is True


# =============================================================================
# BloodHoundAnalyzer Tests
# =============================================================================


class TestBloodHoundAnalyzer:
    """Tests for BloodHoundAnalyzer class."""

    def test_init(self) -> None:
        """Test initialization."""
        analyzer = BloodHoundAnalyzer()
        assert len(analyzer.nodes) == 0
        assert len(analyzer.edges) == 0

    def test_add_node(self) -> None:
        """Test adding nodes."""
        analyzer = BloodHoundAnalyzer()
        node = BloodHoundNode("sid1", "USER1@DOMAIN", "User")
        analyzer.add_node(node)
        assert "sid1" in analyzer.nodes
        assert analyzer.nodes["sid1"] == node

    def test_add_edge(self) -> None:
        """Test adding edges."""
        analyzer = BloodHoundAnalyzer()
        edge = BloodHoundEdge("src", "tgt", BloodHoundRelationship.MEMBER_OF)
        analyzer.add_edge(edge)
        assert len(analyzer.edges) == 1
        assert "src" in analyzer._adjacency

    def test_add_user(self) -> None:
        """Test add_user helper."""
        analyzer = BloodHoundAnalyzer()
        node = analyzer.add_user(
            sid="S-1-5-21-123-456-789-1001",
            username="jsmith",
            domain="CORP.LOCAL",
            enabled=True,
            admin_count=True,
        )
        assert node.node_type == "User"
        assert node.name == "JSMITH@CORP.LOCAL"
        assert node.admin_count is True
        assert node.object_id in analyzer.nodes

    def test_add_computer(self) -> None:
        """Test add_computer helper."""
        analyzer = BloodHoundAnalyzer()
        node = analyzer.add_computer(
            sid="S-1-5-21-123-456-789-1002",
            hostname="DC01",
            domain="CORP.LOCAL",
            os="Windows Server 2019",
            high_value=True,
        )
        assert node.node_type == "Computer"
        assert "DC01" in node.name
        assert node.high_value is True

    def test_add_group(self) -> None:
        """Test add_group helper."""
        analyzer = BloodHoundAnalyzer()
        node = analyzer.add_group(
            sid="S-1-5-21-123-456-789-512",
            name="Domain Admins",
            domain="CORP.LOCAL",
            high_value=True,
        )
        assert node.node_type == "Group"
        assert node.high_value is True

    def test_graph_building(self) -> None:
        """Test building a simple graph."""
        analyzer = BloodHoundAnalyzer()

        # Add users (results used implicitly in graph)
        analyzer.add_user("sid1", "user1", "DOMAIN")
        analyzer.add_user("sid2", "user2", "DOMAIN", admin_count=True)

        # Add group
        analyzer.add_group("sid3", "Administrators", "DOMAIN", high_value=True)

        # Add edges
        analyzer.add_edge(BloodHoundEdge("sid1", "sid2", BloodHoundRelationship.HAS_SESSION))
        analyzer.add_edge(BloodHoundEdge("sid2", "sid3", BloodHoundRelationship.MEMBER_OF))

        assert len(analyzer.nodes) == 3
        assert len(analyzer.edges) == 2
        assert len(analyzer._adjacency["sid1"]) == 1
        assert len(analyzer._adjacency["sid2"]) == 1


# =============================================================================
# Attack Path Tests
# =============================================================================


class TestAttackPaths:
    """Tests for attack path finding."""

    def test_simple_path(self) -> None:
        """Test finding simple attack path."""
        analyzer = BloodHoundAnalyzer()

        # Build graph (nodes used implicitly in graph structure)
        analyzer.add_user("user-sid", "compromised_user", "DOMAIN")
        analyzer.add_user("admin-sid", "domain_admin", "DOMAIN", high_value=True)

        analyzer.add_edge(
            BloodHoundEdge(
                "user-sid",
                "admin-sid",
                BloodHoundRelationship.ADMIN_TO,
            )
        )

        # Verify graph structure
        assert len(analyzer._adjacency["user-sid"]) == 1
        edge = analyzer._adjacency["user-sid"][0]
        assert edge.target == "admin-sid"

    def test_multi_hop_path(self) -> None:
        """Test multi-hop attack path."""
        analyzer = BloodHoundAnalyzer()

        # Create chain: user1 -> group1 -> group2 -> admin
        analyzer.add_user("u1", "user1", "D")
        analyzer.add_group("g1", "Group1", "D")
        analyzer.add_group("g2", "Group2", "D")
        analyzer.add_user("admin", "admin", "D", high_value=True)

        analyzer.add_edge(BloodHoundEdge("u1", "g1", BloodHoundRelationship.MEMBER_OF))
        analyzer.add_edge(BloodHoundEdge("g1", "g2", BloodHoundRelationship.MEMBER_OF))
        analyzer.add_edge(BloodHoundEdge("g2", "admin", BloodHoundRelationship.ADMIN_TO))

        assert len(analyzer.edges) == 3


# =============================================================================
# Impacket Integration Tests (Mocked)
# =============================================================================


class TestImpacketIntegration:
    """Tests for Impacket tool integration."""

    def test_impacket_tool_commands(self) -> None:
        """Test Impacket tool command templates."""
        # All Impacket tools should be .py scripts
        for tool in ImpacketTool:
            assert tool.value.endswith(".py")

    def test_secretsdump_command(self) -> None:
        """Test secretsdump command construction."""
        target = "192.168.1.10"
        domain = "CORP.LOCAL"
        user = "admin"
        password = "password123"

        # Command template
        cmd = f"{ImpacketTool.SECRETSDUMP.value} {domain}/{user}:{password}@{target}"
        assert "secretsdump.py" in cmd
        assert domain in cmd
        assert target in cmd

    def test_psexec_command(self) -> None:
        """Test psexec command construction."""
        target = "dc01.corp.local"
        cmd = f"{ImpacketTool.PSEXEC.value} CORP/admin@{target}"
        assert "psexec.py" in cmd
        assert target in cmd
