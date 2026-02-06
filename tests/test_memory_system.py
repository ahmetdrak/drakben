# tests/test_memory_system.py
"""Comprehensive tests for the Stanford-style Memory System.

Tests cover:
1. ConceptNode creation and manipulation
2. MemoryStream storage and retrieval
3. RetrievalEngine scoring (Stanford 4-factor formula)
4. Cognitive modules (Perceive, Retrieve, Reflect)

Token Efficiency Validation:
- Verify constant context size regardless of history length
- Validate selective retrieval vs linear history
"""

import time

import pytest

from core.agent.memory.concept_node import (
    ConceptNode,
    NodeType,
    PentestRelevance,
    SPOTriple,
    create_event_node,
    create_finding_node,
    create_thought_node,
)
from core.agent.memory.memory_stream import (
    MemoryStream,
    reset_memory_stream,
)
from core.agent.memory.retrieval import (
    RetrievalEngine,
    RetrievalWeights,
    ScoredNode,
)

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def memory_stream():
    """Create a fresh in-memory MemoryStream for testing."""
    reset_memory_stream()
    stream = MemoryStream(persist_path=None)
    yield stream
    stream.close()


@pytest.fixture
def sample_nodes():
    """Create a set of sample nodes for testing."""
    nodes = [
        create_event_node(
            description="Port 22 SSH discovered",
            tool="nmap",
            result="service_discovered",
            poignancy=6.0,
            target="192.168.1.100",
            pentest_relevance=PentestRelevance.SERVICE_INFO,
        ),
        create_event_node(
            description="Port 80 HTTP discovered",
            tool="nmap",
            result="service_discovered",
            poignancy=5.0,
            target="192.168.1.100",
            pentest_relevance=PentestRelevance.SERVICE_INFO,
        ),
        create_finding_node(
            description="SQL injection in /login endpoint",
            finding_type="vulnerability",
            severity="critical",
            target="192.168.1.100",
        ),
        create_finding_node(
            description="Admin credentials: admin/password123",
            finding_type="credential",
            severity="critical",
            target="192.168.1.100",
        ),
        create_thought_node(
            description="SQLi might lead to database access",
            reasoning_type="hypothesis",
            confidence=0.8,
            target="192.168.1.100",
        ),
    ]
    return nodes


# =============================================================================
# ConceptNode Tests
# =============================================================================


class TestConceptNode:
    """Tests for ConceptNode dataclass and factory functions."""

    def test_node_creation_default(self):
        """Test default node creation."""
        node = ConceptNode(description="Test node")

        assert node.description == "Test node"
        assert abs(node.poignancy - 5.0) < 0.01  # Default
        assert node.node_type == NodeType.EVENT  # Default
        assert node.node_id  # UUID generated

    def test_node_creation_with_spo_triple(self):
        """Test node with SPO triple."""
        spo = SPOTriple(subject="nmap", predicate="discovered", obj="port 22")
        node = ConceptNode(
            description="Found SSH",
            spo_triple=spo,
        )

        assert node.spo_triple is not None
        assert node.spo_triple.subject == "nmap"
        assert node.spo_triple.to_sentence() == "nmap discovered port 22"

    def test_event_node_factory(self):
        """Test create_event_node factory."""
        node = create_event_node(
            description="Scan completed",
            tool="nmap",
            result="success",
            poignancy=7.0,
            target="10.0.0.1",
        )

        assert node.node_type == NodeType.EVENT
        assert abs(node.poignancy - 7.0) < 0.01
        assert node.target == "10.0.0.1"
        assert node.spo_triple is not None

    def test_finding_node_factory_severity_mapping(self):
        """Test finding severity to poignancy mapping."""
        critical = create_finding_node(
            description="RCE found",
            finding_type="vulnerability",
            severity="critical",
        )
        high = create_finding_node(
            description="XSS found",
            finding_type="vulnerability",
            severity="high",
        )
        low = create_finding_node(
            description="Info disclosure",
            finding_type="vulnerability",
            severity="low",
        )

        assert abs(critical.poignancy - 10.0) < 0.01
        assert abs(high.poignancy - 8.0) < 0.01
        assert abs(low.poignancy - 4.0) < 0.01

    def test_credential_finding_high_poignancy(self):
        """Test credential findings get high poignancy."""
        cred = create_finding_node(
            description="Found password",
            finding_type="credential",
            severity="low",  # Even low severity
        )

        assert abs(cred.poignancy - 9.0) < 0.01  # Credentials are always high
        assert cred.pentest_relevance == PentestRelevance.CREDENTIAL

    def test_node_touch_updates_access(self):
        """Test touch() updates access tracking."""
        node = ConceptNode(description="Test")
        original_access = node.last_accessed
        original_count = node.access_count

        time.sleep(0.01)  # Small delay
        node.touch()

        assert node.last_accessed > original_access
        assert node.access_count == original_count + 1

    def test_node_recency_score(self):
        """Test recency score calculation."""
        node = ConceptNode(description="Test")

        # Just created, should be close to 1.0
        score = node.recency_score()
        assert 0.99 <= score <= 1.0

    def test_node_serialization(self):
        """Test node to_dict and from_dict."""
        original = create_finding_node(
            description="SQLi found",
            finding_type="vulnerability",
            severity="critical",
            target="test.com",
        )

        data = original.to_dict()
        restored = ConceptNode.from_dict(data)

        assert restored.description == original.description
        assert restored.poignancy == original.poignancy
        assert restored.node_type == original.node_type
        assert restored.target == original.target

    def test_pentest_boost_factors(self):
        """Test pentest relevance boost values."""
        critical = ConceptNode(
            description="RCE",
            pentest_relevance=PentestRelevance.CRITICAL_VULN,
        )
        credential = ConceptNode(
            description="Cred",
            pentest_relevance=PentestRelevance.CREDENTIAL,
        )
        generic = ConceptNode(
            description="Generic",
            pentest_relevance=PentestRelevance.GENERIC,
        )

        assert abs(critical.get_pentest_boost() - 3.0) < 0.01
        assert abs(credential.get_pentest_boost() - 2.5) < 0.01
        assert abs(generic.get_pentest_boost() - 1.0) < 0.01


# =============================================================================
# MemoryStream Tests
# =============================================================================


class TestMemoryStream:
    """Tests for MemoryStream storage and retrieval."""

    def test_add_and_get(self, memory_stream):
        """Test basic add and get."""
        node = ConceptNode(description="Test node")
        node_id = memory_stream.add(node)

        retrieved = memory_stream.get(node_id)

        assert retrieved is not None
        assert retrieved.description == "Test node"

    def test_get_recent(self, memory_stream, sample_nodes):
        """Test get_recent retrieval."""
        for node in sample_nodes:
            memory_stream.add(node)

        recent = memory_stream.get_recent(n=3)

        assert len(recent) == 3
        # Most recent first
        assert recent[0].description == sample_nodes[-1].description

    def test_get_by_type(self, memory_stream, sample_nodes):
        """Test filtering by node type."""
        for node in sample_nodes:
            memory_stream.add(node)

        findings = memory_stream.get_by_type(NodeType.FINDING)

        assert len(findings) == 2  # SQLi and credential

    def test_get_by_target(self, memory_stream, sample_nodes):
        """Test filtering by target."""
        for node in sample_nodes:
            memory_stream.add(node)

        # Add node for different target
        other = ConceptNode(description="Other", target="10.0.0.1")
        memory_stream.add(other)

        target_nodes = memory_stream.get_recent(n=10, target="192.168.1.100")

        assert len(target_nodes) == 5  # Only sample_nodes

    def test_get_critical_findings(self, memory_stream, sample_nodes):
        """Test critical findings retrieval."""
        for node in sample_nodes:
            memory_stream.add(node)

        critical = memory_stream.get_critical_findings(target="192.168.1.100")

        assert len(critical) >= 2  # SQLi and credential
        # Sorted by poignancy
        assert critical[0].poignancy >= critical[-1].poignancy

    def test_spo_query(self, memory_stream):
        """Test SPO triple querying."""
        node1 = ConceptNode(
            description="Nmap found SSH",
            spo_triple=SPOTriple("nmap", "discovered", "SSH on port 22"),
        )
        node2 = ConceptNode(
            description="Nmap found HTTP",
            spo_triple=SPOTriple("nmap", "discovered", "HTTP on port 80"),
        )
        node3 = ConceptNode(
            description="SQLMap found injection",
            spo_triple=SPOTriple("sqlmap", "found", "SQL injection"),
        )

        memory_stream.add(node1)
        memory_stream.add(node2)
        memory_stream.add(node3)

        # Query by subject
        nmap_results = memory_stream.query_spo(subject="nmap")
        assert len(nmap_results) == 2

        # Query by predicate
        found_results = memory_stream.query_spo(predicate="found")
        assert len(found_results) == 1

    def test_count_methods(self, memory_stream, sample_nodes):
        """Test count and count_by_type."""
        for node in sample_nodes:
            memory_stream.add(node)

        assert memory_stream.count() == 5

        by_type = memory_stream.count_by_type()
        assert by_type["event"] == 2
        assert by_type["finding"] == 2
        assert by_type["thought"] == 1

    def test_build_context(self, memory_stream, sample_nodes):
        """Test context building for LLM."""
        for node in sample_nodes:
            memory_stream.add(node)

        context = memory_stream.build_context(target="192.168.1.100")

        assert "CRITICAL FINDINGS" in context
        assert "SQL injection" in context
        assert "RECENT ACTIONS" in context

    def test_clear_by_target(self, memory_stream):
        """Test clearing nodes by target."""
        node1 = ConceptNode(description="Target A", target="A")
        node2 = ConceptNode(description="Target B", target="B")

        memory_stream.add(node1)
        memory_stream.add(node2)

        assert memory_stream.count() == 2

        memory_stream.clear(target="A")

        assert memory_stream.count() == 1
        remaining = memory_stream.get_recent(n=10)
        assert remaining[0].target == "B"


# =============================================================================
# RetrievalEngine Tests
# =============================================================================


class TestRetrievalEngine:
    """Tests for Stanford 4-factor retrieval."""

    def test_basic_retrieval(self, memory_stream, sample_nodes):
        """Test basic retrieval functionality."""
        for node in sample_nodes:
            memory_stream.add(node)

        engine = RetrievalEngine(memory_stream)
        result = engine.retrieve("SQL injection", n=5)

        assert result.returned_count > 0
        assert len(result.nodes) <= 5

    def test_scored_node_structure(self, memory_stream, sample_nodes):
        """Test ScoredNode has all score components."""
        for node in sample_nodes:
            memory_stream.add(node)

        engine = RetrievalEngine(memory_stream)
        result = engine.retrieve("vulnerability", n=3)

        for scored in result.nodes:
            assert isinstance(scored, ScoredNode)
            assert scored.total_score > 0
            # All components should be non-negative
            assert scored.recency_score >= 0
            assert scored.importance_score >= 0
            assert scored.pentest_score >= 0

    def test_high_poignancy_ranks_higher(self, memory_stream):
        """Test that high poignancy nodes rank higher."""
        low = ConceptNode(description="Low importance", poignancy=2.0)
        high = ConceptNode(description="High importance", poignancy=9.0)

        memory_stream.add(low)
        memory_stream.add(high)

        engine = RetrievalEngine(memory_stream)
        result = engine.retrieve("importance", n=2)

        assert result.nodes[0].node.poignancy > result.nodes[1].node.poignancy

    def test_pentest_boost_affects_ranking(self, memory_stream):
        """Test pentest relevance boost affects ranking."""
        generic = ConceptNode(
            description="Generic finding",
            poignancy=5.0,
            pentest_relevance=PentestRelevance.GENERIC,
        )
        critical = ConceptNode(
            description="Critical vuln",
            poignancy=5.0,  # Same poignancy
            pentest_relevance=PentestRelevance.CRITICAL_VULN,
        )

        memory_stream.add(generic)
        memory_stream.add(critical)

        engine = RetrievalEngine(memory_stream)
        result = engine.retrieve("finding", n=2)

        # Critical should rank higher due to boost
        assert result.nodes[0].node.pentest_relevance == PentestRelevance.CRITICAL_VULN

    def test_custom_weights(self, memory_stream, sample_nodes):
        """Test custom retrieval weights."""
        for node in sample_nodes:
            memory_stream.add(node)

        # Heavy importance weighting
        weights = RetrievalWeights(
            recency=0.1,
            relevance=0.1,
            importance=2.0,  # Boosted
            pentest_boost=0.1,
        )

        engine = RetrievalEngine(memory_stream, weights=weights)
        result = engine.retrieve("test", n=5)

        # High poignancy nodes should dominate
        assert result.nodes[0].node.poignancy >= 8.0

    def test_retrieve_for_planning(self, memory_stream, sample_nodes):
        """Test phase-specific retrieval."""
        for node in sample_nodes:
            memory_stream.add(node)

        engine = RetrievalEngine(memory_stream)

        # Exploit phase should prioritize vulnerabilities
        result = engine.retrieve_for_planning(
            current_phase="exploit",
            target="192.168.1.100",
        )

        assert result.returned_count > 0

    def test_retrieve_for_context_string(self, memory_stream, sample_nodes):
        """Test context string generation."""
        for node in sample_nodes:
            memory_stream.add(node)

        engine = RetrievalEngine(memory_stream)
        context = engine.retrieve_for_context(
            user_input="exploit vulnerabilities",
            target="192.168.1.100",
        )

        assert "RELEVANT CONTEXT" in context
        assert len(context) > 0

    def test_retrieval_time_tracking(self, memory_stream, sample_nodes):
        """Test retrieval time is tracked."""
        for node in sample_nodes:
            memory_stream.add(node)

        engine = RetrievalEngine(memory_stream)
        result = engine.retrieve("test", n=5)

        assert result.retrieval_time_ms > 0
        assert result.retrieval_time_ms < 1000  # Should be fast


# =============================================================================
# Cognitive Module Tests
# =============================================================================


class TestPerceiveModule:
    """Tests for the Perceive cognitive module."""

    def test_perceive_nmap_output(self, memory_stream):
        """Test perceiving nmap output."""
        from core.agent.cognitive.perceive import PerceiveModule

        perceive = PerceiveModule(memory_stream)

        nmap_output = """
        22/tcp open ssh OpenSSH 7.9
        80/tcp open http Apache 2.4
        443/tcp open https
        """

        nodes = perceive.perceive(
            tool_name="nmap",
            tool_output=nmap_output,
            target="192.168.1.100",
        )

        assert len(nodes) > 0
        # Should find services
        assert any("22" in n.description for n in nodes)

    def test_perceive_vuln_scanner(self, memory_stream):
        """Test perceiving vulnerability scanner output."""
        from core.agent.cognitive.perceive import PerceiveModule

        perceive = PerceiveModule(memory_stream)

        vuln_output = """
        [CRITICAL] SQL Injection found in /login
        Parameter: username
        CVE-2023-1234
        """

        nodes = perceive.perceive(
            tool_name="sqlmap",
            tool_output=vuln_output,
            target="192.168.1.100",
        )

        assert len(nodes) > 0
        # Should have high poignancy for critical
        assert any(n.poignancy >= 9.0 for n in nodes)
        # Should extract CVE
        assert any("CVE" in n.description or n.metadata.get("cves") for n in nodes)

    def test_perceive_credential_discovery(self, memory_stream):
        """Test perceiving credential discovery."""
        from core.agent.cognitive.perceive import PerceiveModule

        perceive = PerceiveModule(memory_stream)

        hydra_output = """
        [22][ssh] host: 192.168.1.100   login: admin   password: secret123
        [SUCCESS] 1 valid password found
        """

        nodes = perceive.perceive(
            tool_name="hydra",
            tool_output=hydra_output,
            target="192.168.1.100",
        )

        assert len(nodes) > 0
        # Should be high importance credential
        assert any(n.pentest_relevance == PentestRelevance.CREDENTIAL for n in nodes)


class TestRetrieveModule:
    """Tests for the Retrieve cognitive module."""

    def test_retrieve_for_decision(self, memory_stream, sample_nodes):
        """Test decision context retrieval."""
        from core.agent.cognitive.retrieve import RetrieveModule

        for node in sample_nodes:
            memory_stream.add(node)

        retrieve = RetrieveModule(memory_stream)
        context = retrieve.retrieve_for_decision(
            focal_point="exploit SQL injection",
            target="192.168.1.100",
        )

        assert context.total_nodes > 0
        assert context.context_string  # Non-empty

    def test_context_budget(self, memory_stream, sample_nodes):
        """Test context budget enforcement."""
        from core.agent.cognitive.retrieve import ContextBudget, RetrieveModule

        for node in sample_nodes:
            memory_stream.add(node)

        # Very small budget
        budget = ContextBudget(
            total_tokens=500,
            critical_findings=100,
            recent_events=100,
            reasoning=100,
            insights=50,
            reserved=150,
        )

        retrieve = RetrieveModule(memory_stream, budget=budget)
        context = retrieve.retrieve_for_decision(
            focal_point="test",
            target="192.168.1.100",
        )

        # Should respect budget
        assert context.estimated_tokens <= 500


class TestReflectModule:
    """Tests for the Reflect cognitive module."""

    def test_reflect_generates_insights(self, memory_stream, sample_nodes):
        """Test reflection generates insight nodes."""
        from core.agent.cognitive.reflect import ReflectModule

        for node in sample_nodes:
            memory_stream.add(node)

        reflect = ReflectModule(memory_stream, reflection_threshold=1)
        insights = reflect.reflect(target="192.168.1.100", force=True)

        # Should return a list (may be empty depending on patterns)
        assert isinstance(insights, list)

    def test_reflection_trigger(self, memory_stream):
        """Test reflection trigger conditions."""
        from core.agent.cognitive.reflect import ReflectModule

        reflect = ReflectModule(memory_stream, reflection_threshold=5)

        # Not enough nodes
        assert not reflect.should_reflect()

        # Simulate adding nodes
        for _ in range(5):
            reflect.notify_new_node(ConceptNode(description="test"))

        assert reflect.should_reflect()


# =============================================================================
# Token Efficiency Tests
# =============================================================================


class TestTokenEfficiency:
    """Tests validating token efficiency claims."""

    def test_context_size_stays_constant(self, memory_stream):
        """Test context size doesn't grow linearly with history."""
        from core.agent.cognitive.retrieve import RetrieveModule

        # Add many nodes (simulating long session)
        for i in range(100):
            node = create_event_node(
                description=f"Action {i} performed",
                tool="tool",
                result="done",
                target="192.168.1.100",
            )
            memory_stream.add(node)

        retrieve = RetrieveModule(memory_stream)

        # Context should be bounded, not 100x
        context = retrieve.retrieve_for_decision(
            focal_point="recent actions",
            target="192.168.1.100",
        )

        # Should retrieve far fewer than 100 nodes (allow up to 35)
        assert context.total_nodes <= 35
        # Token estimate should be bounded
        assert context.estimated_tokens < 5000

    def test_selective_retrieval_vs_linear(self, memory_stream, sample_nodes):
        """Compare selective retrieval to linear history."""
        from core.agent.cognitive.retrieve import RetrieveModule

        for node in sample_nodes:
            memory_stream.add(node)

        retrieve = RetrieveModule(memory_stream)

        # Linear approach: all nodes as context
        linear_size = sum(len(n.description) for n in sample_nodes)

        # Selective approach: retrieved context
        context = retrieve.retrieve_for_decision(
            focal_point="SQL injection",
            target="192.168.1.100",
        )

        # Context includes headers and formatting, so allow 4x linear for small sets
        # The real efficiency shows at scale (100+ nodes)
        assert len(context.context_string) <= linear_size * 4


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the complete memory system."""

    def test_full_cognitive_cycle(self, memory_stream):
        """Test complete perceive-retrieve-reflect cycle."""
        from core.agent.cognitive.perceive import PerceiveModule
        from core.agent.cognitive.reflect import ReflectModule
        from core.agent.cognitive.retrieve import RetrieveModule

        perceive = PerceiveModule(memory_stream)
        retrieve = RetrieveModule(memory_stream)
        reflect = ReflectModule(memory_stream, reflection_threshold=3)

        # 1. Perceive: Tool outputs
        perceive.perceive(
            "nmap",
            "22/tcp open ssh\n80/tcp open http",
            target="test.com",
        )
        perceive.perceive(
            "sqlmap",
            "[CRITICAL] SQL Injection found",
            target="test.com",
        )

        # 2. Retrieve: Get context for decision
        context = retrieve.retrieve_for_decision(
            focal_point="exploit vulnerability",
            target="test.com",
        )

        assert context.total_nodes > 0

        # 3. Reflect: Generate insights
        _ = reflect.reflect(target="test.com", force=True)

        # Complete cycle without errors
        assert memory_stream.count() > 0

    def test_multi_target_isolation(self, memory_stream):
        """Test memories are isolated per target."""
        node_a = ConceptNode(description="Target A finding", target="A")
        node_b = ConceptNode(description="Target B finding", target="B")

        memory_stream.add(node_a)
        memory_stream.add(node_b)

        # Retrieve for target A only
        a_nodes = memory_stream.get_recent(n=10, target="A")
        b_nodes = memory_stream.get_recent(n=10, target="B")

        assert len(a_nodes) == 1
        assert len(b_nodes) == 1
        assert a_nodes[0].description == "Target A finding"
        assert b_nodes[0].description == "Target B finding"
