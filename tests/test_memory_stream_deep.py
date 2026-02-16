# tests/test_memory_stream_deep.py
"""Deep tests for MemoryStream — persistence, multi-index, eviction, stats.

Covers untested areas for coverage improvement: %54 → %75.
- Persistence layer (SQLite init, persist, load, row_to_node)
- Eviction logic (_evict_oldest_low_importance)
- Semantic search (with mocked VectorStore)
- get_stats, get_by_relevance (direct), full clear
- get_memory_stream/reset_memory_stream singletons
- build_context edge cases (max_tokens, include_types)
- close() behavior
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.agent.memory.concept_node import (
    ConceptNode,
    NodeType,
    PentestRelevance,
    SPOTriple,
)
from core.agent.memory.memory_stream import (
    MemoryStream,
    get_memory_stream,
    reset_memory_stream,
)


# ------------------------------------------------------------------ helpers
def _make_node(
    description: str = "test node",
    poignancy: float = 5.0,
    node_type: NodeType = NodeType.EVENT,
    relevance: PentestRelevance = PentestRelevance.SERVICE_INFO,
    target: str = "10.0.0.1",
    spo: SPOTriple | None = None,
    metadata: dict | None = None,
) -> ConceptNode:
    """Convenience helper to create a ConceptNode with defaults."""
    return ConceptNode(
        description=description,
        poignancy=poignancy,
        node_type=node_type,
        pentest_relevance=relevance,
        target=target,
        spo_triple=spo,
        metadata=metadata or {},
    )


# ================================================================== fixtures
@pytest.fixture
def tmp_db(tmp_path: Path) -> str:
    """Return a temporary SQLite DB path for persistence tests."""
    return str(tmp_path / "test_memory.db")


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Ensure the global singleton is reset before and after each test."""
    reset_memory_stream()
    yield
    reset_memory_stream()


# ================================================================== Persistence
class TestPersistence:
    """Persistence layer: init, save, reload, row_to_node."""

    def test_init_persistence_creates_db(self, tmp_db: str) -> None:
        """_init_persistence should create the SQLite DB file."""
        ms = MemoryStream(persist_path=tmp_db)
        try:
            assert Path(tmp_db).exists()
            assert ms._db_conn is not None
        finally:
            ms.close()

    def test_persist_and_reload(self, tmp_db: str) -> None:
        """Nodes added persist to disk and are reloaded on new instance."""
        # Add nodes
        ms1 = MemoryStream(persist_path=tmp_db)
        node = _make_node(
            description="SSH on port 22",
            poignancy=7.0,
            target="10.0.0.1",
            spo=SPOTriple(subject="10.0.0.1", predicate="has_service", obj="ssh"),
        )
        ms1.add(node)
        assert ms1.count() == 1
        ms1.close()

        # Reopen — should load from DB
        ms2 = MemoryStream(persist_path=tmp_db)
        assert ms2.count() == 1
        reloaded = ms2.get(node.node_id)
        assert reloaded is not None
        assert reloaded.description == "SSH on port 22"
        assert reloaded.poignancy == pytest.approx(7.0)
        assert reloaded.spo_triple is not None
        assert reloaded.spo_triple.subject == "10.0.0.1"
        assert reloaded.spo_triple.predicate == "has_service"
        assert reloaded.spo_triple.obj == "ssh"
        ms2.close()

    def test_persist_node_metadata_roundtrip(self, tmp_db: str) -> None:
        """Metadata and parent_node_ids survive persistence roundtrip."""
        ms1 = MemoryStream(persist_path=tmp_db)
        node = _make_node(
            description="vuln found",
            metadata={"cve": "CVE-2024-1234", "port": 443},
        )
        node.parent_node_ids = ["parent-1", "parent-2"]
        ms1.add(node)
        ms1.close()

        ms2 = MemoryStream(persist_path=tmp_db)
        reloaded = ms2.get(node.node_id)
        assert reloaded is not None
        assert reloaded.metadata["cve"] == "CVE-2024-1234"
        assert reloaded.metadata["port"] == 443
        assert "parent-1" in reloaded.parent_node_ids
        assert "parent-2" in reloaded.parent_node_ids
        ms2.close()

    def test_persist_node_without_spo(self, tmp_db: str) -> None:
        """Nodes without SPO triple persist and reload correctly."""
        ms1 = MemoryStream(persist_path=tmp_db)
        node = _make_node(description="no spo", spo=None)
        ms1.add(node)
        ms1.close()

        ms2 = MemoryStream(persist_path=tmp_db)
        reloaded = ms2.get(node.node_id)
        assert reloaded is not None
        assert reloaded.spo_triple is None
        ms2.close()

    def test_persist_corrupt_metadata_handled(self, tmp_db: str) -> None:
        """Corrupt JSON metadata in DB is handled gracefully."""
        ms1 = MemoryStream(persist_path=tmp_db)
        node = _make_node(description="corrupt meta test")
        ms1.add(node)

        # Corrupt the metadata column directly
        ms1._db_conn.execute(
            "UPDATE memory_nodes SET metadata = 'NOT-JSON' WHERE node_id = ?",
            (node.node_id,),
        )
        ms1._db_conn.commit()
        ms1.close()

        # Reopen — should load without error, metadata = {}
        ms2 = MemoryStream(persist_path=tmp_db)
        reloaded = ms2.get(node.node_id)
        assert reloaded is not None
        assert reloaded.metadata == {}
        ms2.close()

    def test_persist_corrupt_parent_ids_handled(self, tmp_db: str) -> None:
        """Corrupt parent_node_ids JSON in DB is handled gracefully."""
        ms1 = MemoryStream(persist_path=tmp_db)
        node = _make_node(description="corrupt parent test")
        ms1.add(node)

        ms1._db_conn.execute(
            "UPDATE memory_nodes SET parent_node_ids = 'INVALID' WHERE node_id = ?",
            (node.node_id,),
        )
        ms1._db_conn.commit()
        ms1.close()

        ms2 = MemoryStream(persist_path=tmp_db)
        reloaded = ms2.get(node.node_id)
        assert reloaded is not None
        assert reloaded.parent_node_ids == []
        ms2.close()

    def test_get_updates_access_in_db(self, tmp_db: str) -> None:
        """Calling get() should update last_accessed and access_count in DB."""
        ms = MemoryStream(persist_path=tmp_db)
        node = _make_node(description="access test")
        ms.add(node)

        original_access = node.last_accessed
        time.sleep(0.01)

        retrieved = ms.get(node.node_id)
        assert retrieved is not None
        assert retrieved.access_count >= 1
        assert retrieved.last_accessed >= original_access
        ms.close()

    def test_clear_target_deletes_from_db(self, tmp_db: str) -> None:
        """clear(target=X) deletes only that target's rows from DB."""
        ms = MemoryStream(persist_path=tmp_db)
        ms.add(_make_node(description="target A", target="A"))
        ms.add(_make_node(description="target B", target="B"))
        assert ms.count() == 2

        ms.clear(target="A")
        assert ms.count() == 1
        ms.close()

        # Reopen and verify only B exists
        ms2 = MemoryStream(persist_path=tmp_db)
        assert ms2.count() == 1
        ms2.close()

    def test_clear_all_deletes_all_from_db(self, tmp_db: str) -> None:
        """clear() without target deletes everything from DB."""
        ms = MemoryStream(persist_path=tmp_db)
        ms.add(_make_node(description="n1"))
        ms.add(_make_node(description="n2"))
        ms.add(_make_node(description="n3"))
        assert ms.count() == 3

        ms.clear()
        assert ms.count() == 0
        ms.close()

        ms2 = MemoryStream(persist_path=tmp_db)
        assert ms2.count() == 0
        ms2.close()

    def test_init_persistence_failure_handled(self, tmp_path: Path) -> None:
        """If persistence init fails, stream falls back to in-memory."""
        # Use an invalid path that can't be written to
        bad_path = str(tmp_path / "nonexistent_deep_dir" / "sub" / "test.db")
        # Force an error by making the parent a file instead of a directory
        parent = tmp_path / "nonexistent_deep_dir"
        parent.touch()  # file, not directory — sqlite3 will fail

        ms = MemoryStream(persist_path=bad_path)
        # Should not crash, falls back to in-memory
        assert ms._db_conn is None
        # Still works as in-memory
        ms.add(_make_node(description="fallback works"))
        assert ms.count() == 1
        ms.close()


# ================================================================== Eviction
class TestEviction:
    """Eviction logic when at MAX_MEMORY_NODES capacity."""

    def test_eviction_at_capacity(self) -> None:
        """When at capacity, adding a node evicts low-importance old ones."""
        ms = MemoryStream(persist_path=None)
        # Use a small capacity for testing
        ms.MAX_MEMORY_NODES = 50

        # Add 50 low-poignancy nodes
        for i in range(50):
            ms.add(_make_node(description=f"low-{i}", poignancy=3.0, target="evict-test"))
        assert ms.count() == 50

        # Add one more — should trigger eviction
        ms.add(_make_node(description="new-important", poignancy=9.0, target="evict-test"))

        # Should be at or near capacity (eviction removed some)
        assert ms.count() <= 50
        ms.close()

    def test_eviction_spares_high_poignancy(self) -> None:
        """High-poignancy nodes are not evicted."""
        ms = MemoryStream(persist_path=None)
        ms.MAX_MEMORY_NODES = 20

        # Add high-poignancy nodes first
        high_ids = []
        for i in range(10):
            node = _make_node(description=f"high-{i}", poignancy=9.0)
            ms.add(node)
            high_ids.append(node.node_id)

        # Add low-poignancy nodes to fill
        for i in range(10):
            ms.add(_make_node(description=f"low-{i}", poignancy=2.0))

        assert ms.count() == 20

        # Trigger eviction
        ms.add(_make_node(description="trigger", poignancy=9.0))

        # High-poignancy nodes should still be there
        for nid in high_ids:
            assert ms.get(nid) is not None
        ms.close()

    def test_eviction_with_persistence(self, tmp_db: str) -> None:
        """Eviction also deletes from SQLite DB."""
        ms = MemoryStream(persist_path=tmp_db)
        ms.MAX_MEMORY_NODES = 20

        for i in range(20):
            ms.add(_make_node(description=f"fill-{i}", poignancy=2.0))

        ms.add(_make_node(description="trigger-eviction", poignancy=9.0))

        # Some nodes should have been evicted
        assert ms.count() < 21

        # Verify DB matches in-memory count
        cursor = ms._db_conn.execute("SELECT COUNT(*) FROM memory_nodes")
        row = cursor.fetchone()
        db_count = row[0] if row else 0
        assert db_count == ms.count()
        ms.close()


# ================================================================== Semantic Search
class TestSemanticSearch:
    """Semantic search with mocked VectorStore."""

    def test_search_semantic_with_mock_store(self) -> None:
        """search_semantic delegates to vector_store.search."""
        mock_store = MagicMock()
        ms = MemoryStream(persist_path=None, vector_store=mock_store, use_embeddings=True)

        node = _make_node(description="SQL injection found", poignancy=8.0)
        ms.add(node)

        # Mock search results
        mock_store.search.return_value = [{"metadata": {"node_id": node.node_id}, "distance": 0.1}]

        results = ms.search_semantic("SQL injection", n=5)
        assert len(results) == 1
        assert results[0][0].node_id == node.node_id
        assert results[0][1] == pytest.approx(0.9, abs=0.01)  # 1.0 - 0.1

        mock_store.search.assert_called_once_with("SQL injection", n_results=5)
        ms.close()

    def test_search_semantic_no_store(self) -> None:
        """search_semantic returns empty if no vector_store."""
        ms = MemoryStream(persist_path=None, vector_store=None)
        results = ms.search_semantic("test query")
        assert results == []
        ms.close()

    def test_search_semantic_handles_error(self) -> None:
        """search_semantic handles exceptions from vector_store."""
        mock_store = MagicMock()
        mock_store.search.side_effect = RuntimeError("connection failed")
        ms = MemoryStream(persist_path=None, vector_store=mock_store, use_embeddings=True)
        results = ms.search_semantic("test")
        assert results == []
        ms.close()

    def test_embed_node_called_on_add(self) -> None:
        """Adding a node with embeddings enabled calls _embed_node."""
        mock_store = MagicMock()
        ms = MemoryStream(persist_path=None, vector_store=mock_store, use_embeddings=True)

        node = _make_node(
            description="open port",
            spo=SPOTriple(subject="host", predicate="has_port", obj="80"),
        )
        ms.add(node)

        # add_memory should have been called
        mock_store.add_memory.assert_called_once()
        call_args = mock_store.add_memory.call_args
        assert "open port" in call_args[0][0]
        ms.close()

    def test_embed_node_failure_handled(self) -> None:
        """Embedding failure does not prevent node from being added."""
        mock_store = MagicMock()
        mock_store.add_memory.side_effect = RuntimeError("embedding error")
        ms = MemoryStream(persist_path=None, vector_store=mock_store, use_embeddings=True)

        node = _make_node(description="still saved")
        ms.add(node)

        assert ms.count() == 1
        assert ms.get(node.node_id) is not None
        ms.close()


# ================================================================== get_stats
class TestGetStats:
    """Test get_stats method."""

    def test_stats_empty_stream(self) -> None:
        """get_stats on empty stream returns sensible defaults."""
        ms = MemoryStream(persist_path=None)
        stats = ms.get_stats()
        assert stats["total_nodes"] == 0
        assert stats["by_type"] == {}
        assert stats["targets"] == []
        assert stats["oldest_node"] is None
        assert stats["newest_node"] is None
        assert stats["persistence_enabled"] is False
        assert stats["embeddings_enabled"] is False
        ms.close()

    def test_stats_with_nodes(self) -> None:
        """get_stats reflects added nodes."""
        ms = MemoryStream(persist_path=None)
        ms.add(_make_node(description="e1", node_type=NodeType.EVENT, target="T1"))
        ms.add(_make_node(description="e2", node_type=NodeType.EVENT, target="T2"))
        ms.add(_make_node(description="t1", node_type=NodeType.THOUGHT, target="T1"))

        stats = ms.get_stats()
        assert stats["total_nodes"] == 3
        assert stats["by_type"][NodeType.EVENT.value] == 2
        assert stats["by_type"][NodeType.THOUGHT.value] == 1
        assert set(stats["targets"]) == {"T1", "T2"}
        assert stats["oldest_node"] is not None
        assert stats["newest_node"] is not None
        ms.close()

    def test_stats_with_persistence(self, tmp_db: str) -> None:
        """persistence_enabled should be True when using DB."""
        ms = MemoryStream(persist_path=tmp_db)
        stats = ms.get_stats()
        assert stats["persistence_enabled"] is True
        ms.close()


# ================================================================== get_by_relevance (direct)
class TestGetByRelevance:
    """Direct tests for get_by_relevance."""

    def test_get_by_relevance_direct(self) -> None:
        """get_by_relevance returns nodes of specific relevance."""
        ms = MemoryStream(persist_path=None)
        ms.add(_make_node(relevance=PentestRelevance.CRITICAL_VULN, description="crit"))
        ms.add(_make_node(relevance=PentestRelevance.SERVICE_INFO, description="svc"))
        ms.add(_make_node(relevance=PentestRelevance.CRITICAL_VULN, description="crit2"))

        crits = ms.get_by_relevance(PentestRelevance.CRITICAL_VULN)
        assert len(crits) == 2
        ms.close()

    def test_get_by_relevance_with_target(self) -> None:
        """get_by_relevance filters by target."""
        ms = MemoryStream(persist_path=None)
        ms.add(_make_node(relevance=PentestRelevance.HIGH_VULN, target="A"))
        ms.add(_make_node(relevance=PentestRelevance.HIGH_VULN, target="B"))

        result = ms.get_by_relevance(PentestRelevance.HIGH_VULN, target="A")
        assert len(result) == 1
        assert result[0].target == "A"
        ms.close()

    def test_get_by_relevance_empty(self) -> None:
        """get_by_relevance returns empty for non-existing relevance."""
        ms = MemoryStream(persist_path=None)
        result = ms.get_by_relevance(PentestRelevance.CRITICAL_VULN)
        assert result == []
        ms.close()


# ================================================================== Singleton
class TestSingleton:
    """Tests for get_memory_stream / reset_memory_stream."""

    def test_get_memory_stream_creates_instance(self, tmp_db: str) -> None:
        """get_memory_stream creates and returns a singleton."""
        ms = get_memory_stream(persist_path=tmp_db)
        assert isinstance(ms, MemoryStream)
        assert ms.count() == 0

    def test_get_memory_stream_returns_same(self, tmp_db: str) -> None:
        """Calling get_memory_stream twice returns the same instance."""
        ms1 = get_memory_stream(persist_path=tmp_db)
        ms2 = get_memory_stream(persist_path=tmp_db)
        assert ms1 is ms2

    def test_reset_clears_singleton(self, tmp_db: str) -> None:
        """reset_memory_stream clears the singleton."""
        ms1 = get_memory_stream(persist_path=tmp_db)
        reset_memory_stream()
        ms2 = get_memory_stream(persist_path=tmp_db)
        assert ms1 is not ms2


# ================================================================== build_context
class TestBuildContextAdvanced:
    """Advanced build_context tests — max_tokens, include_types."""

    def test_build_context_max_tokens_limits_output(self) -> None:
        """build_context respects max_tokens limit."""
        ms = MemoryStream(persist_path=None)
        for i in range(20):
            ms.add(
                _make_node(
                    description=f"Event {i}: " + "A" * 200,
                    node_type=NodeType.EVENT,
                    poignancy=5.0,
                )
            )

        # Very small token limit
        context = ms.build_context(max_tokens=50)
        max_chars = 50 * 4
        assert len(context) <= max_chars + 100  # Allow some header overhead
        ms.close()

    def test_build_context_include_types_filter(self) -> None:
        """build_context with include_types only includes those types."""
        ms = MemoryStream(persist_path=None)
        ms.add(
            _make_node(
                description="An event",
                node_type=NodeType.EVENT,
                relevance=PentestRelevance.SERVICE_INFO,
            )
        )
        ms.add(
            _make_node(
                description="A thought",
                node_type=NodeType.THOUGHT,
                relevance=PentestRelevance.SERVICE_INFO,
            )
        )
        ms.add(
            _make_node(
                description="A reflection",
                node_type=NodeType.REFLECTION,
                relevance=PentestRelevance.SERVICE_INFO,
            )
        )

        # Only events
        context = ms.build_context(include_types=[NodeType.EVENT])
        assert "RECENT ACTIONS" in context
        # Thoughts and reflections should not appear in their sections
        assert "CURRENT REASONING" not in context
        assert "INSIGHTS" not in context
        ms.close()

    def test_build_context_empty_stream(self) -> None:
        """build_context on empty stream returns empty string."""
        ms = MemoryStream(persist_path=None)
        context = ms.build_context()
        assert context == ""
        ms.close()


# ================================================================== close()
class TestClose:
    """Test close() behavior."""

    def test_close_sets_conn_none(self, tmp_db: str) -> None:
        """close() should commit and set _db_conn to None."""
        ms = MemoryStream(persist_path=tmp_db)
        assert ms._db_conn is not None
        ms.close()
        assert ms._db_conn is None

    def test_close_idempotent(self, tmp_db: str) -> None:
        """Calling close() multiple times should not error."""
        ms = MemoryStream(persist_path=tmp_db)
        ms.close()
        ms.close()  # Should not raise
        assert ms._db_conn is None

    def test_close_in_memory_no_error(self) -> None:
        """close() on in-memory stream (no persistence) should not error."""
        ms = MemoryStream(persist_path=None)
        ms.close()  # Should not raise


# ================================================================== Full clear
class TestFullClear:
    """Test clear() without target — full wipe."""

    def test_clear_all_in_memory(self) -> None:
        """clear() without target clears all nodes and indexes."""
        ms = MemoryStream(persist_path=None)
        ms.add(_make_node(description="n1", target="A"))
        ms.add(_make_node(description="n2", target="B"))
        ms.add(
            _make_node(
                description="n3",
                target="C",
                spo=SPOTriple(subject="C", predicate="has", obj="thing"),
            )
        )
        assert ms.count() == 3

        ms.clear()
        assert ms.count() == 0
        assert ms.get_recent() == []
        assert ms.get_by_type(NodeType.EVENT) == []
        assert ms.count_by_type() == {}
        ms.close()

    def test_clear_all_with_persistence(self, tmp_db: str) -> None:
        """Full clear also deletes all rows from DB."""
        ms = MemoryStream(persist_path=tmp_db)
        ms.add(_make_node(description="n1"))
        ms.add(_make_node(description="n2"))
        ms.clear()

        # Verify DB is also empty
        cursor = ms._db_conn.execute("SELECT COUNT(*) FROM memory_nodes")
        row = cursor.fetchone()
        assert row and row[0] == 0
        ms.close()


# ================================================================== Edge cases
class TestEdgeCases:
    """Edge cases and robustness tests."""

    def test_get_nonexistent_node(self) -> None:
        """get() with unknown node_id returns None."""
        ms = MemoryStream(persist_path=None)
        assert ms.get("nonexistent-id") is None
        ms.close()

    def test_get_recent_empty(self) -> None:
        """get_recent on empty stream returns empty list."""
        ms = MemoryStream(persist_path=None)
        assert ms.get_recent() == []
        ms.close()

    def test_get_recent_n_zero(self) -> None:
        """get_recent with n=0 returns all nodes (Python [-0:] == [:])."""
        ms = MemoryStream(persist_path=None)
        ms.add(_make_node(description="test"))
        # Python slice [-0:] is same as [:], so n=0 returns all
        assert len(ms.get_recent(n=0)) == 1
        ms.close()

    def test_get_by_type_empty(self) -> None:
        """get_by_type with no matching types returns empty."""
        ms = MemoryStream(persist_path=None)
        ms.add(_make_node(node_type=NodeType.EVENT))
        assert ms.get_by_type(NodeType.REFLECTION) == []
        ms.close()

    def test_use_embeddings_false_overrides_store(self) -> None:
        """use_embeddings=False disables embeddings even with vector_store."""
        mock_store = MagicMock()
        ms = MemoryStream(
            persist_path=None,
            vector_store=mock_store,
            use_embeddings=False,
        )
        ms.add(_make_node(description="no embed"))
        mock_store.add_memory.assert_not_called()
        ms.close()

    def test_multiple_adds_index_consistency(self) -> None:
        """Adding many nodes keeps all indexes consistent."""
        ms = MemoryStream(persist_path=None)
        targets = ["A", "B", "C"]
        types = [NodeType.EVENT, NodeType.THOUGHT, NodeType.FINDING]

        for i in range(30):
            ms.add(
                _make_node(
                    description=f"node-{i}",
                    target=targets[i % 3],
                    node_type=types[i % 3],
                )
            )

        assert ms.count() == 30
        assert len(ms.get_by_type(NodeType.EVENT)) == 10
        assert len(ms.get_by_type(NodeType.THOUGHT)) == 10
        assert len(ms.get_by_type(NodeType.FINDING)) == 10

        # Target filter
        recent_a = ms.get_recent(n=100, target="A")
        assert len(recent_a) == 10
        ms.close()

    def test_query_spo_after_clear(self) -> None:
        """SPO index is cleared after full clear."""
        ms = MemoryStream(persist_path=None)
        ms.add(
            _make_node(
                spo=SPOTriple(subject="host", predicate="runs", obj="nginx"),
            )
        )
        assert len(ms.query_spo(subject="host")) == 1

        ms.clear()
        assert len(ms.query_spo(subject="host")) == 0
        ms.close()
