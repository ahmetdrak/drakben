# core/agent/memory/memory_stream.py
"""AssociativeMemory - Stanford Generative Agents Style Memory Stream.

This implements the core memory stream that stores and organizes ConceptNodes.
Inspired by Stanford's "Generative Agents" paper's associative memory system.

Key features:
- In-memory storage with optional persistence
- Integration with VectorStore for semantic embeddings
- Efficient indexing by type, target, and time
- Graph-based retrieval via SPO triples
- Token-efficient context generation

The memory stream is the central hub that:
1. Stores all ConceptNodes (events, thoughts, findings, reflections)
2. Provides multiple retrieval interfaces (recency, type, semantic)
3. Integrates with external embedding services
4. Supports multi-target scenarios
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.agent.memory.concept_node import (
    ConceptNode,
    NodeType,
    PentestRelevance,
    SPOTriple,
)

if TYPE_CHECKING:
    from core.storage.vector_store import VectorStore

logger = logging.getLogger(__name__)


class MemoryStream:
    """Associative memory stream for storing and retrieving ConceptNodes.

    This is the central memory system that implements:
    - Stanford-style memory storage
    - Multi-index access (time, type, target, semantic)
    - Persistence via SQLite
    - Integration with VectorStore for embeddings

    Token Efficiency:
    - Instead of passing entire history to LLM, we retrieve only relevant nodes
    - Typical context: 5-20 nodes instead of 100+ raw history entries
    - Estimated 10-12x token reduction vs linear history
    """

    # Configuration
    MAX_MEMORY_NODES = 10000  # Hard limit to prevent unbounded growth
    PERSISTENCE_BATCH_SIZE = 50  # Batch writes for efficiency
    DEFAULT_CONTEXT_NODES = 15  # Default nodes to include in LLM context

    def __init__(
        self,
        persist_path: str | None = None,
        vector_store: VectorStore | None = None,
        use_embeddings: bool = True,
    ) -> None:
        """Initialize the memory stream.

        Args:
            persist_path: Path to SQLite DB for persistence (None = in-memory)
            vector_store: Optional VectorStore for semantic embeddings
            use_embeddings: Whether to generate embeddings for nodes
        """
        self._lock = threading.RLock()

        # Core storage
        self._nodes: dict[str, ConceptNode] = {}  # node_id -> ConceptNode

        # Indexes for fast retrieval
        self._by_type: dict[NodeType, list[str]] = defaultdict(list)
        self._by_target: dict[str, list[str]] = defaultdict(list)
        self._by_time: list[str] = []  # Chronologically ordered node IDs
        self._by_relevance: dict[PentestRelevance, list[str]] = defaultdict(list)

        # Graph index for SPO triple queries
        self._spo_index: dict[str, list[str]] = defaultdict(list)  # subject -> node_ids

        # Persistence
        self._persist_path = persist_path
        self._db_conn: sqlite3.Connection | None = None
        self._pending_writes: list[ConceptNode] = []

        # Embedding integration
        self._vector_store = vector_store
        self._use_embeddings = use_embeddings and vector_store is not None

        # Initialize persistence if path provided
        if persist_path:
            self._init_persistence()

    def _init_persistence(self) -> None:
        """Initialize SQLite persistence layer."""
        try:
            # M-6 FIX: Resolve path at init time to avoid CWD sensitivity
            db_path = str(Path(self._persist_path).resolve())
            self._db_conn = sqlite3.connect(
                db_path,
                timeout=10.0,
                check_same_thread=False,
            )
            self._db_conn.row_factory = sqlite3.Row

            # Enable WAL mode for concurrency
            self._db_conn.execute("PRAGMA journal_mode=WAL")
            self._db_conn.execute("PRAGMA busy_timeout=10000")

            # Create table
            self._db_conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_nodes (
                    node_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    poignancy REAL NOT NULL,
                    created_at REAL NOT NULL,
                    last_accessed REAL NOT NULL,
                    access_count INTEGER DEFAULT 0,
                    node_type TEXT NOT NULL,
                    pentest_relevance TEXT NOT NULL,
                    spo_subject TEXT,
                    spo_predicate TEXT,
                    spo_obj TEXT,
                    metadata TEXT,
                    parent_node_ids TEXT,
                    target TEXT
                )
            """)

            # Create indexes for fast retrieval
            self._db_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_node_type ON memory_nodes(node_type)",
            )
            self._db_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target ON memory_nodes(target)",
            )
            self._db_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_created_at ON memory_nodes(created_at)",
            )
            self._db_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_poignancy ON memory_nodes(poignancy)",
            )

            self._db_conn.commit()

            # Load existing nodes
            self._load_from_persistence()

            logger.info("MemoryStream persistence initialized: %s", self._persist_path)
        except Exception as e:
            logger.exception("Failed to initialize persistence: %s", e)
            self._db_conn = None

    def _load_from_persistence(self) -> None:
        """Load nodes from SQLite into memory."""
        if not self._db_conn:
            return

        try:
            cursor = self._db_conn.execute(
                "SELECT * FROM memory_nodes ORDER BY created_at",
            )
            for row in cursor:
                node = self._row_to_node(row)
                self._index_node(node)
                self._nodes[node.node_id] = node

            logger.info("Loaded %d nodes from persistence", len(self._nodes))
        except Exception as e:
            logger.exception("Failed to load from persistence: %s", e)

    def _row_to_node(self, row: sqlite3.Row) -> ConceptNode:
        """Convert SQLite row to ConceptNode."""
        spo_triple = None
        if row["spo_subject"]:
            spo_triple = SPOTriple(
                subject=row["spo_subject"],
                predicate=row["spo_predicate"] or "",
                obj=row["spo_obj"] or "",
            )

        metadata = {}
        if row["metadata"]:
            try:
                metadata = json.loads(row["metadata"])
            except json.JSONDecodeError:
                pass

        parent_ids = []
        if row["parent_node_ids"]:
            try:
                parent_ids = json.loads(row["parent_node_ids"])
            except json.JSONDecodeError:
                pass

        return ConceptNode(
            node_id=row["node_id"],
            description=row["description"],
            poignancy=row["poignancy"],
            created_at=row["created_at"],
            last_accessed=row["last_accessed"],
            access_count=row["access_count"],
            node_type=NodeType(row["node_type"]),
            pentest_relevance=PentestRelevance(row["pentest_relevance"]),
            spo_triple=spo_triple,
            metadata=metadata,
            parent_node_ids=parent_ids,
            target=row["target"],
        )

    def _persist_node(self, node: ConceptNode) -> None:
        """Persist a single node to SQLite."""
        if not self._db_conn:
            return

        try:
            spo_subject = node.spo_triple.subject if node.spo_triple else None
            spo_predicate = node.spo_triple.predicate if node.spo_triple else None
            spo_obj = node.spo_triple.obj if node.spo_triple else None

            self._db_conn.execute(
                """
                INSERT OR REPLACE INTO memory_nodes
                (node_id, description, poignancy, created_at, last_accessed,
                 access_count, node_type, pentest_relevance, spo_subject,
                 spo_predicate, spo_obj, metadata, parent_node_ids, target)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    node.node_id,
                    node.description,
                    node.poignancy,
                    node.created_at,
                    node.last_accessed,
                    node.access_count,
                    node.node_type.value,
                    node.pentest_relevance.value,
                    spo_subject,
                    spo_predicate,
                    spo_obj,
                    json.dumps(node.metadata),
                    json.dumps(node.parent_node_ids),
                    node.target,
                ),
            )
            self._db_conn.commit()
        except Exception as e:
            logger.exception("Failed to persist node %s: %s", node.node_id, e)

    def _index_node(self, node: ConceptNode) -> None:
        """Add node to all relevant indexes."""
        # Type index
        self._by_type[node.node_type].append(node.node_id)

        # Target index
        if node.target:
            self._by_target[node.target].append(node.node_id)

        # Time index (maintain chronological order)
        self._by_time.append(node.node_id)

        # Relevance index
        self._by_relevance[node.pentest_relevance].append(node.node_id)

        # SPO index
        if node.spo_triple:
            self._spo_index[node.spo_triple.subject.lower()].append(node.node_id)

    def _remove_from_indexes(self, node_id: str) -> None:
        """Remove node from all indexes."""
        if node_id not in self._nodes:
            return

        node = self._nodes[node_id]

        # Remove from type index
        if node_id in self._by_type[node.node_type]:
            self._by_type[node.node_type].remove(node_id)

        # Remove from target index
        if node.target and node_id in self._by_target[node.target]:
            self._by_target[node.target].remove(node_id)

        # Remove from time index
        if node_id in self._by_time:
            self._by_time.remove(node_id)

        # Remove from relevance index
        if node_id in self._by_relevance[node.pentest_relevance]:
            self._by_relevance[node.pentest_relevance].remove(node_id)

        # Remove from SPO index
        if node.spo_triple:
            subject_key = node.spo_triple.subject.lower()
            if node_id in self._spo_index[subject_key]:
                self._spo_index[subject_key].remove(node_id)

    def add(self, node: ConceptNode) -> str:
        """Add a new node to the memory stream.

        Args:
            node: ConceptNode to add

        Returns:
            The node_id of the added node
        """
        with self._lock:
            # Enforce memory limit
            if len(self._nodes) >= self.MAX_MEMORY_NODES:
                self._evict_oldest_low_importance()

            # Store node
            self._nodes[node.node_id] = node

            # Update indexes
            self._index_node(node)

            # Persist if enabled
            if self._db_conn:
                self._persist_node(node)

            # Generate embedding if enabled
            if self._use_embeddings and self._vector_store:
                self._embed_node(node)

            logger.debug("Added memory node: %s (%s)", node.node_id[:8], node.node_type.value)

            return node.node_id

    def _evict_oldest_low_importance(self) -> None:
        """Evict oldest low-importance nodes when at capacity."""
        # Find candidates: old nodes with low poignancy
        candidates = []
        for node_id in self._by_time[:100]:  # Check oldest 100
            node = self._nodes.get(node_id)
            if node and node.poignancy < 6.0:  # Low importance threshold
                candidates.append((node_id, node.poignancy, node.created_at))

        # Sort by poignancy (ascending) then age (oldest first)
        candidates.sort(key=lambda x: (x[1], x[2]))

        # Remove up to 10% of max capacity
        to_remove = max(1, self.MAX_MEMORY_NODES // 10)
        for node_id, _, _ in candidates[:to_remove]:
            self._remove_from_indexes(node_id)
            del self._nodes[node_id]
            if self._db_conn:
                try:
                    self._db_conn.execute(
                        "DELETE FROM memory_nodes WHERE node_id = ?", (node_id,),
                    )
                except Exception:
                    pass

        # Commit eviction deletes to persist them
        if self._db_conn:
            try:
                self._db_conn.commit()
            except Exception:
                pass

        logger.info("Evicted %d low-importance nodes", min(to_remove, len(candidates)))

    def _embed_node(self, node: ConceptNode) -> None:
        """Generate and store embedding for a node."""
        if not self._vector_store:
            return

        try:
            # Use description + SPO triple for embedding
            text = node.description
            if node.spo_triple:
                text += f" ({node.spo_triple.to_sentence()})"

            # Add to vector store with metadata
            metadata = {
                "node_id": node.node_id,
                "node_type": node.node_type.value,
                "poignancy": node.poignancy,
                "target": node.target or "",
            }

            self._vector_store.add_memory(text, metadata)
        except Exception as e:
            logger.debug("Failed to embed node: %s", e)

    def get(self, node_id: str) -> ConceptNode | None:
        """Get a node by ID and update access tracking.

        Args:
            node_id: The node ID to retrieve

        Returns:
            ConceptNode or None if not found
        """
        with self._lock:
            node = self._nodes.get(node_id)
            if node:
                node.touch()  # Update access time
                if self._db_conn:
                    try:
                        self._db_conn.execute(
                            "UPDATE memory_nodes SET last_accessed = ?, access_count = ? WHERE node_id = ?",
                            (node.last_accessed, node.access_count, node_id),
                        )
                        self._db_conn.commit()
                    except Exception:
                        pass
            return node

    def get_recent(self, n: int = 10, target: str | None = None) -> list[ConceptNode]:
        """Get the N most recent nodes.

        Args:
            n: Number of nodes to return
            target: Optional target filter

        Returns:
            List of ConceptNodes, most recent first
        """
        with self._lock:
            if target:
                node_ids = self._by_target.get(target, [])
            else:
                node_ids = self._by_time

            # Get last n nodes, reversed for most-recent-first
            recent_ids = list(reversed(node_ids[-n:]))

            return [self._nodes[nid] for nid in recent_ids if nid in self._nodes]

    def get_by_type(
        self,
        node_type: NodeType,
        n: int = 10,
        target: str | None = None,
    ) -> list[ConceptNode]:
        """Get nodes of a specific type.

        Args:
            node_type: Type of nodes to retrieve
            n: Maximum number to return
            target: Optional target filter

        Returns:
            List of matching ConceptNodes, most recent first
        """
        with self._lock:
            node_ids = self._by_type.get(node_type, [])

            if target:
                node_ids = [
                    nid for nid in node_ids
                    if self._nodes.get(nid) and self._nodes[nid].target == target
                ]

            recent_ids = list(reversed(node_ids[-n:]))

            return [self._nodes[nid] for nid in recent_ids if nid in self._nodes]

    def get_by_relevance(
        self,
        relevance: PentestRelevance,
        n: int = 10,
        target: str | None = None,
    ) -> list[ConceptNode]:
        """Get nodes by pentest relevance category.

        Args:
            relevance: Pentest relevance category
            n: Maximum number to return
            target: Optional target filter

        Returns:
            List of matching ConceptNodes
        """
        with self._lock:
            node_ids = self._by_relevance.get(relevance, [])

            if target:
                node_ids = [
                    nid for nid in node_ids
                    if self._nodes.get(nid) and self._nodes[nid].target == target
                ]

            recent_ids = list(reversed(node_ids[-n:]))

            return [self._nodes[nid] for nid in recent_ids if nid in self._nodes]

    def get_critical_findings(
        self,
        target: str | None = None,
        min_poignancy: float = 7.0,
    ) -> list[ConceptNode]:
        """Get high-importance findings (vulns, creds, attack paths).

        Args:
            target: Optional target filter
            min_poignancy: Minimum poignancy threshold

        Returns:
            List of critical finding nodes
        """
        with self._lock:
            critical_types = [
                PentestRelevance.CRITICAL_VULN,
                PentestRelevance.HIGH_VULN,
                PentestRelevance.CREDENTIAL,
                PentestRelevance.ATTACK_PATH,
            ]

            findings: list[ConceptNode] = []
            for rel in critical_types:
                nodes = self.get_by_relevance(rel, n=20, target=target)
                findings.extend(n for n in nodes if n.poignancy >= min_poignancy)

            # Sort by poignancy (highest first)
            findings.sort(key=lambda x: x.poignancy, reverse=True)

            return findings

    def query_spo(
        self,
        subject: str | None = None,
        predicate: str | None = None,
        obj: str | None = None,
    ) -> list[ConceptNode]:
        """Query nodes by SPO triple pattern.

        Args:
            subject: Subject filter (None = wildcard)
            predicate: Predicate filter (None = wildcard)
            obj: Object filter (None = wildcard)

        Returns:
            List of matching ConceptNodes
        """
        with self._lock:
            # Start with subject index if available
            if subject:
                node_ids = self._spo_index.get(subject.lower(), [])
            else:
                node_ids = list(self._nodes.keys())

            results = []
            for node_id in node_ids:
                node = self._nodes.get(node_id)
                if not node or not node.spo_triple:
                    continue

                if node.spo_triple.matches(subject, predicate, obj):
                    results.append(node)

            return results

    def search_semantic(
        self,
        query: str,
        n: int = 10,
    ) -> list[tuple[ConceptNode, float]]:
        """Semantic search using vector embeddings.

        Args:
            query: Natural language query
            n: Number of results

        Returns:
            List of (ConceptNode, similarity_score) tuples
        """
        if not self._vector_store:
            return []

        try:
            results = self._vector_store.search(query, n_results=n)

            output = []
            for result in results:
                metadata = result.get("metadata", {})
                node_id = metadata.get("node_id")
                if node_id:
                    node = self.get(node_id)
                    if node:
                        # Distance to similarity (lower distance = higher similarity)
                        similarity = 1.0 - result.get("distance", 0.5)
                        output.append((node, similarity))

            return output
        except Exception as e:
            logger.debug("Semantic search failed: %s", e)
            return []

    def count(self) -> int:
        """Return total number of nodes."""
        with self._lock:
            return len(self._nodes)

    def count_by_type(self) -> dict[str, int]:
        """Return count per node type."""
        with self._lock:
            return {
                ntype.value: len(ids)
                for ntype, ids in self._by_type.items()
            }

    def get_stats(self) -> dict[str, Any]:
        """Get memory stream statistics."""
        with self._lock:
            return {
                "total_nodes": len(self._nodes),
                "by_type": self.count_by_type(),
                "targets": list(self._by_target.keys()),
                "oldest_node": self._by_time[0] if self._by_time else None,
                "newest_node": self._by_time[-1] if self._by_time else None,
                "persistence_enabled": self._db_conn is not None,
                "embeddings_enabled": self._use_embeddings,
            }

    @staticmethod
    def _collect_section(
        header: str,
        nodes: list[Any],
        limit: int,
        current_chars: int,
        max_chars: int,
    ) -> tuple[str, int]:
        """Build one context section from *nodes*, respecting char budget.

        Returns:
            (section_text, updated_current_chars)
        """
        section = header
        for node in nodes[:limit]:
            line = node.to_context_string() + "\n"
            if current_chars + len(line) > max_chars:
                break
            section += line
            current_chars += len(line)
        return section, current_chars

    def _build_typed_section(
        self,
        node_type: NodeType,
        header: str,
        n: int,
        target: str | None,
        include_types: list[NodeType] | None,
        current_chars: int,
        max_chars: int,
    ) -> tuple[str | None, int]:
        """Build a section for a specific NodeType if it is included."""
        if include_types and node_type not in include_types:
            return None, current_chars
        nodes = self.get_by_type(node_type, n=n, target=target)
        if not nodes:
            return None, current_chars
        section, current_chars = self._collect_section(
            header, nodes, n, current_chars, max_chars,
        )
        return section, current_chars

    def build_context(
        self,
        target: str | None = None,
        max_tokens: int = 2000,
        include_types: list[NodeType] | None = None,
    ) -> str:
        """Build a token-efficient context string for LLM.

        This is the KEY TOKEN EFFICIENCY FUNCTION.
        Instead of dumping entire history, we select the most relevant nodes.

        Args:
            target: Target to filter by
            max_tokens: Approximate token limit (4 chars ≈ 1 token)
            include_types: Node types to include (None = all)

        Returns:
            Formatted context string for LLM
        """
        with self._lock:
            chars_per_token = 4
            max_chars = max_tokens * chars_per_token

            sections: list[str] = []
            current_chars = 0

            # 1. Critical findings first (always include)
            critical = self.get_critical_findings(target=target)
            if critical:
                sec, current_chars = self._collect_section(
                    "=== CRITICAL FINDINGS ===\n", critical, 5,
                    current_chars, max_chars,
                )
                sections.append(sec)

            # 2-4. Typed sections
            typed_specs: list[tuple[NodeType, str, int]] = [
                (NodeType.EVENT, "\n=== RECENT ACTIONS ===\n", 10),
                (NodeType.THOUGHT, "\n=== CURRENT REASONING ===\n", 5),
                (NodeType.REFLECTION, "\n=== INSIGHTS ===\n", 3),
            ]
            for node_type, header, n in typed_specs:
                sec, current_chars = self._build_typed_section(
                    node_type, header, n, target,
                    include_types, current_chars, max_chars,
                )
                if sec is not None:
                    sections.append(sec)

            return "".join(sections)

    def _clear_target(self, target: str) -> None:
        """Remove all nodes belonging to *target* from indexes and DB."""
        node_ids = list(self._by_target.get(target, []))
        for node_id in node_ids:
            self._remove_from_indexes(node_id)
            if node_id in self._nodes:
                del self._nodes[node_id]
        if self._db_conn:
            try:
                self._db_conn.execute(
                    "DELETE FROM memory_nodes WHERE target = ?", (target,),
                )
                self._db_conn.commit()
            except Exception:
                pass

    def _clear_all(self) -> None:
        """Remove every node from indexes and DB."""
        self._nodes.clear()
        self._by_type.clear()
        self._by_target.clear()
        self._by_time.clear()
        self._by_relevance.clear()
        self._spo_index.clear()
        if self._db_conn:
            try:
                self._db_conn.execute("DELETE FROM memory_nodes")
                self._db_conn.commit()
            except Exception:
                pass

    def clear(self, target: str | None = None) -> None:
        """Clear memory stream.

        Args:
            target: If provided, only clear nodes for this target
        """
        with self._lock:
            if target:
                self._clear_target(target)
            else:
                self._clear_all()

            logger.info("Memory stream cleared (target=%s)", target)

    def close(self) -> None:
        """Close persistence connection."""
        if self._db_conn:
            try:
                self._db_conn.commit()
                self._db_conn.close()
            except Exception:
                pass
            self._db_conn = None


# Global singleton instance
_memory_stream: MemoryStream | None = None
_memory_stream_lock = threading.RLock()


def get_memory_stream(
    persist_path: str | None = "drakben_memory.db",
    vector_store: VectorStore | None = None,
) -> MemoryStream:
    """Get or create the global memory stream instance.

    Args:
        persist_path: Path to persistence DB
        vector_store: Optional VectorStore for embeddings

    Returns:
        MemoryStream singleton instance
    """
    global _memory_stream
    if _memory_stream is None:
        with _memory_stream_lock:
            if _memory_stream is None:
                _memory_stream = MemoryStream(
                    persist_path=persist_path,
                    vector_store=vector_store,
                )
    return _memory_stream


def reset_memory_stream() -> None:
    """Reset the global memory stream (for testing)."""
    global _memory_stream
    if _memory_stream:
        _memory_stream.close()
    _memory_stream = None
