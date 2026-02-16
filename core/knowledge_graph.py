# core/knowledge_graph.py
# DRAKBEN â€” Lightweight Knowledge Graph
# Entity-relationship tracking for cross-session context.
# Inspired by PentAGI's Neo4j/Graphiti approach but uses NetworkX locally.

"""In-process knowledge graph for pentest entity tracking.

Tracks hosts, services, vulnerabilities, credentials, and the
relationships between them â€” enabling cross-session intelligence
and attack-path reasoning.

Usage::

    from core.knowledge_graph import get_knowledge_graph

    kg = get_knowledge_graph()
    kg.add_entity("host", "10.0.0.1", {"os": "Linux"})
    kg.add_entity("service", "10.0.0.1:80", {"name": "http", "version": "Apache/2.4"})
    kg.add_relation("10.0.0.1", "10.0.0.1:80", "RUNS")
    kg.add_entity("vuln", "CVE-2021-44228", {"severity": "critical"})
    kg.add_relation("10.0.0.1:80", "CVE-2021-44228", "VULNERABLE_TO")

    paths = kg.find_attack_paths("10.0.0.1", "foothold")
    related = kg.get_related("10.0.0.1:80", relation="VULNERABLE_TO")
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)

# Constant for in-memory SQLite database path
_MEMORY_DB = ":memory:"


# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------
ENTITY_TYPES = frozenset(
    {
        "host",
        "service",
        "vulnerability",
        "credential",
        "foothold",
        "domain",
        "user",
        "url",
        "finding",
        "tool_result",
        "network",
        "session",
    }
)

# Relationship types
RELATION_TYPES = frozenset(
    {
        "RUNS",  # host â†’ service
        "VULNERABLE_TO",  # service â†’ vulnerability
        "EXPLOITED_BY",  # vulnerability â†’ tool_result
        "LEADS_TO",  # tool_result â†’ foothold
        "DISCOVERED_BY",  # entity â†’ tool_result
        "AUTHENTICATES",  # credential â†’ service
        "BELONGS_TO",  # entity â†’ domain/network
        "CONNECTS_TO",  # host â†’ host (lateral movement)
        "ESCALATES_TO",  # credential â†’ credential (privesc)
        "MEMBER_OF",  # user â†’ domain group
        "CHILD_OF",  # subdomain â†’ domain
        "CONTAINS",  # network â†’ host
    }
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class Entity:
    """A node in the knowledge graph."""

    entity_type: str
    entity_id: str
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    session_id: str = ""


@dataclass
class Relation:
    """An edge in the knowledge graph."""

    source_id: str
    target_id: str
    relation_type: str
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    confidence: float = 1.0


# ---------------------------------------------------------------------------
# Knowledge Graph (SQLite-backed)
# ---------------------------------------------------------------------------
class KnowledgeGraph:
    """Persistent knowledge graph with SQLite backend.

    Thread-safe singleton.
    """

    _instance: KnowledgeGraph | None = None
    _lock = threading.Lock()

    DB_PATH = "drakben_knowledge.db"

    def __new__(cls, db_path: str | None = None) -> KnowledgeGraph:
        with cls._lock:
            if cls._instance is None:
                instance = super().__new__(cls)
                instance._db_path = db_path or cls.DB_PATH
                instance._kg_lock = threading.RLock()
                instance._persistent_conn = None  # sqlite3.Connection | None
                instance._init_db()
                cls._instance = instance
            return cls._instance

    def _init_db(self) -> None:
        """Initialize database schema."""
        try:
            conn = self._connect()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS entities (
                    entity_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    properties TEXT DEFAULT '{}',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    session_id TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS relations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    properties TEXT DEFAULT '{}',
                    created_at REAL NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    UNIQUE(source_id, target_id, relation_type)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_entity_type
                ON entities(entity_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_relation_source
                ON relations(source_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_relation_target
                ON relations(target_id)
            """)
            conn.commit()
        except sqlite3.Error:
            logger.exception("Knowledge graph DB init failed")

    def _connect(self) -> sqlite3.Connection:
        """Get a database connection.

        For ``:memory:`` databases, returns a single persistent
        connection (since each ``sqlite3.connect(':memory:')``
        creates a separate database). For file-based databases,
        creates a new connection per call.
        """
        if self._db_path == _MEMORY_DB:
            if self._persistent_conn is None:
                self._persistent_conn = self._make_conn()
            return self._persistent_conn
        return self._make_conn()

    @staticmethod
    def _make_conn_from_path(db_path: str) -> sqlite3.Connection:
        """Create a new SQLite connection with default pragmas."""
        conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
        if db_path != _MEMORY_DB:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        return conn

    def _make_conn(self) -> sqlite3.Connection:
        """Create a new SQLite connection."""
        return self._make_conn_from_path(self._db_path)

    @contextmanager
    def _get_conn(self) -> Iterator[sqlite3.Connection]:
        """Context manager that yields a connection and auto-closes it.

        For file-based databases, closes the connection on exit to
        prevent file-descriptor leaks.  For ``:memory:`` databases,
        the persistent connection is kept open.
        """
        conn = self._connect()
        try:
            with conn:  # handles commit / rollback
                yield conn
        finally:
            if self._db_path != _MEMORY_DB:
                conn.close()

    # -- Entity Operations --

    def add_entity(
        self,
        entity_type: str,
        entity_id: str,
        properties: dict[str, Any] | None = None,
        session_id: str = "",
    ) -> Entity | None:
        """Add or update an entity.

        Returns the Entity on success, or ``None`` if the DB write failed.
        """
        now = time.time()
        props = properties or {}

        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    conn.execute(
                        """
                        INSERT INTO entities (entity_id, entity_type, properties,
                                              created_at, updated_at, session_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(entity_id) DO UPDATE SET
                            properties = ?,
                            updated_at = ?,
                            session_id = CASE
                                WHEN excluded.session_id != '' THEN excluded.session_id
                                ELSE entities.session_id
                            END
                        """,
                        (
                            entity_id,
                            entity_type,
                            json.dumps(props, default=str),
                            now,
                            now,
                            session_id,
                            json.dumps(props, default=str),
                            now,
                        ),
                    )
            except sqlite3.Error:
                logger.exception("Failed to add entity %s", entity_id)
                return None

        return Entity(
            entity_type=entity_type,
            entity_id=entity_id,
            properties=props,
            created_at=now,
            updated_at=now,
            session_id=session_id,
        )

    def get_entity(self, entity_id: str) -> Entity | None:
        """Get an entity by ID."""
        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    row = conn.execute(
                        "SELECT * FROM entities WHERE entity_id = ?",
                        (entity_id,),
                    ).fetchone()
                    if row:
                        return Entity(
                            entity_type=row["entity_type"],
                            entity_id=row["entity_id"],
                            properties=json.loads(row["properties"]),
                            created_at=row["created_at"],
                            updated_at=row["updated_at"],
                            session_id=row["session_id"],
                        )
            except sqlite3.Error:
                logger.exception("Failed to get entity %s", entity_id)
        return None

    def find_entities(
        self,
        entity_type: str | None = None,
        session_id: str | None = None,
        limit: int = 100,
    ) -> list[Entity]:
        """Find entities by type and/or session."""
        conditions: list[str] = []
        params: list[Any] = []

        if entity_type:
            conditions.append("entity_type = ?")
            params.append(entity_type)
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM entities {where} ORDER BY updated_at DESC LIMIT ?"  # noqa: S608
        params.append(limit)

        results: list[Entity] = []
        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    for row in conn.execute(query, params):
                        results.append(
                            Entity(
                                entity_type=row["entity_type"],
                                entity_id=row["entity_id"],
                                properties=json.loads(row["properties"]),
                                created_at=row["created_at"],
                                updated_at=row["updated_at"],
                                session_id=row["session_id"],
                            )
                        )
            except sqlite3.Error:
                logger.exception("Failed to find entities")
        return results

    # -- Relation Operations --

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        properties: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ) -> Relation | None:
        """Add a relationship between two entities.

        Returns the Relation on success, or ``None`` if the DB write failed.
        """
        now = time.time()
        props = properties or {}

        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    conn.execute(
                        """
                        INSERT INTO relations (source_id, target_id, relation_type,
                                               properties, created_at, confidence)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(source_id, target_id, relation_type) DO UPDATE SET
                            properties = ?,
                            confidence = ?
                        """,
                        (
                            source_id,
                            target_id,
                            relation_type,
                            json.dumps(props, default=str),
                            now,
                            confidence,
                            json.dumps(props, default=str),
                            confidence,
                        ),
                    )
            except sqlite3.Error:
                logger.exception(
                    "Failed to add relation %s -> %s",
                    source_id,
                    target_id,
                )
                return None

        return Relation(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=props,
            created_at=now,
            confidence=confidence,
        )

    def get_related(
        self,
        entity_id: str,
        relation: str | None = None,
        direction: str = "outgoing",
    ) -> list[tuple[str, str, dict[str, Any]]]:
        """Get entities related to a given entity.

        Args:
            entity_id: The source entity.
            relation: Filter by relation type (optional).
            direction: "outgoing", "incoming", or "both".

        Returns:
            List of (related_entity_id, relation_type, properties).
        """
        results: list[tuple[str, str, dict[str, Any]]] = []

        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    if direction in ("outgoing", "both"):
                        q = "SELECT target_id, relation_type, properties FROM relations WHERE source_id = ?"
                        params: list[Any] = [entity_id]
                        if relation:
                            q += " AND relation_type = ?"
                            params.append(relation)
                        for row in conn.execute(q, params):
                            results.append(
                                (
                                    row["target_id"],
                                    row["relation_type"],
                                    json.loads(row["properties"]),
                                )
                            )

                    if direction in ("incoming", "both"):
                        q = "SELECT source_id, relation_type, properties FROM relations WHERE target_id = ?"
                        params = [entity_id]
                        if relation:
                            q += " AND relation_type = ?"
                            params.append(relation)
                        for row in conn.execute(q, params):
                            results.append(
                                (
                                    row["source_id"],
                                    row["relation_type"],
                                    json.loads(row["properties"]),
                                )
                            )
            except sqlite3.Error:
                logger.exception("Failed to get related for %s", entity_id)

        return results

    @staticmethod
    def _expand_bfs_neighbors(
        conn: sqlite3.Connection,
        current: str,
        path: list[str],
        visited: set[str],
        queue: Any,
        max_queue: int,
    ) -> None:
        """Add unvisited neighbors to the BFS queue (with size guard)."""
        for neighbor in conn.execute(
            "SELECT target_id FROM relations WHERE source_id = ?",
            (current,),
        ):
            next_id = neighbor["target_id"]
            if next_id not in visited and len(queue) < max_queue:
                queue.append([*path, next_id])

    def find_attack_paths(
        self,
        start_id: str,
        goal_type: str = "foothold",
        max_depth: int = 6,
    ) -> list[list[str]]:
        """BFS to find paths from start entity to entities of goal_type.

        Args:
            start_id: Starting entity ID.
            goal_type: Target entity type (e.g. "foothold").
            max_depth: Maximum path length in nodes (not edges).
                A value of 6 allows paths with up to 6 nodes (5 hops).

        Returns:
            List of paths where each path is a list of entity IDs.
        """
        from collections import deque

        visited: set[str] = set()
        queue: deque[list[str]] = deque([[start_id]])
        paths: list[list[str]] = []
        max_queue = 10_000  # Guard against memory explosion on dense graphs

        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    while queue:
                        path = queue.popleft()
                        current = path[-1]

                        if len(path) > max_depth or current in visited:
                            continue
                        visited.add(current)

                        # Check if current is goal
                        row = conn.execute(
                            "SELECT entity_type FROM entities WHERE entity_id = ?",
                            (current,),
                        ).fetchone()
                        if row and row["entity_type"] == goal_type and len(path) > 1:
                            paths.append(path)
                            continue

                        # Expand neighbors (with queue size guard)
                        self._expand_bfs_neighbors(
                            conn,
                            current,
                            path,
                            visited,
                            queue,
                            max_queue,
                        )
            except sqlite3.Error:
                logger.exception("Attack path search failed")

        return paths

    # -- Statistics --

    def stats(self) -> dict[str, Any]:
        """Get graph statistics."""
        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    entity_count = conn.execute(
                        "SELECT COUNT(*) FROM entities",
                    ).fetchone()[0]
                    relation_count = conn.execute(
                        "SELECT COUNT(*) FROM relations",
                    ).fetchone()[0]
                    type_counts = {}
                    for row in conn.execute(
                        "SELECT entity_type, COUNT(*) as c FROM entities GROUP BY entity_type",
                    ):
                        type_counts[row["entity_type"]] = row["c"]
                    return {
                        "entities": entity_count,
                        "relations": relation_count,
                        "types": type_counts,
                    }
            except sqlite3.Error:
                logger.exception("Failed to get graph stats")
                return {"entities": 0, "relations": 0, "types": {}}

    def clear(self) -> None:
        """Clear all data."""
        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    conn.execute("DELETE FROM relations")
                    conn.execute("DELETE FROM entities")
            except sqlite3.Error:
                logger.exception("Failed to clear knowledge graph")

    def export_json(self, path: str | Path) -> None:
        """Export entire graph to JSON."""
        with self._kg_lock:
            try:
                with self._get_conn() as conn:
                    entities = [
                        {
                            "id": row["entity_id"],
                            "type": row["entity_type"],
                            "props": json.loads(row["properties"]),
                            "session": row["session_id"],
                        }
                        for row in conn.execute("SELECT * FROM entities")
                    ]
                    relations = [
                        {
                            "source": row["source_id"],
                            "target": row["target_id"],
                            "type": row["relation_type"],
                            "props": json.loads(row["properties"]),
                            "confidence": row["confidence"],
                        }
                        for row in conn.execute("SELECT * FROM relations")
                    ]

                    path = Path(path)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(
                        json.dumps({"entities": entities, "relations": relations}, indent=2),
                        encoding="utf-8",
                    )
            except (sqlite3.Error, OSError):
                logger.exception("Failed to export knowledge graph")

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        with cls._lock:
            if cls._instance is not None:
                pc = getattr(cls._instance, "_persistent_conn", None)
                if pc is not None:
                    try:
                        pc.close()
                    except sqlite3.Error:
                        pass  # Cleanup: best-effort on singleton reset
            cls._instance = None


def get_knowledge_graph(db_path: str | None = None) -> KnowledgeGraph:
    """Get the global KnowledgeGraph singleton."""
    return KnowledgeGraph(db_path=db_path)
