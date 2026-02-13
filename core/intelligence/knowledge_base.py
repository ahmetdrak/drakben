# core/intelligence/knowledge_base.py
# DRAKBEN — Cross-Session Knowledge Base
#
# Problem: Every scan session starts from scratch. Lessons from past
#          sessions are lost (e.g., "WAF X blocks technique Y, use Z").
# Solution: SQLite-backed persistent knowledge base that stores:
#   - Learned lessons (tactical knowledge)
#   - Target fingerprints (what was found before)
#   - Tool effectiveness ratings per target type
#   - WAF/defense bypass recipes
#
# Entries have TTL (default 90 days) and relevance scoring.

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Default TTL: 90 days
_DEFAULT_TTL = 90 * 24 * 3600


@dataclass
class KnowledgeEntry:
    """A single piece of learned knowledge."""

    entry_id: str = ""
    category: str = ""          # "lesson", "fingerprint", "tool_rating", "defense_bypass"
    key: str = ""               # Lookup key (e.g., "waf:cloudflare:sqli")
    content: str = ""           # The knowledge itself
    tags: list[str] = field(default_factory=list)
    confidence: float = 0.5     # 0-1
    use_count: int = 0          # Times this knowledge was used
    success_count: int = 0      # Times it led to success
    created_at: float = 0.0
    updated_at: float = 0.0
    expires_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize entry."""
        return {
            "entry_id": self.entry_id,
            "category": self.category,
            "key": self.key,
            "content": self.content,
            "tags": self.tags,
            "confidence": self.confidence,
            "use_count": self.use_count,
            "success_count": self.success_count,
        }


class CrossSessionKB:
    """Persistent knowledge base that survives across scan sessions.

    Stores tactical lessons, target fingerprints, tool ratings,
    and defense bypass recipes. Entries have TTL and decay.

    Usage::

        kb = CrossSessionKB()

        # Store a lesson
        kb.learn(
            category="lesson",
            key="waf:cloudflare:sqli",
            content="CloudFlare WAF blocks basic SQLi. Use tamper=charencode,space2plus",
            tags=["waf", "cloudflare", "sqli", "bypass"],
        )

        # Recall before a scan
        lessons = kb.recall(tags=["cloudflare"], category="lesson")
        for lesson in lessons:
            print(lesson.content)

        # Store target fingerprint
        kb.learn(
            category="fingerprint",
            key="target:10.0.0.1",
            content=json.dumps({"os": "Linux", "ports": [22, 80, 443]}),
            tags=["10.0.0.1", "linux"],
        )

    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS knowledge (
        entry_id TEXT PRIMARY KEY,
        category TEXT NOT NULL,
        key TEXT NOT NULL,
        content TEXT NOT NULL,
        tags TEXT DEFAULT '[]',
        confidence REAL DEFAULT 0.5,
        use_count INTEGER DEFAULT 0,
        success_count INTEGER DEFAULT 0,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        metadata TEXT DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge(category);
    CREATE INDEX IF NOT EXISTS idx_knowledge_key ON knowledge(key);
    CREATE INDEX IF NOT EXISTS idx_knowledge_expires ON knowledge(expires_at);
    """

    def __init__(self, db_path: str = "sessions/knowledge_base.db") -> None:
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._stats = {
            "learns": 0,
            "recalls": 0,
            "hits": 0,
            "entries_expired": 0,
        }
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database."""
        try:
            import os
            os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
            self._conn = sqlite3.connect(
                self._db_path,
                check_same_thread=False,
                timeout=10,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(self._SCHEMA)
            self._conn.commit()
        except Exception as exc:
            logger.warning("Knowledge base init failed: %s", exc)
            self._conn = None

    # ─────────────────────── Public API ───────────────────────

    def learn(
        self,
        category: str,
        key: str,
        content: str,
        *,
        tags: list[str] | None = None,
        confidence: float = 0.5,
        ttl: int = _DEFAULT_TTL,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store a piece of knowledge.

        If key already exists, updates content and refreshes TTL.

        Args:
            category: Knowledge category (lesson, fingerprint, tool_rating, defense_bypass).
            key: Unique lookup key.
            content: The knowledge content.
            tags: Searchable tags.
            confidence: How confident we are in this knowledge.
            ttl: Time-to-live in seconds.
            metadata: Additional data.

        Returns:
            Entry ID.

        """
        if not self._conn:
            return ""

        self._stats["learns"] += 1
        now = time.time()
        entry_id = f"{category}:{key}"

        try:
            # Upsert
            self._conn.execute(
                """
                INSERT INTO knowledge
                    (entry_id, category, key, content, tags, confidence,
                     use_count, success_count, created_at, updated_at, expires_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?)
                ON CONFLICT(entry_id) DO UPDATE SET
                    content = excluded.content,
                    tags = excluded.tags,
                    confidence = MAX(knowledge.confidence, excluded.confidence),
                    updated_at = excluded.updated_at,
                    expires_at = excluded.expires_at,
                    metadata = excluded.metadata
                """,
                (
                    entry_id, category, key, content,
                    json.dumps(tags or []), confidence,
                    now, now, now + ttl,
                    json.dumps(metadata or {}),
                ),
            )
            self._conn.commit()
        except Exception as exc:
            logger.debug("Knowledge learn failed: %s", exc)
            return ""

        return entry_id

    def recall(
        self,
        *,
        category: str = "",
        key: str = "",
        tags: list[str] | None = None,
        min_confidence: float = 0.0,
        limit: int = 20,
    ) -> list[KnowledgeEntry]:
        """Recall knowledge matching criteria.

        Args:
            category: Filter by category.
            key: Filter by exact key match.
            tags: Filter by any matching tag.
            min_confidence: Minimum confidence threshold.
            limit: Maximum results.

        Returns:
            List of matching KnowledgeEntry objects.

        """
        if not self._conn:
            return []

        self._stats["recalls"] += 1

        query, params = self._build_recall_query(
            category, key, min_confidence, limit,
        )

        rows = self._execute_recall(query, params)
        if not rows:
            return []

        entries = self._rows_to_entries(rows, tags)
        self._stats["hits"] += len(entries)

        for entry in entries:
            self._increment_use_count(entry.entry_id)

        return entries[:limit]

    def _build_recall_query(
        self, category: str, key: str, min_confidence: float, limit: int,
    ) -> tuple[str, list[Any]]:
        """Build SQL query and params for recall filtering."""
        now = time.time()
        query = "SELECT * FROM knowledge WHERE expires_at > ?"
        params: list[Any] = [now]

        if category:
            query += " AND category = ?"
            params.append(category)
        if key:
            query += " AND key = ?"
            params.append(key)
        if min_confidence > 0:
            query += " AND confidence >= ?"
            params.append(min_confidence)

        query += " ORDER BY confidence DESC, use_count DESC LIMIT ?"
        params.append(limit)
        return query, params

    def _execute_recall(
        self, query: str, params: list[Any],
    ) -> list[tuple[Any, ...]]:
        """Execute recall query and return raw rows."""
        try:
            cursor = self._conn.execute(query, params)
            return cursor.fetchall()
        except Exception as exc:
            logger.debug("Knowledge recall failed: %s", exc)
            return []

    @staticmethod
    def _rows_to_entries(
        rows: list[tuple[Any, ...]], tags: list[str] | None,
    ) -> list[KnowledgeEntry]:
        """Convert raw DB rows to KnowledgeEntry objects with tag filtering."""
        entries: list[KnowledgeEntry] = []
        for row in rows:
            entry = KnowledgeEntry(
                entry_id=row[0],
                category=row[1],
                key=row[2],
                content=row[3],
                tags=json.loads(row[4]) if row[4] else [],
                confidence=row[5],
                use_count=row[6],
                success_count=row[7],
                created_at=row[8],
                updated_at=row[9],
                expires_at=row[10],
                metadata=json.loads(row[11]) if row[11] else {},
            )
            if tags and not any(t in entry.tags for t in tags):
                continue
            entries.append(entry)
        return entries

    def recall_for_target(self, target: str) -> list[KnowledgeEntry]:
        """Recall all knowledge related to a target."""
        return self.recall(tags=[target], limit=50)

    def recall_for_context(
        self, target: str, service: str = "", defense: str = "",
    ) -> str:
        """Get all relevant knowledge as a compact string for LLM injection.

        Args:
            target: Target IP/domain.
            service: Service being attacked.
            defense: Detected defense mechanism.

        Returns:
            Compact string of relevant knowledge for LLM prompt.

        """
        relevant = self._gather_context_entries(target, service, defense)

        if not relevant:
            return ""

        unique = self._deduplicate(relevant)

        lines = ["### Prior Knowledge (from previous sessions):"]
        for entry in unique[:15]:
            confidence_pct = f"{entry.confidence:.0%}"
            lines.append(f"  [{entry.category}] {entry.content} (conf={confidence_pct})")

        return "\n".join(lines)

    def _gather_context_entries(
        self, target: str, service: str, defense: str,
    ) -> list[KnowledgeEntry]:
        """Gather relevant knowledge entries from all categories."""
        relevant: list[KnowledgeEntry] = []
        relevant.extend(self.recall(tags=[target], limit=10))
        if service:
            relevant.extend(self.recall(category="lesson", tags=[service], limit=5))
            relevant.extend(self.recall(category="tool_rating", tags=[service], limit=5))
        if defense:
            relevant.extend(self.recall(
                category="defense_bypass", tags=[defense.lower()], limit=5,
            ))
        return relevant

    @staticmethod
    def _deduplicate(entries: list[KnowledgeEntry]) -> list[KnowledgeEntry]:
        """Remove duplicate entries by entry_id."""
        seen: set[str] = set()
        unique: list[KnowledgeEntry] = []
        for entry in entries:
            if entry.entry_id not in seen:
                seen.add(entry.entry_id)
                unique.append(entry)
        return unique

    def learn_from_scan(
        self,
        target: str,
        tool_name: str,
        success: bool,
        findings: list[str] | None = None,
        defense_detected: str = "",
        bypass_used: str = "",
    ) -> None:
        """Auto-learn from a completed scan step.

        Call this after each tool execution to accumulate knowledge.
        """
        # Tool effectiveness
        self.learn(
            category="tool_rating",
            key=f"tool:{tool_name}:{target}",
            content=f"{tool_name} on {target}: {'success' if success else 'failed'}",
            tags=[tool_name, target],
            confidence=0.6 if success else 0.3,
        )
        if success:
            self._increment_success(f"tool_rating:tool:{tool_name}:{target}")

        # Defense bypass recipe
        if defense_detected and bypass_used:
            self.learn(
                category="defense_bypass",
                key=f"bypass:{defense_detected}:{tool_name}",
                content=f"Against {defense_detected}, use: {bypass_used}",
                tags=[defense_detected.lower(), tool_name, "bypass"],
                confidence=0.8 if success else 0.3,
            )

        # Findings as lessons
        if findings:
            for finding in findings[:5]:
                if "CVE-" in finding or "VULNERABLE" in finding.upper():
                    self.learn(
                        category="lesson",
                        key=f"finding:{target}:{hash(finding) % 10000}",
                        content=finding[:300],
                        tags=[target, tool_name],
                        confidence=0.7,
                    )

    def cleanup_expired(self) -> int:
        """Remove expired entries."""
        if not self._conn:
            return 0
        try:
            cursor = self._conn.execute(
                "DELETE FROM knowledge WHERE expires_at < ?",
                (time.time(),),
            )
            self._conn.commit()
            count = cursor.rowcount
            self._stats["entries_expired"] += count
            return count
        except Exception:
            return 0

    def get_stats(self) -> dict[str, Any]:
        """Return KB statistics."""
        total = 0
        if self._conn:
            try:
                cursor = self._conn.execute("SELECT COUNT(*) FROM knowledge")
                total = cursor.fetchone()[0]
            except Exception:
                pass
        return {**self._stats, "total_entries": total}

    # ─────────────────── Internal Helpers ───────────────────

    def _increment_use_count(self, entry_id: str) -> None:
        """Increment use count for an entry."""
        if not self._conn:
            return
        try:
            self._conn.execute(
                "UPDATE knowledge SET use_count = use_count + 1 WHERE entry_id = ?",
                (entry_id,),
            )
            self._conn.commit()
        except Exception:
            pass

    def _increment_success(self, entry_id: str) -> None:
        """Increment success count for an entry."""
        if not self._conn:
            return
        try:
            self._conn.execute(
                "UPDATE knowledge SET success_count = success_count + 1 WHERE entry_id = ?",
                (entry_id,),
            )
            self._conn.commit()
        except Exception:
            pass

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
