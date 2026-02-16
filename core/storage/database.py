# core/storage/database.py
# DRAKBEN — Shared Database Manager
# Single SQLite connection pool and lifecycle management.
# Replaces 3+ independent SQLite connections (EvolutionMemory, SelfRefiningEngine, KnowledgeGraph).

"""Thread-safe SQLite connection management for DRAKBEN.

Usage::

    from core.storage.database import DatabaseManager

    db = DatabaseManager("data/evolution.db")
    with db.connection() as conn:
        conn.execute("SELECT 1")
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from core.config import TIMEOUTS

if TYPE_CHECKING:
    from collections.abc import Iterator

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Thread-safe SQLite connection manager with WAL mode and proper cleanup.

    Features:
    - WAL mode for concurrent reads
    - Connection timeout configuration
    - Thread-local connections for safety
    - Graceful close with commit
    - Context manager support
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        timeout: float = TIMEOUTS.SQLITE_CONNECT_TIMEOUT,
        wal_mode: bool = True,
    ) -> None:
        self._db_path = str(db_path)
        self._timeout = timeout
        self._wal_mode = wal_mode
        self._lock = threading.RLock()
        self._local = threading.local()
        self._closed = False

        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a thread-local connection."""
        conn = getattr(self._local, "conn", None)
        if conn is None or self._closed:
            if self._closed:
                msg = "DatabaseManager is closed"
                raise RuntimeError(msg)
            conn = sqlite3.connect(
                self._db_path,
                timeout=self._timeout,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            if self._wal_mode:
                conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA busy_timeout={TIMEOUTS.SQLITE_BUSY_TIMEOUT}")
            self._local.conn = conn
        return conn

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Context manager providing a SQLite connection.

        On success, commits. On error, rolls back and closes the connection
        to avoid stale state.
        """
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except sqlite3.Error:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            # Close stale connection
            self._close_local_conn()
            raise

    def execute(self, sql: str, params: tuple[Any, ...] | None = None) -> sqlite3.Cursor:
        """Execute a single SQL statement."""
        conn = self._get_conn()
        return conn.execute(sql, params or ())

    def executemany(self, sql: str, params_seq: Any) -> sqlite3.Cursor:
        """Execute a SQL statement with many parameter sets."""
        conn = self._get_conn()
        return conn.executemany(sql, params_seq)

    def commit(self) -> None:
        """Commit current transaction."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.commit()

    def close(self) -> None:
        """Close all connections and mark as closed."""
        with self._lock:
            self._closed = True
            self._close_local_conn()

    def _close_local_conn(self) -> None:
        """Close the thread-local connection."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None

    def __enter__(self) -> DatabaseManager:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except (sqlite3.Error, OSError):
            pass  # Destructor: best-effort cleanup
