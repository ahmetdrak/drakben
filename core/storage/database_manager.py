"""DRAKBEN Database Abstraction Layer (DAL)
Description: Centralized database connection manager supporting SQLite (default) and scalable to PostgreSQL.
Thread-safe singleton pattern.
"""

import logging
import sqlite3
import threading
from abc import ABC, abstractmethod
from contextlib import suppress

logger = logging.getLogger(__name__)


class DatabaseProvider(ABC):
    """Abstract Base Class for Database Providers (Future-proofing)."""

    @abstractmethod
    def connect(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        raise NotImplementedError


class SQLiteProvider(DatabaseProvider):
    """Robust SQLite Provider with Connection Pooling logic (One per thread)."""

    DB_NAME = "drakben.db"

    def __init__(self, db_path: str = DB_NAME) -> None:
        self.db_path = db_path
        self._local = threading.local()  # Thread-local storage for connections

    def connect(self) -> None:
        """Establish connection for current thread (lazy via _get_conn)."""
        self._get_conn()

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-specific connection."""
        if not hasattr(self._local, "conn"):
            # WAL mode is crucial for concurrency (Write-Ahead Logging)
            self._local.conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False,
            )
            self._local.conn.execute("PRAGMA journal_mode=WAL;")
            self._local.conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def close(self) -> None:
        """Close connection for current thread."""
        if hasattr(self._local, "conn"):
            with suppress(Exception):
                self._local.conn.close()
            del self._local.conn

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        import time

        conn = self._get_conn()
        last_error = None
        for attempt in range(5):
            try:
                cur = conn.execute(query, params)
                # Optimize: Only commit if query modifies data
                if (
                    query.strip()
                    .upper()
                    .startswith(
                        ("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER"),
                    )
                ):
                    conn.commit()
                return cur
            except sqlite3.OperationalError as e:
                last_error = e
                if "locked" in str(e).lower() and attempt < 4:
                    time.sleep(0.1 * (attempt + 1))
                    continue
                # For other errors or final attempt, rollback and raise
                with suppress(Exception):
                    conn.rollback()
                raise
            except sqlite3.Error as e:
                logger.exception("DB Error: %s | Query: %s", e, query)
                with suppress(Exception):
                    conn.rollback()
                raise
        # Defensive: This should be unreachable — every loop iteration either
        # returns (success), raises (non-locked error / final attempt), or
        # continues (locked + not final). Kept as safety net.
        if last_error is None:
            msg = "Database operation failed without an error instance"
            raise sqlite3.OperationalError(msg)
        raise last_error
