"""DRAKBEN Database Abstraction Layer (DAL)
Description: Centralized database connection manager supporting SQLite (default) and scalable to PostgreSQL.
Thread-safe singleton pattern.
"""

import logging
import sqlite3
import threading
from contextlib import contextmanager, suppress
from typing import Any, NoReturn

logger = logging.getLogger(__name__)


class DatabaseProvider:
    """Abstract Base Class for Database Providers (Future-proofing)."""

    def connect(self) -> NoReturn:
        raise NotImplementedError

    def close(self) -> NoReturn:
        raise NotImplementedError

    def execute(self, query: str, params: tuple = ()) -> NoReturn:
        raise NotImplementedError


class SQLiteProvider(DatabaseProvider):
    """Robust SQLite Provider with Connection Pooling logic (One per thread)."""

    _instance = None
    _lock = threading.Lock()
    DB_NAME = "drakben.db"

    def __init__(self, db_path: str = DB_NAME) -> None:
        self.db_path = db_path
        self._local = threading.local()  # Thread-local storage for connections

    @classmethod
    def get_instance(cls, db_path: str = DB_NAME) -> Any:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

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
        # This part should theoretically not be reached if continue/raise logic is correct
        if last_error is None:
            raise sqlite3.OperationalError("Database operation failed without an error instance")
        raise last_error

    def fetch_all(self, query: str, params: tuple = ()) -> list[dict]:
        cur = self.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def fetch_one(self, query: str, params: tuple = ()) -> dict | None:
        cur = self.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None

    @contextmanager
    def transaction(self) -> Any:
        """Context manager for atomic transactions."""
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


# Global Accessor
def get_db(db_path: str = "drakben.db") -> SQLiteProvider:
    return SQLiteProvider.get_instance(db_path)
