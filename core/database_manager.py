"""
DRAKBEN Database Abstraction Layer (DAL)
Description: Centralized database connection manager supporting SQLite (default) and scalable to PostgreSQL.
Thread-safe singleton pattern.
"""

import sqlite3
import threading
import logging
from typing import Optional, List
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class DatabaseProvider:
    """Abstract Base Class for Database Providers (Future-proofing)"""

    def connect(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def execute(self, query: str, params: tuple = ()):
        raise NotImplementedError


class SQLiteProvider(DatabaseProvider):
    """Robust SQLite Provider with Connection Pooling logic (One per thread)"""

    _instance = None
    _lock = threading.Lock()

    def __init__(self, db_path: str = "drakben.db"):
        self.db_path = db_path
        self._local = threading.local()  # Thread-local storage for connections

    @classmethod
    def get_instance(cls, db_path: str = "drakben.db"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-specific connection"""
        if not hasattr(self._local, "conn"):
            # WAL mode is crucial for concurrency (Write-Ahead Logging)
            self._local.conn = sqlite3.connect(
                self.db_path, timeout=30.0, check_same_thread=False
            )
            self._local.conn.execute("PRAGMA journal_mode=WAL;")
            self._local.conn.execute("PRAGMA synchronous=NORMAL;")
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def close(self):
        """Close connection for current thread"""
        if hasattr(self._local, "conn"):
            try:
                self._local.conn.close()
            except:
                pass
            del self._local.conn

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        conn = self._get_conn()
        try:
            cur = conn.execute(query, params)
            # Optimize: Only commit if query modifies data
            if (
                query.strip()
                .upper()
                .startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER"))
            ):
                conn.commit()
            return cur
        except sqlite3.Error as e:
            logger.error(f"DB Error: {e} | Query: {query}")
            # Only rollback if we were in a write operation context (simplified)
            try:
                conn.rollback()
            except:
                pass
            raise

    def fetch_all(self, query: str, params: tuple = ()) -> List[dict]:
        cur = self.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def fetch_one(self, query: str, params: tuple = ()) -> Optional[dict]:
        cur = self.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None

    @contextmanager
    def transaction(self):
        """Context manager for atomic transactions"""
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
