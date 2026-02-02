# core/evolution_memory.py
# REAL PERSISTENT EVOLUTION MEMORY
# This file implements MANDATORY persistent memory that AFFECTS decision making

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ActionRecord:
    """Single action record - MANDATORY FIELDS."""

    goal: str
    plan_id: str
    step_id: str
    action_name: str
    tool: str
    parameters: str  # JSON serialized
    outcome: str  # "success" | "failure"
    timestamp: float
    penalty_score: float
    error_message: str = ""


@dataclass
class PlanRecord:
    """Plan record for replanning."""

    plan_id: str
    goal: str
    steps: str  # JSON serialized list
    status: str  # "pending" | "executing" | "completed" | "failed" | "replanned"
    created_at: float
    updated_at: float
    attempt_count: int = 1


class EvolutionMemory:
    """REAL PERSISTENT EVOLUTION MEMORY.

    GUARANTEES:
    1. All data survives process restart (SQLite)
    2. Penalty scores affect tool selection BEFORE execution
    3. Failed tools are blocked after threshold
    4. Plans are persisted and support replanning
    """

    PENALTY_INCREMENT = 10.0
    PENALTY_DECREMENT = 5.0
    BLOCK_THRESHOLD = 50.0  # Tool blocked after this penalty

    def __init__(self, db_path: str = "drakben_evolution.db") -> None:
        # Handle in-memory databases specially
        if db_path == ":memory:":
            self.db_path = db_path
            self._is_memory = True
            self._persistent_conn = None  # Will hold the connection for in-memory mode
        else:
            self.db_path = str(Path(db_path))
            self._is_memory = False
            self._persistent_conn = None
        self._lock = threading.Lock()
        self._init_database()

    def _init_database(self) -> None:
        """Create tables if not exist.

        Improvements:
        - Timeout protection on connection
        - WAL mode for concurrency
        - Proper error handling
        """
        import logging

        logger = logging.getLogger(__name__)

        with self._lock:
            db_path_str = (
                self.db_path if isinstance(self.db_path, str) else str(self.db_path)
            )

            try:
                conn = sqlite3.connect(
                    db_path_str,
                    timeout=10.0,
                    check_same_thread=False,
                )
                conn.row_factory = sqlite3.Row

                # Enable WAL mode for better concurrency
                try:
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute("PRAGMA busy_timeout=10000")
                except sqlite3.OperationalError:
                    pass  # WAL might not be available

                # For in-memory databases, keep the connection open
                if self._is_memory:
                    self._persistent_conn = conn

                cursor = conn.cursor()
            except sqlite3.OperationalError as e:
                logger.exception("Database initialization failed: %s", e)
                msg = f"Could not initialize evolution database: {e}"
                raise RuntimeError(msg) from e

            # ACTION HISTORY TABLE - stores every action with outcome
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS action_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    goal TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    step_id TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    parameters TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    penalty_score REAL NOT NULL,
                    error_message TEXT DEFAULT ''
                )
            """)

            # TOOL PENALTIES TABLE - cumulative penalty per tool and target
            # LOGIC FIX: Penalties are now per-target to prevent global tool blocking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_penalties (
                    tool TEXT NOT NULL,
                    target TEXT NOT NULL,
                    penalty_score REAL DEFAULT 0.0,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    last_used REAL,
                    blocked INTEGER DEFAULT 0,
                    PRIMARY KEY (tool, target)
                )
            """)

            # Migration: Ensure 'target' column exists in tool_penalties (LOGIC FIX)
            try:
                cursor.execute("SELECT target FROM tool_penalties LIMIT 1")
            except sqlite3.OperationalError:
                logger.info("Migrating tool_penalties: adding 'target' column")
                # SQLite doesn't support adding to PRIMARY KEY directly, so we drop and recreate if needed
                # But for safety in migration, we add column first
                cursor.execute(
                    "ALTER TABLE tool_penalties ADD COLUMN target TEXT NOT NULL DEFAULT 'global'",
                )
                # Re-create index/PK requires more steps, but adding column solves the query error
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS plans (
                    plan_id TEXT PRIMARY KEY,
                    goal TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    attempt_count INTEGER DEFAULT 1
                )
            """)

            # HEURISTICS TABLE - self-modifying parameters
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS heuristics (
                    key TEXT PRIMARY KEY,
                    value REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

            # Initialize default heuristics if not exist
            defaults = [
                ("max_retries", 3.0),
                ("penalty_increment", 10.0),
                ("penalty_decrement", 5.0),
                ("block_threshold", 50.0),
                ("stagnation_limit", 3.0),
            ]
            for key, val in defaults:
                cursor.execute(
                    "INSERT OR IGNORE INTO heuristics (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, val, time.time()),
                )

            conn.commit()
            # Don't close the connection for in-memory databases
            if not self._is_memory:
                self._close_conn(conn)

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection with timeout protection and WAL mode.

        Improvements:
        - timeout=10.0 to prevent indefinite blocking
        - WAL mode for better concurrency
        - busy_timeout PRAGMA for SQLite-level timeout
        - Proper error handling with logging
        """
        # For in-memory databases, return the persistent connection
        if self._is_memory and self._persistent_conn:
            return self._persistent_conn

        db_path_str = (
            self.db_path if isinstance(self.db_path, str) else str(self.db_path)
        )

        try:
            conn = sqlite3.connect(db_path_str, timeout=10.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row

            # Enable WAL mode for better concurrency (reduces lock contention)
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=10000")  # 10 second busy timeout
            except sqlite3.OperationalError:
                pass  # WAL might not be available, continue anyway

            return conn
        except sqlite3.OperationalError as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.exception("Database connection failed: %s", e)
            raise

    def _close_conn(self, conn: sqlite3.Connection) -> None:
        """Close connection, unless it's an in-memory persistent connection."""
        if not self._is_memory:
            conn.close()

    # ==================== ACTION RECORDING ====================

    def record_action(self, record: ActionRecord) -> None:
        """Record action outcome - PERSISTENT."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO action_history
                (goal, plan_id, step_id, action_name, tool, parameters, outcome, timestamp, penalty_score, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    record.goal,
                    record.plan_id,
                    record.step_id,
                    record.action_name,
                    record.tool,
                    record.parameters,
                    record.outcome,
                    record.timestamp,
                    record.penalty_score,
                    record.error_message,
                ),
            )
            conn.commit()
            self._close_conn(conn)

    # ==================== PENALTY SYSTEM ====================
    def _run_with_retry(self, func, *args, **kwargs) -> Any:
        """Helper to retry DB operations on lock."""
        for i in range(5):
            try:
                return func(*args, **kwargs)
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and i < 4:
                    time.sleep(0.1 * (i + 1))
                    continue
                raise
        return None

    def update_penalty(self, tool: str, success: bool, target: str = "global") -> None:
        """Update tool penalty score.
        Called AFTER every tool execution.
        """
        target = target or "global"
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            # Get current state
            cursor.execute(
                "SELECT * FROM tool_penalties WHERE tool = ? AND target = ?",
                (tool, target),
            )
            row = cursor.fetchone()

            if row is None:
                # New tool/target combo
                penalty = 0.0 if success else self.PENALTY_INCREMENT
                cursor.execute(
                    """
                    INSERT INTO tool_penalties (tool, target, penalty_score, success_count, failure_count, last_used, blocked)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        tool,
                        target,
                        penalty,
                        1 if success else 0,
                        0 if success else 1,
                        time.time(),
                        0,
                    ),
                )
            else:
                current_penalty = row["penalty_score"]
                success_count = row["success_count"]
                failure_count = row["failure_count"]

                if success:
                    new_penalty = max(0.0, current_penalty - self.PENALTY_DECREMENT)
                    success_count += 1
                else:
                    new_penalty = current_penalty + self.PENALTY_INCREMENT
                    failure_count += 1

                blocked = 1 if new_penalty >= self.BLOCK_THRESHOLD else 0

                cursor.execute(
                    """
                    UPDATE tool_penalties
                    SET penalty_score = ?, success_count = ?, failure_count = ?, last_used = ?, blocked = ?
                    WHERE tool = ? AND target = ?
                """,
                    (
                        new_penalty,
                        success_count,
                        failure_count,
                        time.time(),
                        blocked,
                        tool,
                        target,
                    ),
                )

            conn.commit()
            self._close_conn(conn)

    def get_tool_penalty(self, tool: str, target: str = "global") -> float:
        """Get current penalty for tool/target combo."""
        target = target or "global"
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT penalty_score FROM tool_penalties WHERE tool = ? AND target = ?",
                (tool, target),
            )
            row = cursor.fetchone()
            self._close_conn(conn)
            return row["penalty_score"] if row else 0.0

    def get_penalty(self, tool: str, target: str = "global") -> float:
        """Alias for get_tool_penalty - compatibility with tool_selector.py."""
        return self.get_tool_penalty(tool, target)

    def is_tool_blocked(self, tool: str, target: str = "global") -> bool:
        """Check if tool is blocked due to high penalty.
        MUST be called BEFORE tool selection.
        """
        target = target or "global"
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT blocked, penalty_score FROM tool_penalties WHERE tool = ? AND target = ?",
                (tool, target),
            )
            row = cursor.fetchone()
            self._close_conn(conn)
            if row is None:
                return False
            return row["blocked"] == 1 or row["penalty_score"] >= self.BLOCK_THRESHOLD

    def get_allowed_tools(self, tool_list: list[str]) -> list[str]:
        """Filter tool list by penalty.
        Returns only non-blocked tools, sorted by penalty (lowest first).
        """
        result = []
        penalties = []

        for tool in tool_list:
            if not self.is_tool_blocked(tool):
                result.append(tool)
                penalties.append((tool, self.get_tool_penalty(tool)))

        # Sort by penalty ascending (prefer low-penalty tools)
        penalties.sort(key=lambda x: x[1])
        return [t[0] for t in penalties]

    def get_all_penalties(self) -> dict[str, dict]:
        """Get all tool penalties for debugging."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tool_penalties")
            rows = cursor.fetchall()
            self._close_conn(conn)
            return {row["tool"]: dict(row) for row in rows}

    # ==================== PLAN MANAGEMENT ====================

    def create_plan(
        self,
        goal: str,
        steps: list[dict],
        plan_id: str | None = None,
    ) -> str:
        """Create new plan - PERSISTENT."""
        plan_id = plan_id or f"plan_{int(time.time() * 1000)}"
        now = time.time()

        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO plans (plan_id, goal, steps, status, created_at, updated_at, attempt_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (plan_id, goal, json.dumps(steps), "pending", now, now, 1),
            )
            conn.commit()
            self._close_conn(conn)

        return plan_id

    def get_plan(self, plan_id: str) -> PlanRecord | None:
        """Get plan by ID."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM plans WHERE plan_id = ?", (plan_id,))
            row = cursor.fetchone()
            self._close_conn(conn)

            if row is None:
                return None

            return PlanRecord(
                plan_id=row["plan_id"],
                goal=row["goal"],
                steps=row["steps"],
                status=row["status"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                attempt_count=row["attempt_count"],
            )

    def update_plan_status(self, plan_id: str, status: str) -> None:
        """Update plan status."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE plans SET status = ?, updated_at = ? WHERE plan_id = ?
            """,
                (status, time.time(), plan_id),
            )
            conn.commit()
            self._close_conn(conn)

    def update_plan_steps(self, plan_id: str, steps: list[dict]) -> None:
        """Update plan steps (for replanning)."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE plans SET steps = ?, status = 'replanned', updated_at = ?, attempt_count = attempt_count + 1
                WHERE plan_id = ?
            """,
                (json.dumps(steps), time.time(), plan_id),
            )
            conn.commit()
            self._close_conn(conn)

    def get_active_plan(self, goal: str) -> PlanRecord | None:
        """Get most recent non-completed plan for goal."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM plans
                WHERE goal = ? AND status NOT IN ('completed', 'failed')
                ORDER BY created_at DESC LIMIT 1
            """,
                (goal,),
            )
            row = cursor.fetchone()
            self._close_conn(conn)

            if row is None:
                return None

            return PlanRecord(
                plan_id=row["plan_id"],
                goal=row["goal"],
                steps=row["steps"],
                status=row["status"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                attempt_count=row["attempt_count"],
            )

    # ==================== HEURISTICS (SELF-MODIFICATION) ====================

    def get_heuristic(self, key: str) -> float:
        """Get heuristic value."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM heuristics WHERE key = ?", (key,))
            row = cursor.fetchone()
            self._close_conn(conn)
            return row["value"] if row else 0.0

    def set_heuristic(self, key: str, value: float) -> None:
        """Set heuristic value - THIS IS SELF-MODIFICATION."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO heuristics (key, value, updated_at)
                VALUES (?, ?, ?)
            """,
                (key, value, time.time()),
            )
            conn.commit()
            self._close_conn(conn)

    def adjust_heuristic(self, key: str, delta: float) -> None:
        """Adjust heuristic by delta - SELF-MODIFICATION."""
        current = self.get_heuristic(key)
        self.set_heuristic(key, current + delta)

    def update_heuristic(self, key: str, func: Any) -> None:
        """Update heuristic using a lambda function."""
        current = self.get_heuristic(key)
        new_value = func(current)
        self.set_heuristic(key, new_value)

    def get_all_heuristics(self) -> dict[str, float]:
        """Get all heuristics."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM heuristics")
            rows = cursor.fetchall()
            self._close_conn(conn)
            return {row["key"]: row["value"] for row in rows}

    # ==================== STAGNATION DETECTION ====================

    def get_recent_actions(self, count: int = 5) -> list[ActionRecord]:
        """Get last N actions."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM action_history ORDER BY timestamp DESC LIMIT ?
            """,
                (count,),
            )
            rows = cursor.fetchall()
            self._close_conn(conn)

            return [
                ActionRecord(
                    goal=row["goal"],
                    plan_id=row["plan_id"],
                    step_id=row["step_id"],
                    action_name=row["action_name"],
                    tool=row["tool"],
                    parameters=row["parameters"],
                    outcome=row["outcome"],
                    timestamp=row["timestamp"],
                    penalty_score=row["penalty_score"],
                    error_message=row["error_message"],
                )
                for row in rows
            ]

    def detect_stagnation(self) -> bool:
        """Detect if agent is stuck:
        - Same tool called 3+ times consecutively
        - All recent actions failed.
        """
        recent = self.get_recent_actions(5)
        if len(recent) < 3:
            return False

        # Check same tool repeated
        tools = [a.tool for a in recent[:3]]
        if len(set(tools)) == 1:
            return True

        # Check all failures
        outcomes = [a.outcome for a in recent]
        return bool(all(o == "failure" for o in outcomes))

    def detect_tool_abuse(self, tool: str, threshold: int = 3) -> bool:
        """Detect if specific tool is being abused."""
        recent = self.get_recent_actions(threshold)
        if len(recent) < threshold:
            return False

        return all(a.tool == tool for a in recent[:threshold])


# Global instance
_evolution_memory: EvolutionMemory | None = None


def get_evolution_memory(db_path: str | None = None) -> EvolutionMemory:
    """Get singleton instance (optionally override db_path)."""
    global _evolution_memory
    if _evolution_memory is None:
        _evolution_memory = EvolutionMemory(db_path or "drakben_evolution.db")
        return _evolution_memory

    current_path = (
        str(_evolution_memory.db_path)
        if not isinstance(_evolution_memory.db_path, str)
        else _evolution_memory.db_path
    )

    if db_path:
        if current_path != db_path:
            _evolution_memory = EvolutionMemory(db_path)
            return _evolution_memory
    elif not _evolution_memory._is_memory and not Path(current_path).exists():
        # If the backing file was removed, re-initialize to restore tables
        _evolution_memory = EvolutionMemory(current_path)

    return _evolution_memory
