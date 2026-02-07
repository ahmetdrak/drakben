"""SELF-REFINING EVOLVING AGENT ENGINE.
===================================

This module implements a STRONG self-refining agent with:
- Strategy Profiles (behavioral variants)
- Policy Engine with Conflict Resolution
- Profile Mutation on Failure
- Restart Evolution Guarantee

Author: Drakben Team
"""

import copy
import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager, suppress
from datetime import datetime
from typing import Any, NoReturn

from core.intelligence.sre_failure import SREFailureMixin
from core.intelligence.sre_models import (
    SCHEMA_SQL,
    Policy,  # noqa: F401 (re-exported)
    PolicyTier,
    Strategy,
    StrategyProfile,
)
from core.intelligence.sre_mutation import SREMutationMixin
from core.intelligence.sre_policy import SREPolicyMixin

logger = logging.getLogger(__name__)


# =============================================================================
# SELF-REFINING ENGINE
# =============================================================================


class SelfRefiningEngine(SREPolicyMixin, SREMutationMixin, SREFailureMixin):
    """STRONG SELF-REFINING EVOLVING AGENT ENGINE.

    This engine provides:
    1. Strategy and Profile management
    2. Policy-based behavior modification
    3. Deterministic conflict resolution
    4. Profile mutation on failure
    5. Restart evolution guarantee
    """

    # Thresholds
    PROFILE_RETIRE_THRESHOLD = 0.25  # Retire if success_rate < 25%
    MIN_USAGE_FOR_RETIRE = 3  # Minimum uses before retirement
    MUTATION_PARAM_CHANGE = 0.2  # How much to change params on mutation

    def __init__(self, db_path: str | None = None) -> None:
        # Use consistent database naming with EvolutionMemory
        if db_path is None:
            # Check if drakben_evolution.db exists (for compatibility)
            import os

            if os.path.exists("drakben_evolution.db"):
                self.db_path = "drakben_evolution.db"
            else:
                self.db_path = "evolution.db"
        else:
            self.db_path = db_path
        self._lock = threading.RLock()  # Reentrant lock to prevent deadlocks
        self._initialized = False
        self._init_lock = threading.RLock()  # Reentrant lock

        # LAZY INITIALIZATION: Don't initialize database in __init__
        # This prevents blocking during object creation
        # Database will be initialized on first use
        logger.debug("SelfRefiningEngine created (lazy initialization)")

    def _generate_id(self, prefix: str = "") -> str:
        """Generate a unique ID with optional prefix."""
        return f"{prefix}{uuid.uuid4().hex[:12]}"

    def _ensure_initialized(self) -> None:
        """Ensure database is initialized (lazy initialization).

        Improvements:
        - On failure, _initialized stays False to allow retry
        - Added retry counter to prevent infinite retry loops
        - Better error handling and logging
        """
        if self._initialized:
            return

        # Track retry attempts to prevent infinite loops
        if not hasattr(self, "_init_attempts"):
            self._init_attempts = 0

        # Max 3 retry attempts
        if self._init_attempts >= 3:
            logger.warning(
                "Max initialization attempts reached, skipping database init",
            )
            return

        with self._init_lock:
            # Double-check after acquiring lock
            if self._initialized:
                return

            self._init_attempts += 1

            try:
                logger.info(
                    f"Initializing SelfRefiningEngine database (attempt {self._init_attempts}/3)...",
                )
                self._init_database()
                self._seed_default_strategies()
                self._initialized = True
                logger.info("SelfRefiningEngine database initialized successfully")
            except Exception as e:
                logger.exception("Failed to initialize SelfRefiningEngine: %s", e)
                logger.exception("Initialization error details")
                # DON'T set _initialized = True on failure
                # This allows retry on next use (up to max attempts)

    def _connect_raw(self) -> sqlite3.Connection:
        """Internal low-level connection creator without init check."""
        # Set timeout to prevent indefinite blocking (5 seconds)
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency (reduces lock contention)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")  # 5 second busy timeout
        except sqlite3.OperationalError:
            pass  # WAL might not be available, continue anyway
        return conn

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection with timeout protection."""
        # Ensure database is initialized before getting connection
        self._ensure_initialized()
        return self._connect_raw()

    @contextmanager
    def _db_operation(self, timeout: float = 5.0) -> Any:
        """Safe database operation context manager.

        Automatically handles:
        - Lock acquisition with timeout
        - Connection management
        - Commit on success
        - Proper cleanup on failure

        Usage:
            with self._db_operation() as conn:
                cursor = conn.execute(...)
                # conn.commit() is called automatically on success
        """
        acquired = self._lock.acquire(timeout=timeout)
        if not acquired:
            msg = "Database lock acquisition timeout - possible deadlock"
            raise TimeoutError(msg)

        conn = None
        try:
            conn = self._get_conn()
            yield conn
            conn.commit()
        except Exception as e:
            logger.exception("Database operation failed: %s", e)
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except (sqlite3.Error, AttributeError) as e:
                    logger.debug("Error closing connection: %s", e)
            try:
                self._lock.release()
            except (RuntimeError, AttributeError) as e:
                logger.debug("Error releasing lock: %s", e)

    def _init_database(self) -> None:
        """Initialize database schema with migration support."""
        # 1. Acquire Lock
        lock_acquired = self._acquire_db_lock()
        if not lock_acquired:
            logger.error("Failed to acquire lock for database init")
            msg = "Lock acquisition timeout - possible deadlock"
            raise RuntimeError(msg)

        conn = None
        try:
            # 2. Connect and Migrate
            conn = self._connect_raw()
            self._handle_schema_migration(conn)

            # 3. Create Schema
            conn.executescript(SCHEMA_SQL)
            conn.commit()

        except sqlite3.OperationalError as e:
            self._handle_db_error(e)
        finally:
            self._cleanup_conn_and_lock(conn, lock_acquired)

    def _acquire_db_lock(
        self,
        max_retries: int = 3,
        timeout_per_attempt: float = 1.5,
    ) -> bool:
        """Attempt to acquire database lock with retries.

        Args:
            max_retries: Maximum number of retry attempts
            timeout_per_attempt: Timeout per attempt in seconds

        Returns:
            True if lock acquired, False otherwise

        """
        for attempt in range(max_retries):
            try:
                if self._lock.acquire(timeout=timeout_per_attempt):
                    return True
                logger.warning("Lock wait attempt %s/%s", attempt + 1, max_retries)
                time.sleep(0.3)  # Short sleep before retry
            except Exception as e:
                logger.exception("Lock error: %s", e)

        logger.error(
            "Failed to acquire lock after %s attempts - possible deadlock", max_retries,
        )
        return False

    def _handle_schema_migration(self, conn: sqlite3.Connection) -> None:
        """Check and migrate old schema conservatively (LOGIC FIX: Don't drop data)."""
        cursor = conn.execute("PRAGMA user_version")
        version = cursor.fetchone()[0]

        if version == 1:
            logger.info(
                "Migrating database from v1 to v2: Adding structural improvements",
            )
            # LOGIC FIX: Add parameter_hash to prevent duplicate profile mutations
            try:
                conn.execute(
                    "ALTER TABLE strategy_profiles ADD COLUMN parameter_hash TEXT",
                )
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_params ON strategy_profiles(strategy_name, parameter_hash)",
                )
            except sqlite3.OperationalError:
                pass
            conn.execute("PRAGMA user_version = 2")
            conn.commit()

    def _handle_db_error(self, e: Exception) -> NoReturn:
        """Handle database specific errors."""
        logger.error("Database operation failed: %s", e)
        if "locked" in str(e).lower():
            logger.error("Database is locked by another process.")
        msg = f"Database error: {e}"
        raise RuntimeError(msg) from e

    def _seed_default_strategies(self) -> None:
        """Seed default strategies if none exist."""
        import time

        max_duration = 10
        start_time = time.time()

        # Acquire lock safely
        lock_acquired = self._acquire_lock_safe()
        if not lock_acquired:
            return

        conn = None
        try:
            conn = self._connect_raw()
            if self._strategies_exist(conn):
                return

            default_strategies = self._get_default_strategy_definitions()

            # Batch Insert Strategies
            self._batch_insert_strategies(
                conn,
                default_strategies,
                start_time,
                max_duration,
            )

            # Create Profiles
            self._create_profiles_batch(
                conn,
                default_strategies,
                start_time,
                max_duration,
            )

            conn.commit()

        except sqlite3.OperationalError as e:
            logger.exception("Database error during seeding: %s", e)
        except Exception as e:
            logger.exception("Unexpected error during seeding: %s", e)
        finally:
            self._cleanup_conn_and_lock(conn, lock_acquired)

    def _acquire_lock_safe(self, max_retries: int = 2) -> bool:
        """Helper to acquire lock safely."""
        for _ in range(max_retries):
            try:
                if self._lock.acquire(timeout=1.5):
                    return True
                time.sleep(0.5)
            except Exception as e:
                logger.exception("Lock error: %s", e)
        return False

    def _strategies_exist(self, conn: "sqlite3.Connection") -> bool:
        """Check if strategies table is populated."""
        cursor = conn.execute("SELECT COUNT(*) FROM strategies")
        return cursor.fetchone()[0] > 0

    def _get_default_strategy_definitions(self) -> list[dict]:
        """Return list of default strategies."""
        return [
            {
                "name": "aggressive_scan",
                "target_type": "network_host",
                "description": "Fast aggressive network scanning",
                "base_parameters": {
                    "scan_speed": "fast",
                    "stealth": False,
                    "parallel_scans": 10,
                    "timeout": 30,
                },
            },
            {
                "name": "stealth_scan",
                "target_type": "network_host",
                "description": "Slow stealthy network scanning",
                "base_parameters": {
                    "scan_speed": "slow",
                    "stealth": True,
                    "parallel_scans": 1,
                    "timeout": 120,
                },
            },
            {
                "name": "web_aggressive",
                "target_type": "web_app",
                "description": "Aggressive web application testing",
                "base_parameters": {
                    "threads": 10,
                    "follow_redirects": True,
                    "test_all_params": True,
                    "timeout": 30,
                },
            },
            {
                "name": "web_stealth",
                "target_type": "web_app",
                "description": "Stealthy web application testing",
                "base_parameters": {
                    "threads": 1,
                    "follow_redirects": False,
                    "test_all_params": False,
                    "timeout": 60,
                },
            },
            {
                "name": "api_fuzzing",
                "target_type": "api_endpoint",
                "description": "API endpoint fuzzing",
                "base_parameters": {
                    "fuzz_depth": 3,
                    "auth_bypass": True,
                    "rate_limit": 10,
                },
            },
            {
                "name": "api_enumeration",
                "target_type": "api_endpoint",
                "description": "API endpoint enumeration",
                "base_parameters": {
                    "discover_endpoints": True,
                    "test_methods": ["GET", "POST", "PUT", "DELETE"],
                    "rate_limit": 5,
                },
            },
        ]

    def _batch_insert_strategies(
        self,
        conn: "sqlite3.Connection",
        strategies: list[dict[str, Any]],
        start_time: float,
        max_duration: float,
    ) -> None:
        """Insert strategies in batch."""
        import time

        now = datetime.now().isoformat()
        strategy_inserts = []

        for strat in strategies:
            if time.time() - start_time > max_duration:
                break

            strategy_id = self._generate_id("strat_")
            strategy_inserts.append(
                (
                    strategy_id,
                    strat["name"],
                    strat["target_type"],
                    strat["description"],
                    json.dumps(strat["base_parameters"]),
                    now,
                ),
            )

        if strategy_inserts:
            conn.executemany(
                """
                INSERT INTO strategies (strategy_id, name, target_type, description, base_parameters, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                strategy_inserts,
            )

    def _create_profiles_batch(
        self,
        conn: "sqlite3.Connection",
        strategies: list[dict[str, Any]],
        start_time: float,
        max_duration: float,
    ) -> None:
        """Create profiles for strategies."""
        import time

        now = datetime.now().isoformat()

        for strat in strategies:
            if time.time() - start_time > max_duration:
                break
            try:
                self._create_initial_profiles(
                    conn,
                    strat["name"],
                    strat["base_parameters"],
                    now,
                )
            except Exception as e:
                logger.exception("Failed profile creation for %s: %s", strat["name"], e)

    def _cleanup_conn_and_lock(
        self, conn: "sqlite3.Connection | None", lock_acquired: bool,
    ) -> None:
        """Cleanup connection and release lock."""
        if conn:
            try:
                conn.close()
            except (sqlite3.Error, AttributeError) as e:
                logger.debug("Error closing connection: %s", e)
        if lock_acquired:
            try:
                self._lock.release()
            except (RuntimeError, AttributeError) as e:
                logger.debug("Error releasing lock: %s", e)

    def _create_initial_profiles(
        self,
        conn: sqlite3.Connection,
        strategy_name: str,
        base_params: dict,
        created_at: str,
    ) -> None:
        """Create initial behavioral profiles for a strategy."""
        # Profile 1: Default (balanced)
        profile1 = {
            "profile_id": self._generate_id("prof_"),
            "strategy_name": strategy_name,
            "parameters": base_params,
            "step_order": ["recon", "scan", "analyze", "exploit"],
            "aggressiveness": 0.5,
            "tool_preferences": [],
        }

        # Profile 2: Aggressive variant
        aggressive_params = copy.deepcopy(base_params)
        for key in aggressive_params:
            if isinstance(aggressive_params[key], int | float):
                # LOGIC FIX: Ensure mutation actually changes value even if it is 1
                aggressive_params[key] = max(
                    aggressive_params[key] + 1, int(aggressive_params[key] * 1.5),
                )

        profile2 = {
            "profile_id": self._generate_id("prof_"),
            "strategy_name": strategy_name,
            "parameters": aggressive_params,
            "step_order": ["scan", "exploit", "recon", "analyze"],  # Different order
            "aggressiveness": 0.8,
            "tool_preferences": [],
        }

        # Profile 3: Conservative variant
        conservative_params = copy.deepcopy(base_params)
        for key in conservative_params:
            if isinstance(conservative_params[key], int | float):
                # LOGIC FIX: Ensure conservative is actually different
                val = int(conservative_params[key] * 0.5)
                conservative_params[key] = max(
                    1, val if val != aggressive_params.get(key) else max(1, val - 1),
                )

        profile3 = {
            "profile_id": self._generate_id("prof_"),
            "strategy_name": strategy_name,
            "parameters": conservative_params,
            "step_order": ["recon", "analyze", "scan", "exploit"],  # Different order
            "aggressiveness": 0.2,
            "tool_preferences": [],
        }

        for profile in [profile1, profile2, profile3]:
            conn.execute(
                """
                INSERT INTO strategy_profiles
                (profile_id, strategy_name, parameters, step_order, aggressiveness,
                 tool_preferences, success_rate, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0.4, ?)  -- LOGIC FIX: Start lower (0.4) to prefer tested ones
            """,
                (
                    profile["profile_id"],
                    profile["strategy_name"],
                    json.dumps(profile["parameters"]),
                    json.dumps(profile["step_order"]),
                    profile["aggressiveness"],
                    json.dumps(profile["tool_preferences"]),
                    created_at,
                ),
            )

    def get_strategy(self, name: str) -> Strategy | None:
        """Get strategy by name."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "SELECT * FROM strategies WHERE name = ? AND is_active = 1",
                    (name,),
                )
                row = cursor.fetchone()
                if row:
                    return Strategy(
                        strategy_id=row["strategy_id"],
                        name=row["name"],
                        target_type=row["target_type"],
                        description=row["description"],
                        base_parameters=json.loads(row["base_parameters"]),
                        created_at=row["created_at"],
                        is_active=bool(row["is_active"]),
                    )
                return None
            finally:
                conn.close()

    def get_strategies_for_target_type(self, target_type: str) -> list[Strategy]:
        """Get all active strategies for a target type."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "SELECT * FROM strategies WHERE target_type = ? AND is_active = 1",
                    (target_type,),
                )
                strategies = [
                    Strategy(
                        strategy_id=row["strategy_id"],
                        name=row["name"],
                        target_type=row["target_type"],
                        description=row["description"],
                        base_parameters=json.loads(row["base_parameters"]),
                        created_at=row["created_at"],
                        is_active=bool(row["is_active"]),
                    )
                    for row in cursor.fetchall()
                ]
                return strategies
            finally:
                conn.close()

    # =========================================================================
    # PROFILE MANAGEMENT
    # =========================================================================

    def get_profiles_for_strategy(
        self,
        strategy_name: str,
        include_retired: bool = False,
    ) -> list[StrategyProfile]:
        """Get all profiles for a strategy."""
        with self._lock:
            conn = self._get_conn()
            try:
                if include_retired:
                    cursor = conn.execute(
                        "SELECT * FROM strategy_profiles WHERE strategy_name = ?",
                        (strategy_name,),
                    )
                else:
                    cursor = conn.execute(
                        "SELECT * FROM strategy_profiles WHERE strategy_name = ? AND retired = 0",
                        (strategy_name,),
                    )

                profiles = [
                    StrategyProfile(
                        profile_id=row["profile_id"],
                        strategy_name=row["strategy_name"],
                        parameters=json.loads(row["parameters"]),
                        step_order=json.loads(row["step_order"]),
                        aggressiveness=row["aggressiveness"],
                        tool_preferences=json.loads(row["tool_preferences"])
                        if row["tool_preferences"]
                        else [],
                        success_rate=row["success_rate"],
                        usage_count=row["usage_count"],
                        success_count=row["success_count"],
                        failure_count=row["failure_count"],
                        retired=bool(row["retired"]),
                        parent_profile_id=row["parent_profile_id"],
                        mutation_generation=row["mutation_generation"],
                        created_at=row["created_at"],
                        last_used_at=row["last_used_at"],
                    )
                    for row in cursor.fetchall()
                ]
                return profiles
            finally:
                conn.close()

    def get_profile(self, profile_id: str) -> StrategyProfile | None:
        """Get a specific profile by ID."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "SELECT * FROM strategy_profiles WHERE profile_id = ?",
                    (profile_id,),
                )
                row = cursor.fetchone()
                if row:
                    return StrategyProfile(
                        profile_id=row["profile_id"],
                        strategy_name=row["strategy_name"],
                        parameters=json.loads(row["parameters"]),
                        step_order=json.loads(row["step_order"]),
                        aggressiveness=row["aggressiveness"],
                        tool_preferences=json.loads(row["tool_preferences"])
                        if row["tool_preferences"]
                        else [],
                        success_rate=row["success_rate"],
                        usage_count=row["usage_count"],
                        success_count=row["success_count"],
                        failure_count=row["failure_count"],
                        retired=bool(row["retired"]),
                        parent_profile_id=row["parent_profile_id"],
                        mutation_generation=row["mutation_generation"],
                        created_at=row["created_at"],
                        last_used_at=row["last_used_at"],
                    )
                return None
            finally:
                conn.close()

    def select_best_profile(
        self,
        strategy_name: str,
        excluded_profile_ids: list[str] | None = None,
    ) -> StrategyProfile | None:
        """Select best non-retired profile for a strategy.
        If all profiles are retired, trigger mutation and return new profile.
        """
        excluded = excluded_profile_ids or []

        with self._lock:
            conn = self._get_conn()
            try:
                # Get all non-retired profiles
                cursor = conn.execute(
                    """
                    SELECT * FROM strategy_profiles
                    WHERE strategy_name = ? AND retired = 0
                    ORDER BY success_rate DESC, usage_count ASC
                """,
                    (strategy_name,),
                )

                profiles = cursor.fetchall()

                # Find first profile not in excluded list
                for row in profiles:
                    if row["profile_id"] not in excluded:
                        conn.execute(
                            """
                            UPDATE strategy_profiles
                            SET last_used_at = ?
                            WHERE profile_id = ?
                        """,
                            (datetime.now().isoformat(), row["profile_id"]),
                        )
                        conn.commit()

                        return StrategyProfile(
                            profile_id=row["profile_id"],
                            strategy_name=row["strategy_name"],
                            parameters=json.loads(row["parameters"]),
                            step_order=json.loads(row["step_order"]),
                            aggressiveness=row["aggressiveness"],
                            tool_preferences=json.loads(row["tool_preferences"])
                            if row["tool_preferences"]
                            else [],
                            success_rate=row["success_rate"],
                            usage_count=row["usage_count"],
                            success_count=row["success_count"],
                            failure_count=row["failure_count"],
                            retired=bool(row["retired"]),
                            parent_profile_id=row["parent_profile_id"],
                            mutation_generation=row["mutation_generation"],
                            created_at=row["created_at"],
                            last_used_at=row["last_used_at"],
                        )

                # No available profiles - need to mutate from best retired
                return self._mutate_from_retired(conn, strategy_name)

            finally:
                conn.close()

    # =========================================================================
    # TARGET CLASSIFICATION
    # =========================================================================

    def classify_target(self, target: str) -> str:
        """Classify target into a type."""
        target_lower = target.lower()

        if target_lower.startswith(("http://", "https://")):
            if "/api" in target_lower or "api." in target_lower:
                return "api_endpoint"
            return "web_app"

        # Check for IP address pattern
        import re

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target):
            return "network_host"

        # Check for domain
        if "." in target and not target.startswith("/"):
            return "web_app"

        return "unknown"

    def get_target_signature(self, target: str) -> str:
        """Generate a unique signature for a target."""
        target_type = self.classify_target(target)
        # Hash the target for privacy but keep type prefix
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:12]
        return f"{target_type}:{target_hash}"

    # =========================================================================
    # MAIN SELECTION FLOW
    # =========================================================================

    def select_strategy_and_profile(
        self,
        target: str,
    ) -> tuple[Strategy | None, StrategyProfile | None]:
        """ENFORCED SELECTION ORDER with Timeout Protection."""
        import time

        start_time = time.time()
        max_duration = 30

        self._ensure_initialized()

        if not self._acquire_lock_safe(max_retries=3):
            logger.error("Failed to acquire lock within timeout - possible deadlock")
            return None, None

        try:
            # Step 1: Analysis
            target_info = self._analyze_target_for_selection(
                target,
                start_time,
                max_duration,
            )
            if not target_info:
                return None, None

            # Step 2: Strategy Selection
            strategy = self._select_strategy(target_info, start_time, max_duration)
            if not strategy:
                return None, None

            # Step 3: Profile Selection
            profile = self._select_profile(
                strategy,
                target_info,
                start_time,
                max_duration,
            )

            return strategy, profile

        except Exception as e:
            logger.exception("Error in select_strategy_and_profile: %s", e)
            return None, None
        finally:
            self._release_lock_safe()

    def _analyze_target_for_selection(
        self, target: str, start_time: float, max_duration: float,
    ) -> Any:
        """Step 1: Classify and generate signature."""
        import time

        if time.time() - start_time > max_duration:
            return None

        target_type = self.classify_target(target)
        target_signature = self.get_target_signature(target)

        # Pre-calculate context
        return {"target_type": target_type, "target_signature": target_signature}

    def _select_strategy(
        self, context: dict[str, Any], start_time: float, max_duration: float,
    ) -> Any:
        """Step 2: Select best strategy."""
        import time

        if time.time() - start_time > max_duration:
            return None

        # Get strategies
        strategies = self.get_strategies_for_target_type(context["target_type"])
        if not strategies:
            return None

        # Apply policies
        if time.time() - start_time > max_duration:
            return None

        strategies = self.apply_policies_to_strategies(strategies, context)
        return strategies[0] if strategies else None

    def _select_profile(
        self,
        strategy: "Strategy",
        context: dict[str, Any],
        start_time: float,
        max_duration: float,
    ) -> Any:
        """Step 3: Select, filter and mutate profile."""
        import time

        # Get profiles
        if time.time() - start_time > max_duration:
            return None

        profiles = self.get_profiles_for_strategy(strategy.name, include_retired=False)

        # Filter profiles (Policies + Failures)
        profiles = self.apply_policies_to_profiles(profiles, context)

        failed_profiles = self.get_failed_profiles_for_target(
            context["target_signature"],
        )
        profiles = [p for p in profiles if p.profile_id not in failed_profiles]

        # Decision - with timeout protection
        elapsed = time.time() - start_time
        if elapsed > max_duration:
            logger.warning("Profile selection timed out after %.2f seconds", elapsed)
            return profiles[0] if profiles else None

        if not profiles:
            return self._handle_no_profiles(strategy, failed_profiles)

        # Sort by success rate
        profiles.sort(key=lambda p: p.success_rate, reverse=True)

        # LOGIC FIX: Select and VERIFY (Prevent TOCTOU race condition)
        # Another thread might have retired this profile just now
        selected = profiles[0]
        with self._db_operation() as conn:
            cursor = conn.execute(
                "SELECT retired FROM strategy_profiles WHERE profile_id = ?",
                (selected.profile_id,),
            )
            row = cursor.fetchone()
            if row and row[0] == 1:
                logger.warning(
                    f"TOCTOU caught: Profile {selected.profile_id} was retired during selection. Falling back.",
                )
                # Add retired profile to failed list to avoid infinite loop
                failed_profiles.append(selected.profile_id)
                # Check if we've exceeded time or retried too many times
                if time.time() - start_time > max_duration:
                    logger.warning("TOCTOU retry exceeded timeout, returning None")
                    return None
                # Recursively try again with retired profile excluded
                return self._select_profile(strategy, context, start_time, max_duration)

        return selected

    def _handle_no_profiles(
        self, strategy: "Strategy", failed_profiles: list[str],
    ) -> Any:
        """Handle case where all profiles are exhausted."""
        try:
            return self.select_best_profile(strategy.name, failed_profiles)
        except Exception as e:
            logger.exception("Profile selection/mutation failed: %s", e)
            return None

    def _release_lock_safe(self) -> None:
        """Safely release lock."""
        with suppress(Exception):
            self._lock.release()

    # =========================================================================
    # EVOLUTION STATUS & DEBUG
    # =========================================================================

    def get_evolution_status(self) -> dict:
        """Get current evolution status for debugging."""
        with self._lock:
            conn = self._get_conn()
            try:
                status = {}

                # Strategies
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM strategies WHERE is_active = 1",
                )
                status["active_strategies"] = cursor.fetchone()[0]

                # Profiles
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM strategy_profiles WHERE retired = 0",
                )
                status["active_profiles"] = cursor.fetchone()[0]

                cursor = conn.execute(
                    "SELECT COUNT(*) FROM strategy_profiles WHERE retired = 1",
                )
                status["retired_profiles"] = cursor.fetchone()[0]

                cursor = conn.execute(
                    "SELECT MAX(mutation_generation) FROM strategy_profiles",
                )
                status["max_mutation_generation"] = cursor.fetchone()[0] or 0

                # Policies
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM policies WHERE is_active = 1",
                )
                status["active_policies"] = cursor.fetchone()[0]

                cursor = conn.execute("""
                    SELECT priority_tier, COUNT(*) FROM policies
                    WHERE is_active = 1 GROUP BY priority_tier
                """)
                status["policies_by_tier"] = {
                    PolicyTier(row[0]).name: row[1] for row in cursor.fetchall()
                }

                # Failures
                cursor = conn.execute("SELECT COUNT(*) FROM failure_contexts")
                status["total_failures"] = cursor.fetchone()[0]

                cursor = conn.execute(
                    "SELECT COUNT(*) FROM failure_contexts WHERE policy_generated = 1",
                )
                status["failures_with_policies"] = cursor.fetchone()[0]

                return status
            finally:
                conn.close()
