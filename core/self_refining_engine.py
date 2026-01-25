"""
SELF-REFINING EVOLVING AGENT ENGINE
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
import random
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# SCHEMA DEFINITIONS
# =============================================================================

SCHEMA_SQL = """
-- Strategies: High-level reusable approaches
CREATE TABLE IF NOT EXISTS strategies (
    strategy_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    target_type TEXT NOT NULL,
    description TEXT,
    base_parameters TEXT NOT NULL,  -- JSON: default params
    created_at TEXT NOT NULL,
    is_active INTEGER DEFAULT 1
);

-- Strategy Profiles: Concrete behavioral variants of strategies
CREATE TABLE IF NOT EXISTS strategy_profiles (
    profile_id TEXT PRIMARY KEY,
    strategy_name TEXT NOT NULL,
    parameters TEXT NOT NULL,       -- JSON: modified params
    step_order TEXT NOT NULL,       -- JSON: ordered step list
    aggressiveness REAL NOT NULL,   -- 0.0 to 1.0
    tool_preferences TEXT,          -- JSON: preferred tools
    success_rate REAL DEFAULT 0.5,
    usage_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    retired INTEGER DEFAULT 0,
    parent_profile_id TEXT,         -- For mutation tracking
    mutation_generation INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    FOREIGN KEY (strategy_name) REFERENCES strategies(name),
    FOREIGN KEY (parent_profile_id) REFERENCES strategy_profiles(profile_id)
);

-- Policies: Learned behavioral constraints
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    condition TEXT NOT NULL,        -- JSON: when this policy applies
    action TEXT NOT NULL,           -- JSON: what to do
    weight REAL DEFAULT 0.5,        -- 0.0 to 1.0, used within same tier
    priority_tier INTEGER NOT NULL, -- 1=hard avoid, 2=strategy override, 3=tool bias, 4=soft pref
    source TEXT NOT NULL,           -- "failure", "user", "system"
    created_at TEXT NOT NULL,
    expires_at TEXT,                -- Optional expiration
    is_active INTEGER DEFAULT 1
);

-- Failure Contexts: Detailed failure records for learning
CREATE TABLE IF NOT EXISTS failure_contexts (
    context_id TEXT PRIMARY KEY,
    target_signature TEXT NOT NULL,
    strategy_name TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    tool_name TEXT,
    error_type TEXT NOT NULL,
    error_message TEXT,
    context_data TEXT,              -- JSON: full context
    created_at TEXT NOT NULL,
    policy_generated INTEGER DEFAULT 0,
    FOREIGN KEY (strategy_name) REFERENCES strategies(name),
    FOREIGN KEY (profile_id) REFERENCES strategy_profiles(profile_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_profiles_strategy ON strategy_profiles(strategy_name);
CREATE INDEX IF NOT EXISTS idx_profiles_retired ON strategy_profiles(retired);
CREATE INDEX IF NOT EXISTS idx_policies_tier ON policies(priority_tier);
CREATE INDEX IF NOT EXISTS idx_failures_signature ON failure_contexts(target_signature);
"""


# =============================================================================
# DATA CLASSES
# =============================================================================

class PolicyTier(IntEnum):
    """Policy priority tiers - lower number = higher priority"""
    HARD_AVOIDANCE = 1      # Safety/blocking rules
    STRATEGY_OVERRIDE = 2   # Force strategy change
    TOOL_SELECTION = 3      # Bias tool selection
    SOFT_PREFERENCE = 4     # Soft suggestions


@dataclass
class Strategy:
    """High-level reusable approach"""
    strategy_id: str
    name: str
    target_type: str
    description: str
    base_parameters: Dict[str, Any]
    created_at: str
    is_active: bool = True


@dataclass
class StrategyProfile:
    """Concrete behavioral variant of a strategy"""
    profile_id: str
    strategy_name: str
    parameters: Dict[str, Any]
    step_order: List[str]
    aggressiveness: float
    tool_preferences: List[str]
    success_rate: float = 0.5
    usage_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    retired: bool = False
    parent_profile_id: Optional[str] = None
    mutation_generation: int = 0
    created_at: str = ""
    last_used_at: Optional[str] = None


@dataclass
class Policy:
    """Learned behavioral constraint"""
    policy_id: str
    condition: Dict[str, Any]  # {"target_type": "web", "error_type": "timeout"}
    action: Dict[str, Any]     # {"avoid_tools": ["sqlmap"], "prefer_strategy": "stealth"}
    weight: float
    priority_tier: PolicyTier
    source: str
    created_at: str
    expires_at: Optional[str] = None
    is_active: bool = True


@dataclass
class FailureContext:
    """Detailed failure record"""
    context_id: str
    target_signature: str
    strategy_name: str
    profile_id: str
    tool_name: Optional[str]
    error_type: str
    error_message: str
    context_data: Dict[str, Any]
    created_at: str
    policy_generated: bool = False


# =============================================================================
# SELF-REFINING ENGINE
# =============================================================================

class SelfRefiningEngine:
    """
    STRONG SELF-REFINING EVOLVING AGENT ENGINE
    
    This engine provides:
    1. Strategy and Profile management
    2. Policy-based behavior modification
    3. Deterministic conflict resolution
    4. Profile mutation on failure
    5. Restart evolution guarantee
    """
    
    # Thresholds
    PROFILE_RETIRE_THRESHOLD = 0.25  # Retire if success_rate < 25%
    MIN_USAGE_FOR_RETIRE = 3         # Minimum uses before retirement
    MUTATION_PARAM_CHANGE = 0.2      # How much to change params on mutation
    
    def __init__(self, db_path: str = None):
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
        self._lock = threading.RLock()
        self._initialized = False
        self._init_lock = threading.Lock()  # Separate lock for initialization
        
        # LAZY INITIALIZATION: Don't initialize database in __init__
        # This prevents blocking during object creation
        # Database will be initialized on first use
        logger.debug("SelfRefiningEngine created (lazy initialization)")
    
    def _ensure_initialized(self):
        """
        Ensure database is initialized (lazy initialization).
        
        Improvements:
        - On failure, _initialized stays False to allow retry
        - Added retry counter to prevent infinite retry loops
        - Better error handling and logging
        """
        if self._initialized:
            return
        
        # Track retry attempts to prevent infinite loops
        if not hasattr(self, '_init_attempts'):
            self._init_attempts = 0
        
        # Max 3 retry attempts
        if self._init_attempts >= 3:
            logger.warning("Max initialization attempts reached, skipping database init")
            return
        
        with self._init_lock:
            # Double-check after acquiring lock
            if self._initialized:
                return
            
            self._init_attempts += 1
            
            try:
                logger.info(f"Initializing SelfRefiningEngine database (attempt {self._init_attempts}/3)...")
                self._init_database()
                self._seed_default_strategies()
                self._initialized = True
                logger.info("SelfRefiningEngine database initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize SelfRefiningEngine: {e}")
                logger.exception("Initialization error details")
                # DON'T set _initialized = True on failure
                # This allows retry on next use (up to max attempts)
    
    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local database connection with timeout protection"""
        # Ensure database is initialized before getting connection
        self._ensure_initialized()
        
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
    
    @contextmanager
    def _db_operation(self, timeout: float = 5.0):
        """
        Safe database operation context manager.
        
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
            raise TimeoutError("Database lock acquisition timeout - possible deadlock")
        
        conn = None
        try:
            conn = self._get_conn()
            yield conn
            conn.commit()
        except Exception as e:
            logger.error(f"Database operation failed: {e}")
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except (sqlite3.Error, AttributeError) as e:
                    logger.debug(f"Error closing connection: {e}")
            try:
                self._lock.release()
            except (RuntimeError, AttributeError) as e:
                logger.debug(f"Error releasing lock: {e}")
    
    def _init_database(self):
        """Initialize database schema with migration support"""
        # 1. Acquire Lock
        lock_acquired = self._acquire_db_lock()
        if not lock_acquired:
            logger.error("Failed to acquire lock for database init")
            raise RuntimeError("Lock acquisition timeout - possible deadlock")
        
        conn = None
        try:
            # 2. Connect and Migrate
            conn = self._get_conn()
            self._handle_schema_migration(conn)
            
            # 3. Create Schema
            conn.executescript(SCHEMA_SQL)
            conn.commit()
            
        except sqlite3.OperationalError as e:
            self._handle_db_error(e)
        finally:
            self._cleanup_conn_and_lock(conn, lock_acquired)

    def _acquire_db_lock(self, max_retries: int = 3, timeout_per_attempt: float = 1.5) -> bool:
        """
        Attempt to acquire database lock with retries.
        
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
                logger.warning(f"Lock wait attempt {attempt + 1}/{max_retries}")
                time.sleep(0.3)  # Short sleep before retry
            except Exception as e:
                logger.error(f"Lock error: {e}")
        
        logger.error(f"Failed to acquire lock after {max_retries} attempts - possible deadlock")
        return False

    def _handle_schema_migration(self, conn: sqlite3.Connection):
        """Check and migrate old schema if needed"""
        import time
        start_time = time.time()
        
        if self._needs_migration(conn):
            logger.info("Migrating database to new schema...")
            conn.executescript("""
                DROP TABLE IF EXISTS policies;
                DROP TABLE IF EXISTS failure_contexts;
                DROP TABLE IF EXISTS strategy_profiles;
                DROP TABLE IF EXISTS strategies;
                DROP INDEX IF EXISTS idx_profiles_strategy;
                DROP INDEX IF EXISTS idx_profiles_retired;
                DROP INDEX IF EXISTS idx_policies_tier;
                DROP INDEX IF EXISTS idx_failures_signature;
            """)
            conn.commit()

    def _needs_migration(self, conn: sqlite3.Connection) -> bool:
        """Check if migration is needed based on schema"""
        try:
            conn.execute("SELECT priority_tier FROM policies LIMIT 1")
            return False # Schema matches
        except sqlite3.OperationalError:
            return True # Column missing, old schema

    def _handle_db_error(self, e):
        """Handle database specific errors"""
        logger.error(f"Database operation failed: {e}")
        if "locked" in str(e).lower():
            logger.error("Database is locked by another process.")
        raise

    def _seed_default_strategies(self):
        """Seed default strategies if none exist"""
        import time
        max_duration = 10
        start_time = time.time()
        
        # Acquire lock safely
        lock_acquired = self._acquire_lock_safe()
        if not lock_acquired:
            return
        
        conn = None
        try:
            conn = self._get_conn()
            if self._strategies_exist(conn):
                return

            default_strategies = self._get_default_strategy_definitions()
            
            # Batch Insert Strategies
            self._batch_insert_strategies(conn, default_strategies, start_time, max_duration)
            
            # Create Profiles
            self._create_profiles_batch(conn, default_strategies, start_time, max_duration)
            
            conn.commit()
            
        except sqlite3.OperationalError as e:
            logger.error(f"Database error during seeding: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error during seeding: {e}")
        finally:
            self._cleanup_conn_and_lock(conn, lock_acquired)

    def _acquire_lock_safe(self, max_retries=2) -> bool:
        """Helper to acquire lock safely"""
        for attempt in range(max_retries):
            try:
                if self._lock.acquire(timeout=1.5):
                    return True
                time.sleep(0.5)
            except Exception as e:
                logger.error(f"Lock error: {e}")
        return False

    def _strategies_exist(self, conn) -> bool:
        """Check if strategies table is populated"""
        cursor = conn.execute("SELECT COUNT(*) FROM strategies")
        return cursor.fetchone()[0] > 0

    def _get_default_strategy_definitions(self) -> List[Dict]:
        """Return list of default strategies"""
        return [
            {
                "name": "aggressive_scan",
                "target_type": "network_host",
                "description": "Fast aggressive network scanning",
                "base_parameters": {"scan_speed": "fast", "stealth": False, "parallel_scans": 10, "timeout": 30}
            },
            {
                "name": "stealth_scan",
                "target_type": "network_host",
                "description": "Slow stealthy network scanning",
                "base_parameters": {"scan_speed": "slow", "stealth": True, "parallel_scans": 1, "timeout": 120}
            },
            {
                "name": "web_aggressive",
                "target_type": "web_app",
                "description": "Aggressive web application testing",
                "base_parameters": {"threads": 10, "follow_redirects": True, "test_all_params": True, "timeout": 30}
            },
            {
                "name": "web_stealth",
                "target_type": "web_app",
                "description": "Stealthy web application testing",
                "base_parameters": {"threads": 1, "follow_redirects": False, "test_all_params": False, "timeout": 60}
            },
            {
                "name": "api_fuzzing",
                "target_type": "api_endpoint",
                "description": "API endpoint fuzzing",
                "base_parameters": {"fuzz_depth": 3, "auth_bypass": True, "rate_limit": 10}
            },
            {
                "name": "api_enumeration",
                "target_type": "api_endpoint",
                "description": "API endpoint enumeration",
                "base_parameters": {"discover_endpoints": True, "test_methods": ["GET", "POST", "PUT", "DELETE"], "rate_limit": 5}
            }
        ]

    def _batch_insert_strategies(self, conn, strategies, start_time, max_duration):
        """Insert strategies in batch"""
        import time
        now = datetime.now().isoformat()
        strategy_inserts = []
        
        for strat in strategies:
            if time.time() - start_time > max_duration:
                break
            
            strategy_id = self._generate_id("strat_")
            strategy_inserts.append((
                strategy_id, strat["name"], strat["target_type"], 
                strat["description"], json.dumps(strat["base_parameters"]), now
            ))

        if strategy_inserts:
            conn.executemany("""
                INSERT INTO strategies (strategy_id, name, target_type, description, base_parameters, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, strategy_inserts)

    def _create_profiles_batch(self, conn, strategies, start_time, max_duration):
        """Create profiles for strategies"""
        import time
        now = datetime.now().isoformat()
        
        for strat in strategies:
            if time.time() - start_time > max_duration:
                break
            try:
                self._create_initial_profiles(conn, strat["name"], strat["base_parameters"], now)
            except Exception as e:
                logger.error(f"Failed profile creation for {strat['name']}: {e}")

    def _cleanup_conn_and_lock(self, conn, lock_acquired):
        """Cleanup connection and release lock"""
        if conn:
            try:
                conn.close()
            except (sqlite3.Error, AttributeError) as e:
                logger.debug(f"Error closing connection: {e}")
        if lock_acquired:
            try:
                self._lock.release()
            except (RuntimeError, AttributeError) as e:
                logger.debug(f"Error releasing lock: {e}")
    
    def _create_initial_profiles(self, conn: sqlite3.Connection, strategy_name: str, 
                                  base_params: Dict, created_at: str):
        """Create initial behavioral profiles for a strategy"""
        # Profile 1: Default (balanced)
        profile1 = {
            "profile_id": self._generate_id("prof_"),
            "strategy_name": strategy_name,
            "parameters": base_params,
            "step_order": ["recon", "scan", "analyze", "exploit"],
            "aggressiveness": 0.5,
            "tool_preferences": []
        }
        
        # Profile 2: Aggressive variant
        aggressive_params = copy.deepcopy(base_params)
        for key in aggressive_params:
            if isinstance(aggressive_params[key], (int, float)):
                aggressive_params[key] = int(aggressive_params[key] * 1.5)
        
        profile2 = {
            "profile_id": self._generate_id("prof_"),
            "strategy_name": strategy_name,
            "parameters": aggressive_params,
            "step_order": ["scan", "exploit", "recon", "analyze"],  # Different order
            "aggressiveness": 0.8,
            "tool_preferences": []
        }
        
        # Profile 3: Conservative variant
        conservative_params = copy.deepcopy(base_params)
        for key in conservative_params:
            if isinstance(conservative_params[key], (int, float)):
                conservative_params[key] = max(1, int(conservative_params[key] * 0.5))
        
        profile3 = {
            "profile_id": self._generate_id("prof_"),
            "strategy_name": strategy_name,
            "parameters": conservative_params,
            "step_order": ["recon", "analyze", "scan", "exploit"],  # Different order
            "aggressiveness": 0.2,
            "tool_preferences": []
        }
        
        for profile in [profile1, profile2, profile3]:
            conn.execute("""
                INSERT INTO strategy_profiles 
                (profile_id, strategy_name, parameters, step_order, aggressiveness, 
                 tool_preferences, success_rate, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0.5, ?)
            """, (
                profile["profile_id"],
                profile["strategy_name"],
                json.dumps(profile["parameters"]),
                json.dumps(profile["step_order"]),
                profile["aggressiveness"],
                json.dumps(profile["tool_preferences"]),
                created_at
            ))
    
    def get_strategy(self, name: str) -> Optional[Strategy]:
        """Get strategy by name"""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "SELECT * FROM strategies WHERE name = ? AND is_active = 1",
                    (name,)
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
                        is_active=bool(row["is_active"])
                    )
                return None
            finally:
                conn.close()
    
    def get_strategies_for_target_type(self, target_type: str) -> List[Strategy]:
        """Get all active strategies for a target type"""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "SELECT * FROM strategies WHERE target_type = ? AND is_active = 1",
                    (target_type,)
                )
                strategies = []
                for row in cursor.fetchall():
                    strategies.append(Strategy(
                        strategy_id=row["strategy_id"],
                        name=row["name"],
                        target_type=row["target_type"],
                        description=row["description"],
                        base_parameters=json.loads(row["base_parameters"]),
                        created_at=row["created_at"],
                        is_active=bool(row["is_active"])
                    ))
                return strategies
            finally:
                conn.close()
    
    # =========================================================================
    # PROFILE MANAGEMENT
    # =========================================================================
    
    def get_profiles_for_strategy(self, strategy_name: str, 
                                   include_retired: bool = False) -> List[StrategyProfile]:
        """Get all profiles for a strategy"""
        with self._lock:
            conn = self._get_conn()
            try:
                if include_retired:
                    cursor = conn.execute(
                        "SELECT * FROM strategy_profiles WHERE strategy_name = ?",
                        (strategy_name,)
                    )
                else:
                    cursor = conn.execute(
                        "SELECT * FROM strategy_profiles WHERE strategy_name = ? AND retired = 0",
                        (strategy_name,)
                    )
                
                profiles = []
                for row in cursor.fetchall():
                    profiles.append(StrategyProfile(
                        profile_id=row["profile_id"],
                        strategy_name=row["strategy_name"],
                        parameters=json.loads(row["parameters"]),
                        step_order=json.loads(row["step_order"]),
                        aggressiveness=row["aggressiveness"],
                        tool_preferences=json.loads(row["tool_preferences"]) if row["tool_preferences"] else [],
                        success_rate=row["success_rate"],
                        usage_count=row["usage_count"],
                        success_count=row["success_count"],
                        failure_count=row["failure_count"],
                        retired=bool(row["retired"]),
                        parent_profile_id=row["parent_profile_id"],
                        mutation_generation=row["mutation_generation"],
                        created_at=row["created_at"],
                        last_used_at=row["last_used_at"]
                    ))
                return profiles
            finally:
                conn.close()
    
    def get_profile(self, profile_id: str) -> Optional[StrategyProfile]:
        """Get a specific profile by ID"""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "SELECT * FROM strategy_profiles WHERE profile_id = ?",
                    (profile_id,)
                )
                row = cursor.fetchone()
                if row:
                    return StrategyProfile(
                        profile_id=row["profile_id"],
                        strategy_name=row["strategy_name"],
                        parameters=json.loads(row["parameters"]),
                        step_order=json.loads(row["step_order"]),
                        aggressiveness=row["aggressiveness"],
                        tool_preferences=json.loads(row["tool_preferences"]) if row["tool_preferences"] else [],
                        success_rate=row["success_rate"],
                        usage_count=row["usage_count"],
                        success_count=row["success_count"],
                        failure_count=row["failure_count"],
                        retired=bool(row["retired"]),
                        parent_profile_id=row["parent_profile_id"],
                        mutation_generation=row["mutation_generation"],
                        created_at=row["created_at"],
                        last_used_at=row["last_used_at"]
                    )
                return None
            finally:
                conn.close()
    
    def select_best_profile(self, strategy_name: str, 
                            excluded_profile_ids: List[str] = None) -> Optional[StrategyProfile]:
        """
        Select best non-retired profile for a strategy.
        If all profiles are retired, trigger mutation and return new profile.
        """
        excluded = excluded_profile_ids or []
        
        with self._lock:
            conn = self._get_conn()
            try:
                # Get all non-retired profiles
                cursor = conn.execute("""
                    SELECT * FROM strategy_profiles 
                    WHERE strategy_name = ? AND retired = 0
                    ORDER BY success_rate DESC, usage_count ASC
                """, (strategy_name,))
                
                profiles = cursor.fetchall()
                
                # Find first profile not in excluded list
                for row in profiles:
                    if row["profile_id"] not in excluded:
                        conn.execute("""
                            UPDATE strategy_profiles 
                            SET last_used_at = ? 
                            WHERE profile_id = ?
                        """, (datetime.now().isoformat(), row["profile_id"]))
                        conn.commit()
                        
                        return StrategyProfile(
                            profile_id=row["profile_id"],
                            strategy_name=row["strategy_name"],
                            parameters=json.loads(row["parameters"]),
                            step_order=json.loads(row["step_order"]),
                            aggressiveness=row["aggressiveness"],
                            tool_preferences=json.loads(row["tool_preferences"]) if row["tool_preferences"] else [],
                            success_rate=row["success_rate"],
                            usage_count=row["usage_count"],
                            success_count=row["success_count"],
                            failure_count=row["failure_count"],
                            retired=bool(row["retired"]),
                            parent_profile_id=row["parent_profile_id"],
                            mutation_generation=row["mutation_generation"],
                            created_at=row["created_at"],
                            last_used_at=row["last_used_at"]
                        )
                
                # No available profiles - need to mutate from best retired
                return self._mutate_from_retired(conn, strategy_name)
                
            finally:
                conn.close()
    
    def _mutate_from_retired(self, conn: sqlite3.Connection, 
                              strategy_name: str) -> Optional[StrategyProfile]:
        """Create a mutated profile from the best retired profile"""
        cursor = conn.execute("""
            SELECT * FROM strategy_profiles 
            WHERE strategy_name = ? AND retired = 1
            ORDER BY success_rate DESC
            LIMIT 1
        """, (strategy_name,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        # Create mutated profile
        parent_params = json.loads(row["parameters"])
        parent_steps = json.loads(row["step_order"])
        parent_aggression = row["aggressiveness"]
        
        mutated_profile = self._apply_mutation(
            parent_params, parent_steps, parent_aggression
        )
        
        # Insert new profile
        now = datetime.now().isoformat()
        conn.execute("""
            INSERT INTO strategy_profiles 
            (profile_id, strategy_name, parameters, step_order, aggressiveness,
             tool_preferences, success_rate, parent_profile_id, mutation_generation, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0.5, ?, ?, ?)
        """, (
            mutated_profile["profile_id"],
            strategy_name,
            json.dumps(mutated_profile["parameters"]),
            json.dumps(mutated_profile["step_order"]),
            mutated_profile["aggressiveness"],
            json.dumps([]),
            row["profile_id"],
            row["mutation_generation"] + 1,
            now
        ))
        conn.commit()
        
        return StrategyProfile(
            profile_id=mutated_profile["profile_id"],
            strategy_name=strategy_name,
            parameters=mutated_profile["parameters"],
            step_order=mutated_profile["step_order"],
            aggressiveness=mutated_profile["aggressiveness"],
            tool_preferences=[],
            success_rate=0.5,
            usage_count=0,
            success_count=0,
            failure_count=0,
            retired=False,
            parent_profile_id=row["profile_id"],
            mutation_generation=row["mutation_generation"] + 1,
            created_at=now,
            last_used_at=None
        )
    
    def _apply_mutation(self, params: Dict, steps: List[str], 
                        aggression: float) -> Dict:
        """Apply measurable mutation to create new profile"""
        new_id = self._generate_id("mut_")
        
        # Mutation 1: Modify parameters
        new_params = copy.deepcopy(params)
        for key in new_params:
            if isinstance(new_params[key], (int, float)):
                # Change by ±20%
                change = random.uniform(-self.MUTATION_PARAM_CHANGE, self.MUTATION_PARAM_CHANGE)
                new_params[key] = max(1, new_params[key] * (1 + change))
                if isinstance(params[key], int):
                    new_params[key] = int(new_params[key])
        
        # Mutation 2: Shuffle step order
        new_steps = steps.copy()
        if len(new_steps) >= 2:
            # Swap two random steps
            i, j = random.sample(range(len(new_steps)), 2)
            new_steps[i], new_steps[j] = new_steps[j], new_steps[i]
        
        # Mutation 3: Adjust aggressiveness
        aggression_change = random.uniform(-0.2, 0.2)
        new_aggression = max(0.0, min(1.0, aggression + aggression_change))
        
        return {
            "profile_id": new_id,
            "parameters": new_params,
            "step_order": new_steps,
            "aggressiveness": new_aggression
        }
    
    def retire_profile(self, profile_id: str) -> bool:
        """Mark a profile as retired"""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE strategy_profiles SET retired = 1 WHERE profile_id = ?",
                    (profile_id,)
                )
                conn.commit()
                return True
            finally:
                conn.close()
    
    def update_profile_outcome(self, profile_id: str, success: bool) -> Optional[StrategyProfile]:
        """
        Update profile metrics after execution.
        Returns the profile if it was retired due to low success rate.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                # Get current profile
                cursor = conn.execute(
                    "SELECT * FROM strategy_profiles WHERE profile_id = ?",
                    (profile_id,)
                )
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Calculate new metrics
                new_usage = row["usage_count"] + 1
                new_success = row["success_count"] + (1 if success else 0)
                new_failure = row["failure_count"] + (0 if success else 1)
                new_rate = new_success / new_usage if new_usage > 0 else 0.5
                
                # Check for retirement
                should_retire = (
                    new_usage >= self.MIN_USAGE_FOR_RETIRE and 
                    new_rate < self.PROFILE_RETIRE_THRESHOLD
                )
                
                # Update
                conn.execute("""
                    UPDATE strategy_profiles 
                    SET usage_count = ?, success_count = ?, failure_count = ?,
                        success_rate = ?, retired = ?, last_used_at = ?
                    WHERE profile_id = ?
                """, (
                    new_usage, new_success, new_failure, new_rate,
                    1 if should_retire else row["retired"],
                    datetime.now().isoformat(),
                    profile_id
                ))
                conn.commit()
                
                if should_retire:
                    return self.get_profile(profile_id)
                return None
                
            finally:
                conn.close()
    
    # =========================================================================
    # POLICY ENGINE
    # =========================================================================
    
    def add_policy(self, condition: Dict, action: Dict, 
                   priority_tier: PolicyTier, weight: float = 0.5,
                   source: str = "system") -> str:
        """Add a new policy"""
        with self._lock:
            conn = self._get_conn()
            try:
                policy_id = self._generate_id("pol_")
                now = datetime.now().isoformat()
                
                conn.execute("""
                    INSERT INTO policies 
                    (policy_id, condition, action, weight, priority_tier, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    policy_id,
                    json.dumps(condition),
                    json.dumps(action),
                    weight,
                    int(priority_tier),
                    source,
                    now
                ))
                conn.commit()
                return policy_id
            finally:
                conn.close()
    
    def get_applicable_policies(self, context: Dict) -> List[Policy]:
        """
        Get all policies that apply to a given context.
        Returns policies sorted by priority_tier (ASC), weight (DESC), created_at (ASC)
        """
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("""
                    SELECT * FROM policies 
                    WHERE is_active = 1
                    ORDER BY priority_tier ASC, weight DESC, created_at ASC
                """)
                
                applicable = []
                for row in cursor.fetchall():
                    condition = json.loads(row["condition"])
                    
                    # Check if condition matches context
                    if self._condition_matches(condition, context):
                        applicable.append(Policy(
                            policy_id=row["policy_id"],
                            condition=condition,
                            action=json.loads(row["action"]),
                            weight=row["weight"],
                            priority_tier=PolicyTier(row["priority_tier"]),
                            source=row["source"],
                            created_at=row["created_at"],
                            expires_at=row["expires_at"],
                            is_active=bool(row["is_active"])
                        ))
                
                return applicable
            finally:
                conn.close()
    
    def _condition_matches(self, condition: Dict, context: Dict) -> bool:
        """Check if a condition matches a context"""
        for key, value in condition.items():
            if not self._check_condition_key(key, value, context):
                return False
        return True
    
    def _check_condition_key(self, key: str, value: Any, context: Dict) -> bool:
        """Check if a single condition key matches context"""
        if key not in context:
            return False
        
        ctx_value = context[key]
        
        if isinstance(value, list):
            return ctx_value in value
        elif isinstance(value, dict):
            return self._check_dict_condition(value, ctx_value)
        else:
            return ctx_value == value
    
    def _check_dict_condition(self, value: Dict, ctx_value: Any) -> bool:
        """Check dictionary-based condition (contains/not)"""
        if "contains" in value:
            return value["contains"] in str(ctx_value)
        elif "not" in value:
            return ctx_value != value["not"]
        return False
    
    def resolve_policy_conflicts(self, policies: List[Policy]) -> List[Dict]:
        """
        Resolve conflicts between policies.
        
        Resolution rules:
        1. Higher tier (lower number) ALWAYS wins
        2. Within same tier, higher weight wins
        3. Within same tier and weight, older policy wins
        
        Returns list of resolved actions in execution order.
        """
        if not policies:
            return []
        
        # Group by action type to detect conflicts
        action_groups: Dict[str, List[Policy]] = {}
        for policy in policies:
            for action_key in policy.action.keys():
                if action_key not in action_groups:
                    action_groups[action_key] = []
                action_groups[action_key].append(policy)
        
        # Resolve each action type
        resolved_actions = []
        for action_key, conflicting_policies in action_groups.items():
            # Sort by tier (ASC), weight (DESC), created_at (ASC)
            sorted_policies = sorted(
                conflicting_policies,
                key=lambda p: (p.priority_tier, -p.weight, p.created_at)
            )
            
            # Winner is the first one
            winner = sorted_policies[0]
            resolved_actions.append({
                "action_type": action_key,
                "action_value": winner.action[action_key],
                "source_policy": winner.policy_id,
                "tier": winner.priority_tier,
                "weight": winner.weight
            })
        
        # Sort resolved actions by tier for execution order
        resolved_actions.sort(key=lambda a: a["tier"])
        return resolved_actions
    
    def apply_policies_to_strategies(self, strategies: List[Strategy], 
                                      context: Dict) -> List[Strategy]:
        """Apply policies to filter/reorder strategies"""
        policies = self.get_applicable_policies(context)
        resolved = self.resolve_policy_conflicts(policies)
        
        filtered = strategies.copy()
        
        for action in resolved:
            if action["action_type"] == "avoid_strategy":
                avoid_name = action["action_value"]
                filtered = [s for s in filtered if s.name != avoid_name]
            
            elif action["action_type"] == "prefer_strategy":
                prefer_name = action["action_value"]
                # Move preferred to front
                preferred = [s for s in filtered if s.name == prefer_name]
                others = [s for s in filtered if s.name != prefer_name]
                filtered = preferred + others
            
            elif action["action_type"] == "block_strategy":
                # Tier 1 hard block
                if action["tier"] == PolicyTier.HARD_AVOIDANCE:
                    block_name = action["action_value"]
                    filtered = [s for s in filtered if s.name != block_name]
        
        return filtered
    
    def apply_policies_to_profiles(self, profiles: List[StrategyProfile],
                                    context: Dict) -> List[StrategyProfile]:
        """Apply policies to filter/reorder profiles"""
        policies = self.get_applicable_policies(context)
        resolved = self.resolve_policy_conflicts(policies)
        
        filtered = profiles.copy()
        
        for action in resolved:
            if action["action_type"] == "avoid_profile":
                avoid_id = action["action_value"]
                filtered = [p for p in filtered if p.profile_id != avoid_id]
            
            elif action["action_type"] == "max_aggressiveness":
                max_agg = action["action_value"]
                filtered = [p for p in filtered if p.aggressiveness <= max_agg]
            
            elif action["action_type"] == "min_aggressiveness":
                min_agg = action["action_value"]
                filtered = [p for p in filtered if p.aggressiveness >= min_agg]
        
        return filtered
    
    def apply_policies_to_tools(self, tools: List[str], context: Dict) -> List[str]:
        """Apply policies to filter/reorder tools"""
        policies = self.get_applicable_policies(context)
        resolved = self.resolve_policy_conflicts(policies)
        
        filtered = tools.copy()
        
        for action in resolved:
            if action["action_type"] == "avoid_tools":
                # Can be list or single tool
                avoid = action["action_value"]
                if isinstance(avoid, list):
                    filtered = [t for t in filtered if t not in avoid]
                else:
                    filtered = [t for t in filtered if t != avoid]
            
            elif action["action_type"] == "prefer_tools":
                prefer = action["action_value"]
                if isinstance(prefer, str):
                    prefer = [prefer]
                # Move preferred to front
                preferred = [t for t in filtered if t in prefer]
                others = [t for t in filtered if t not in prefer]
                filtered = preferred + others
            
            elif action["action_type"] == "block_tool":
                if action["tier"] == PolicyTier.HARD_AVOIDANCE:
                    block = action["action_value"]
                    filtered = [t for t in filtered if t != block]
        
        return filtered
    
    # =========================================================================
    # FAILURE LEARNING
    # =========================================================================
    
    def record_failure(self, target_signature: str, strategy_name: str,
                       profile_id: str, error_type: str, error_message: str = "",
                       tool_name: str = None, context_data: Dict = None) -> str:
        """Record a failure context"""
        with self._lock:
            conn = self._get_conn()
            try:
                context_id = self._generate_id("fail_")
                now = datetime.now().isoformat()
                
                conn.execute("""
                    INSERT INTO failure_contexts
                    (context_id, target_signature, strategy_name, profile_id, tool_name,
                     error_type, error_message, context_data, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    context_id,
                    target_signature,
                    strategy_name,
                    profile_id,
                    tool_name,
                    error_type,
                    error_message,
                    json.dumps(context_data or {}),
                    now
                ))
                conn.commit()
                return context_id
            finally:
                conn.close()
    
    def learn_policy_from_failure(self, context_id: str) -> Optional[str]:
        """
        Learn a policy from a failure context.
        Returns policy_id if a new policy was created.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                # Get failure context
                cursor = conn.execute(
                    "SELECT * FROM failure_contexts WHERE context_id = ?",
                    (context_id,)
                )
                row = cursor.fetchone()
                if not row or row["policy_generated"]:
                    return None
                
                # Check if similar failures exist (pattern detection)
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM failure_contexts
                    WHERE target_signature = ? AND error_type = ? AND profile_id = ?
                """, (row["target_signature"], row["error_type"], row["profile_id"]))
                
                similar_count = cursor.fetchone()[0]
                
                # Only learn policy if pattern repeats (2+ times)
                if similar_count < 2:
                    return None
                
                # Create policy based on failure type
                condition = {
                    "target_signature": row["target_signature"],
                    "error_type": row["error_type"]
                }
                
                # Determine policy action and tier based on error type
                if row["error_type"] in ["blocked", "banned", "firewall"]:
                    action = {"avoid_profile": row["profile_id"]}
                    tier = PolicyTier.HARD_AVOIDANCE
                    weight = 0.9
                elif row["error_type"] in ["timeout", "slow"]:
                    action = {"max_aggressiveness": 0.5}
                    tier = PolicyTier.STRATEGY_OVERRIDE
                    weight = 0.7
                elif row["tool_name"]:
                    action = {"avoid_tools": [row["tool_name"]]}
                    tier = PolicyTier.TOOL_SELECTION
                    weight = 0.6
                else:
                    action = {"avoid_profile": row["profile_id"]}
                    tier = PolicyTier.SOFT_PREFERENCE
                    weight = 0.5
                
                # Create policy
                policy_id = self._generate_id("pol_")
                now = datetime.now().isoformat()
                
                conn.execute("""
                    INSERT INTO policies 
                    (policy_id, condition, action, weight, priority_tier, source, created_at)
                    VALUES (?, ?, ?, ?, ?, 'failure', ?)
                """, (
                    policy_id,
                    json.dumps(condition),
                    json.dumps(action),
                    weight,
                    int(tier),
                    now
                ))
                
                # Mark failure as policy-generated
                conn.execute(
                    "UPDATE failure_contexts SET policy_generated = 1 WHERE context_id = ?",
                    (context_id,)
                )
                
                conn.commit()
                return policy_id
                
            finally:
                conn.close()
    
    def has_failed_before(self, target_signature: str, profile_id: str) -> bool:
        """Check if this exact target+profile combination has failed before"""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM failure_contexts
                    WHERE target_signature = ? AND profile_id = ?
                """, (target_signature, profile_id))
                return cursor.fetchone()[0] > 0
            finally:
                conn.close()
    
    def get_failed_profiles_for_target(self, target_signature: str) -> List[str]:
        """Get all profile IDs that have failed for a target"""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute("""
                    SELECT DISTINCT profile_id FROM failure_contexts
                    WHERE target_signature = ?
                """, (target_signature,))
                return [row[0] for row in cursor.fetchall()]
            finally:
                conn.close()
    
    # =========================================================================
    # TARGET CLASSIFICATION
    # =========================================================================
    
    def classify_target(self, target: str) -> str:
        """Classify target into a type"""
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
        """Generate a unique signature for a target"""
        target_type = self.classify_target(target)
        # Hash the target for privacy but keep type prefix
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:12]
        return f"{target_type}:{target_hash}"
    
    # =========================================================================
    # MAIN SELECTION FLOW
    # =========================================================================
    
    def select_strategy_and_profile(self, target: str) -> Tuple[Optional[Strategy], Optional[StrategyProfile]]:
        """
        ENFORCED SELECTION ORDER with Timeout Protection.
        """
        import time
        start_time = time.time()
        max_duration = 30
        
        self._ensure_initialized()
        
        if not self._acquire_lock_safe(max_retries=3):
            logger.error("Failed to acquire lock within timeout - possible deadlock")
            return None, None
        
        try:
            # Step 1: Analysis
            target_info = self._analyze_target_for_selection(target, start_time, max_duration)
            if not target_info:
                return None, None
                
            # Step 2: Strategy Selection
            strategy = self._select_strategy(target_info, start_time, max_duration)
            if not strategy:
                return None, None

            # Step 3: Profile Selection
            profile = self._select_profile(strategy, target_info, start_time, max_duration)
            
            return strategy, profile

        except Exception as e:
            logger.exception(f"Error in select_strategy_and_profile: {e}")
            return None, None
        finally:
            self._release_lock_safe()

    def _analyze_target_for_selection(self, target, start_time, max_duration):
        """Step 1: Classify and generate signature"""
        import time
        if time.time() - start_time > max_duration:
             return None
             
        target_type = self.classify_target(target)
        target_signature = self.get_target_signature(target)
        
        # Pre-calculate context
        context = {
            "target_type": target_type,
            "target_signature": target_signature
        }
        return context

    def _select_strategy(self, context, start_time, max_duration):
        """Step 2: Select best strategy"""
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

    def _select_profile(self, strategy, context, start_time, max_duration):
        """Step 3: Select, filter and mutate profile"""
        import time
        
        # Get profiles
        if time.time() - start_time > max_duration:
            return None
            
        profiles = self.get_profiles_for_strategy(strategy.name, include_retired=False)
        
        # Filter profiles (Policies + Failures)
        profiles = self.apply_policies_to_profiles(profiles, context)
        
        failed_profiles = self.get_failed_profiles_for_target(context["target_signature"])
        profiles = [p for p in profiles if p.profile_id not in failed_profiles]
        
        # Decision
        if time.time() - start_time > max_duration:
             return profiles[0] if profiles else None

        if not profiles:
            return self._handle_no_profiles(strategy, failed_profiles)
            
        # Sort by success rate
        profiles.sort(key=lambda p: p.success_rate, reverse=True)
        return profiles[0]

    def _handle_no_profiles(self, strategy, failed_profiles):
        """Handle case where all profiles are exhausted"""
        try:
            return self.select_best_profile(strategy.name, failed_profiles)
        except Exception as e:
            logger.error(f"Profile selection/mutation failed: {e}")
            return None

    def _release_lock_safe(self):
        """Safely release lock"""
        try:
            self._lock.release()
        except Exception:
            pass
    
    # =========================================================================
    # EVOLUTION STATUS & DEBUG
    # =========================================================================
    
    def get_evolution_status(self) -> Dict:
        """Get current evolution status for debugging"""
        with self._lock:
            conn = self._get_conn()
            try:
                status = {}
                
                # Strategies
                cursor = conn.execute("SELECT COUNT(*) FROM strategies WHERE is_active = 1")
                status["active_strategies"] = cursor.fetchone()[0]
                
                # Profiles
                cursor = conn.execute("SELECT COUNT(*) FROM strategy_profiles WHERE retired = 0")
                status["active_profiles"] = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT COUNT(*) FROM strategy_profiles WHERE retired = 1")
                status["retired_profiles"] = cursor.fetchone()[0]
                
                cursor = conn.execute("SELECT MAX(mutation_generation) FROM strategy_profiles")
                status["max_mutation_generation"] = cursor.fetchone()[0] or 0
                
                # Policies
                cursor = conn.execute("SELECT COUNT(*) FROM policies WHERE is_active = 1")
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
                
                cursor = conn.execute("SELECT COUNT(*) FROM failure_contexts WHERE policy_generated = 1")
                status["failures_with_policies"] = cursor.fetchone()[0]
                
                return status
            finally:
                conn.close()
    
    def get_profile_lineage(self, profile_id: str) -> List[str]:
        """Get the mutation lineage of a profile
        
        Includes protection against circular references to prevent infinite loops.
        """
        lineage = [profile_id]
        current_id = profile_id
        visited = {profile_id}  # Track visited IDs to prevent cycles
        max_depth = 100  # Maximum lineage depth to prevent infinite loops
        
        with self._lock:
            conn = self._get_conn()
            try:
                depth = 0
                while depth < max_depth:
                    cursor = conn.execute(
                        "SELECT parent_profile_id FROM strategy_profiles WHERE profile_id = ?",
                        (current_id,)
                    )
                    row = cursor.fetchone()
                    if not row or not row[0]:
                        break
                    
                    parent_id = row[0]
                    
                    # Check for circular reference
                    if parent_id in visited:
                        logger.warning(f"Circular reference detected in profile lineage: {parent_id}")
                        break
                    
                    lineage.append(parent_id)
                    visited.add(parent_id)
                    current_id = parent_id
                    depth += 1
                
                if depth >= max_depth:
                    logger.warning(f"Profile lineage exceeded max depth ({max_depth}), truncating")
                
                return lineage[::-1]  # Return from oldest to newest
            finally:
                conn.close()
