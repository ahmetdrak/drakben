"""Self-Refining Engine — Data Models & Schema.

Contains SCHEMA_SQL constant, PolicyTier enum, and all dataclasses
(Strategy, StrategyProfile, Policy).

Extracted from self_refining_engine.py for maintainability.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

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

-- Learned Patterns: Patterns extracted from multiple failures
CREATE TABLE IF NOT EXISTS learned_patterns (
    pattern_id TEXT PRIMARY KEY,
    pattern_type TEXT NOT NULL,
    pattern_data TEXT NOT NULL,     -- JSON: the pattern itself
    occurrence_count INTEGER DEFAULT 1,
    confidence REAL DEFAULT 0.5,
    last_seen TEXT NOT NULL,
    is_validated INTEGER DEFAULT 0
);

-- Policy Conflicts: History of resolved policy conflicts
CREATE TABLE IF NOT EXISTS policy_conflicts (
    conflict_id TEXT PRIMARY KEY,
    policy_ids TEXT NOT NULL,       -- JSON: conflicting policies
    resolution_action TEXT NOT NULL,
    context_data TEXT,              -- JSON: context of conflict
    resolved_at TEXT NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_profiles_strategy ON strategy_profiles(strategy_name);
CREATE INDEX IF NOT EXISTS idx_profiles_retired ON strategy_profiles(retired);
CREATE INDEX IF NOT EXISTS idx_policies_tier ON policies(priority_tier);
CREATE INDEX IF NOT EXISTS idx_failures_signature ON failure_contexts(target_signature);
CREATE INDEX IF NOT EXISTS idx_patterns_type ON learned_patterns(pattern_type);
"""


# =============================================================================
# DATA CLASSES
# =============================================================================


class PolicyTier(IntEnum):
    """Policy priority tiers - lower number = higher priority."""

    HARD_AVOIDANCE = 1  # Safety/blocking rules
    STRATEGY_OVERRIDE = 2  # Force strategy change
    TOOL_SELECTION = 3  # Bias tool selection
    SOFT_PREFERENCE = 4  # Soft suggestions


@dataclass
class Strategy:
    """High-level reusable approach."""

    strategy_id: str
    name: str
    target_type: str
    description: str
    base_parameters: dict[str, Any]
    created_at: str
    is_active: bool = True


@dataclass
class StrategyProfile:
    """Concrete behavioral variant of a strategy."""

    profile_id: str
    strategy_name: str
    parameters: dict[str, Any]
    step_order: list[str]
    aggressiveness: float
    tool_preferences: list[str]
    success_rate: float = 0.5
    usage_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    retired: bool = False
    parent_profile_id: str | None = None
    mutation_generation: int = 0
    created_at: str = ""
    last_used_at: str | None = None


@dataclass
class Policy:
    """Learned behavioral constraint."""

    policy_id: str
    condition: dict[str, Any]  # {"target_type": "web", "error_type": "timeout"}
    action: dict[str, Any]  # {"avoid_tools": ["sqlmap"], "prefer_strategy": "stealth"}
    weight: float
    priority_tier: PolicyTier
    source: str
    created_at: str
    expires_at: str | None = None
    is_active: bool = True
