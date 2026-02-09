"""Self-Refining Engine — Failure Learning Mixin.

Provides failure recording, pattern detection, and policy learning
from failures.

Extracted from self_refining_engine.py for maintainability.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from core.intelligence.sre_models import PolicyTier

logger = logging.getLogger(__name__)


class SREFailureMixin:
    """Mixin providing failure learning functionality for SelfRefiningEngine.

    Expects the host class to provide:
    - self._lock, self._get_conn(), self._generate_id()
    """

    def record_failure(
        self,
        target_signature: str,
        strategy_name: str,
        profile_id: str,
        error_type: str,
        error_message: str = "",
        tool_name: str | None = None,
        context_data: dict[Any, Any] | None = None,
    ) -> str:
        """Record a failure context."""
        with self._lock:
            conn = self._get_conn()
            try:
                context_id = self._generate_id("fail_")
                now = datetime.now().isoformat()

                conn.execute(
                    """
                    INSERT INTO failure_contexts
                    (context_id, target_signature, strategy_name, profile_id, tool_name,
                     error_type, error_message, context_data, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        context_id,
                        target_signature,
                        strategy_name,
                        profile_id,
                        tool_name,
                        error_type,
                        error_message,
                        json.dumps(context_data or {}),
                        now,
                    ),
                )
                conn.commit()
                return context_id
            finally:
                conn.close()

    def learn_policy_from_failure(self, context_id: str) -> str | None:
        """Learn a policy from a failure context.
        Returns policy_id if a new policy was created.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                # Get failure context
                cursor = conn.execute(
                    "SELECT * FROM failure_contexts WHERE context_id = ?",
                    (context_id,),
                )
                row = cursor.fetchone()
                if not row or row["policy_generated"]:
                    return None

                # Check if similar failures exist (pattern detection)
                cursor = conn.execute(
                    """
                    SELECT COUNT(*) FROM failure_contexts
                    WHERE target_signature = ? AND error_type = ? AND profile_id = ?
                """,
                    (row["target_signature"], row["error_type"], row["profile_id"]),
                )

                result = cursor.fetchone()
                similar_count = result[0] if result else 0

                # CRITICAL SECURITY FIX: Determine if we should learn immediately
                critical_errors = ["blocked", "banned", "firewall", "access_denied"]
                is_critical = row["error_type"] in critical_errors

                # Learn immediately if critical, otherwise wait for 2+ failures
                if not is_critical and similar_count < 2:
                    return None

                # Create policy based on failure type
                condition = {
                    "target_signature": row["target_signature"],
                    "error_type": row["error_type"],
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

                conn.execute(
                    """
                    INSERT INTO policies
                    (policy_id, condition, action, weight, priority_tier, source, created_at)
                    VALUES (?, ?, ?, ?, ?, 'failure', ?)
                """,
                    (
                        policy_id,
                        json.dumps(condition),
                        json.dumps(action),
                        weight,
                        int(tier),
                        now,
                    ),
                )

                # Mark failure as policy-generated
                conn.execute(
                    "UPDATE failure_contexts SET policy_generated = 1 WHERE context_id = ?",
                    (context_id,),
                )

                conn.commit()
                return policy_id

            finally:
                conn.close()

    def get_failed_profiles_for_target(self, target_signature: str) -> list[str]:
        """Get all profile IDs that have failed for a target."""
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    """
                    SELECT DISTINCT profile_id FROM failure_contexts
                    WHERE target_signature = ?
                """,
                    (target_signature,),
                )
                return [row[0] for row in cursor.fetchall()]
            finally:
                conn.close()
