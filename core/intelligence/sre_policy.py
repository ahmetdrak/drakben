"""Self-Refining Engine — Policy Engine Mixin.

Provides policy management, conflict resolution, and policy application
for strategies, profiles, and tools.

Extracted from self_refining_engine.py for maintainability.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from core.intelligence.sre_models import (
    Policy,
    PolicyTier,
    Strategy,
    StrategyProfile,
)

logger = logging.getLogger(__name__)


class SREPolicyMixin:
    """Mixin providing policy engine functionality for SelfRefiningEngine."""

    # =========================================================================
    # POLICY ENGINE
    # =========================================================================

    def get_applicable_policies(self, context: dict) -> list[Policy]:
        """Get all policies that apply to a given context.
        Returns policies sorted by priority_tier (ASC), weight (DESC), created_at (ASC).
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
                        applicable.append(
                            Policy(
                                policy_id=row["policy_id"],
                                condition=condition,
                                action=json.loads(row["action"]),
                                weight=row["weight"],
                                priority_tier=PolicyTier(row["priority_tier"]),
                                source=row["source"],
                                created_at=row["created_at"],
                                expires_at=row["expires_at"],
                                is_active=bool(row["is_active"]),
                            ),
                        )

                return applicable
            finally:
                conn.close()

    def _condition_matches(self, condition: dict, context: dict) -> bool:
        """Check if a condition matches a context."""
        return all(self._check_condition_key(key, value, context) for key, value in condition.items())

    def _check_condition_key(self, key: str, value: Any, context: dict) -> bool:
        """Check if a single condition key matches context."""
        if key not in context:
            return False

        ctx_value = context[key]

        if isinstance(value, list):
            return ctx_value in value
        if isinstance(value, dict):
            return self._check_dict_condition(value, ctx_value)
        return ctx_value == value

    def _check_dict_condition(self, value: dict, ctx_value: Any) -> bool:
        """Check dictionary-based condition (contains/not)."""
        if "contains" in value:
            return value["contains"] in str(ctx_value)
        if "not" in value:
            return ctx_value != value["not"]
        return False

    def resolve_policy_conflicts(self, policies: list[Policy]) -> list[dict]:
        """Resolve conflicts between policies.

        Resolution rules:
        1. Higher tier (lower number) ALWAYS wins
        2. Within same tier, higher weight wins
        3. Within same tier and weight, older policy wins

        Returns list of resolved actions in execution order.
        """
        if not policies:
            return []

        # Group by action type to detect conflicts
        action_groups: dict[str, list[Policy]] = {}
        for policy in policies:
            for action_key in policy.action:
                if action_key not in action_groups:
                    action_groups[action_key] = []
                action_groups[action_key].append(policy)

        # Resolve each action type
        resolved_actions = []
        for action_key, conflicting_policies in action_groups.items():
            # Sort by tier (ASC), weight (DESC), created_at (ASC)
            sorted_policies = sorted(
                conflicting_policies,
                key=lambda p: (p.priority_tier, -p.weight, p.created_at),
            )

            # Winner is the first one
            winner = sorted_policies[0]
            resolved_actions.append(
                {
                    "action_type": action_key,
                    "action_value": winner.action[action_key],
                    "source_policy": winner.policy_id,
                    "tier": winner.priority_tier,
                    "weight": winner.weight,
                },
            )

        # Sort resolved actions by tier for execution order
        resolved_actions.sort(key=lambda a: a["tier"])
        return resolved_actions

    def apply_policies_to_strategies(
        self,
        strategies: list[Strategy],
        context: dict,
    ) -> list[Strategy]:
        """Apply policies to filter/reorder strategies."""
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

    def apply_policies_to_profiles(
        self,
        profiles: list[StrategyProfile],
        context: dict,
    ) -> list[StrategyProfile]:
        """Apply policies to filter/reorder profiles."""
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
