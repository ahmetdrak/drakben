"""Self-Refining Engine — Mutation Mixin.

Provides profile mutation, retirement, and outcome tracking functionality.

Extracted from self_refining_engine.py for maintainability.
"""

from __future__ import annotations

import copy
import json
import logging
import secrets
from datetime import datetime
from typing import TYPE_CHECKING

from core.intelligence.sre_models import StrategyProfile

if TYPE_CHECKING:
    import sqlite3

logger = logging.getLogger(__name__)


class SREMutationMixin:
    """Mixin providing mutation functionality for SelfRefiningEngine.

    Expects the host class to provide:
    - self._lock, self._get_conn(), self._generate_id(), self._db_operation()
    - self.get_profile(), self.MUTATION_PARAM_CHANGE
    - self.PROFILE_RETIRE_THRESHOLD, self.MIN_USAGE_FOR_RETIRE
    """

    def _mutate_from_retired(
        self,
        conn: sqlite3.Connection,
        strategy_name: str,
    ) -> StrategyProfile | None:
        """Create a mutated profile from the best retired profile."""
        cursor = conn.execute(
            """
            SELECT * FROM strategy_profiles
            WHERE strategy_name = ? AND retired = 1
            ORDER BY success_rate DESC
            LIMIT 1
        """,
            (strategy_name,),
        )

        row = cursor.fetchone()
        if not row:
            return None

        # Create mutated profile
        parent_params = json.loads(row["parameters"])
        parent_steps = json.loads(row["step_order"])
        parent_aggression = row["aggressiveness"]

        mutated_profile = self._apply_mutation(
            parent_params,
            parent_steps,
            parent_aggression,
        )

        # Insert new profile
        now = datetime.now().isoformat()
        conn.execute(
            """
            INSERT INTO strategy_profiles
            (profile_id, strategy_name, parameters, step_order, aggressiveness,
             tool_preferences, success_rate, parent_profile_id, mutation_generation, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0.5, ?, ?, ?)
        """,
            (
                mutated_profile["profile_id"],
                strategy_name,
                json.dumps(mutated_profile["parameters"]),
                json.dumps(mutated_profile["step_order"]),
                mutated_profile["aggressiveness"],
                json.dumps([]),
                row["profile_id"],
                row["mutation_generation"] + 1,
                now,
            ),
        )
        # Note: commit is handled by the caller's _db_operation() context manager

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
            last_used_at=None,
        )

    def _mutate_numeric_param(
        self,
        original_value: float,
        is_int: bool,
    ) -> int | float:
        """Apply mutation to a single numeric parameter."""
        u = (secrets.randbelow(200000) / 100000.0) - 1.0
        change = u * self.MUTATION_PARAM_CHANGE
        new_value = max(1, original_value * (1 + change))

        if not is_int:
            return new_value

        new_val = int(new_value)
        if new_val == original_value:
            new_val = new_val + 1 if change >= 0 else max(1, new_val - 1)
        return new_val

    def _mutate_params(self, params: dict) -> dict:
        """Mutate numeric parameters by ±20%."""
        new_params = copy.deepcopy(params)
        for key in new_params:
            if isinstance(new_params[key], int | float):
                new_params[key] = self._mutate_numeric_param(
                    new_params[key],
                    isinstance(params[key], int),
                )
        return new_params

    def _mutate_steps(self, steps: list[str]) -> list[str]:
        """Shuffle step order by swapping two random steps."""
        new_steps = steps.copy()
        if len(new_steps) >= 2:
            idxs = list(range(len(new_steps)))
            idx1 = secrets.choice(idxs)
            idxs.remove(idx1)
            idx2 = secrets.choice(idxs)
            new_steps[idx1], new_steps[idx2] = new_steps[idx2], new_steps[idx1]
        return new_steps

    def _apply_mutation(
        self,
        params: dict,
        steps: list[str],
        aggression: float,
    ) -> dict:
        """Apply measurable mutation to create new profile."""
        new_id = self._generate_id("mut_")
        new_params = self._mutate_params(params)
        new_steps = self._mutate_steps(steps)

        # Mutation 3: Adjust aggressiveness
        aggression_change = ((secrets.randbelow(200) / 100.0) - 1.0) * 0.2
        new_aggression = max(0.0, min(1.0, aggression + aggression_change))

        return {
            "profile_id": new_id,
            "parameters": new_params,
            "step_order": new_steps,
            "aggressiveness": new_aggression,
        }

    def retire_profile(self, profile_id: str) -> bool:
        """Mark a profile as retired."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE strategy_profiles SET retired = 1 WHERE profile_id = ?",
                    (profile_id,),
                )
                conn.commit()
                return True
            finally:
                conn.close()

    def mutate_profile(self, profile_id: str) -> str | None:
        """Manually trigger mutation for a profile (retires old one)."""
        profile = self.get_profile(profile_id)
        if not profile:
            return None

        self.retire_profile(profile_id)

        with self._db_operation() as conn:
            new_profile = self._mutate_from_retired(conn, profile.strategy_name)
            return new_profile.profile_id if new_profile else None

    def update_profile_outcome(
        self,
        profile_id: str,
        success: bool,
    ) -> StrategyProfile | None:
        """Update profile metrics after execution.
        Returns the profile if it was retired due to low success rate.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                # Get current profile
                cursor = conn.execute(
                    "SELECT * FROM strategy_profiles WHERE profile_id = ?",
                    (profile_id,),
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
                should_retire = new_usage >= self.MIN_USAGE_FOR_RETIRE and new_rate < self.PROFILE_RETIRE_THRESHOLD

                # Update
                conn.execute(
                    """
                    UPDATE strategy_profiles
                    SET usage_count = ?, success_count = ?, failure_count = ?,
                        success_rate = ?, retired = ?, last_used_at = ?
                    WHERE profile_id = ?
                """,
                    (
                        new_usage,
                        new_success,
                        new_failure,
                        new_rate,
                        1 if should_retire else row["retired"],
                        datetime.now().isoformat(),
                        profile_id,
                    ),
                )
                conn.commit()

                if should_retire:
                    return self.get_profile(profile_id)
                return None

            finally:
                conn.close()
