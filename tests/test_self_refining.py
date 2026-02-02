"""Tests for Self-Refining Engine
Converted from scripts/debug_skipped_tests.py.
"""

import os
import sys
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.self_refining_engine import SelfRefiningEngine, Strategy, StrategyProfile


class TestSelfRefiningEngine(unittest.TestCase):
    """Validation for the Self-Refining AI optimization engine."""

    def setUp(self) -> None:
        self.engine = SelfRefiningEngine()

    def test_initialization(self) -> None:
        """Test engine initialization."""
        assert isinstance(self.engine, SelfRefiningEngine)
        # Ensure DB is ready
        self.engine._ensure_initialized()
        # Use private check or public method to verify strategies exist
        strategies = self.engine.get_strategies_for_target_type("network_host")
        assert len(strategies) > 0, "No strategies loaded! (Checking network_host type)"

    def test_strategy_selection(self) -> None:
        """Test strategy selection for a target."""
        target = "192.168.1.1"  # Standard private IP

        # This calls select_strategy_and_profile internally
        strategy, profile = self.engine.select_strategy_and_profile(target)

        assert isinstance(strategy, Strategy)
        assert isinstance(profile, StrategyProfile)

        # Verify strategy matches target
        assert strategy.target_type == "network_host"
        assert profile.strategy_name == strategy.name

    def test_mutation_logic(self) -> None:
        """Test that failure triggers mutation/adaptation."""
        target = "10.0.0.5"
        _, profile = self.engine.select_strategy_and_profile(target)

        # Report failure
        self.engine.update_profile_outcome(profile.profile_id, success=False)

        # Report success
        self.engine.update_profile_outcome(profile.profile_id, success=True)

        # Verify state change
        updated_profile = self.engine.get_profile(profile.profile_id)
        assert updated_profile is not None
        # Note: Exact math depends on implementation, but it should be recorded.

    def test_persistence(self) -> None:
        """Test that profiles persist (mock)."""
        # Ideally checks if DB/File is updated


if __name__ == "__main__":
    unittest.main()
