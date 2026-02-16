"""Profile selection and mode filtering mixin for RefactoredDrakbenAgent.

Handles strategy/profile selection, stealth/aggressive mode switching,
target classification, and evolution-info display during initialization.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.agent._agent_protocol import AgentProtocol
    from core.intelligence.self_refining_engine import StrategyProfile

    _MixinBase = AgentProtocol
else:
    _MixinBase = object

logger: logging.Logger = logging.getLogger(__name__)


class RAProfileSelectionMixin(_MixinBase):
    """Mixin: profile/strategy selection and mode filtering."""

    def _classify_target(self, target: str) -> str:
        """Classify target and set signature."""
        target_type: str = self.refining_engine.classify_target(target)
        self.target_signature = self.refining_engine.get_target_signature(target)
        self.console.print(f"\U0001f3af Target Classification: {target_type}", style="cyan")
        self.console.print(f"\U0001f511 Target Signature: {self.target_signature}", style="dim")
        return target_type

    def _select_and_filter_profile(self, target: str) -> bool:
        """Select strategy/profile and apply mode-based filtering. Returns False if failed."""
        try:
            self.current_strategy, self.current_profile = self.refining_engine.select_strategy_and_profile(target)
            self._apply_mode_filtering()
        except (KeyError, ValueError, TypeError, RuntimeError) as e:
            self.console.print(f"\u274c Strategy selection failed: {e}", style="red")
            logger.exception("Strategy selection error")
            return False

        if not self.current_strategy or not self.current_profile:
            self.console.print("\u274c No strategy/profile available", style="red")
            return False
        return True

    def _apply_mode_filtering(self) -> None:
        """Apply mode-based profile filtering."""
        if self._scan_mode == "stealth" and self.current_profile:
            if self.current_profile.aggressiveness > 0.4:
                self._switch_to_stealth_profile()
        elif self._scan_mode == "aggressive" and self.current_profile:
            if self.current_profile.aggressiveness < 0.6:
                self._switch_to_aggressive_profile()

    def _switch_to_stealth_profile(self) -> None:
        """Switch to low-aggression profile for stealth mode."""
        self.console.print(
            "\U0001f977 Stealth mode: Searching for low-aggression profile...",
            style="dim",
        )
        if not self.current_strategy:
            return
        profiles: list[StrategyProfile] = self.refining_engine.get_profiles_for_strategy(self.current_strategy.name)
        stealth_profiles: list[StrategyProfile] = [p for p in profiles if p.aggressiveness <= 0.4]
        if stealth_profiles:
            self.current_profile = sorted(
                stealth_profiles,
                key=lambda p: p.aggressiveness,
            )[0]
            try:
                agg = float(self.current_profile.aggressiveness)
            except (TypeError, ValueError):
                agg = 0.0
            self.console.print(
                f"\U0001f977 Switched to stealth profile (aggression: {agg:.2f})",
                style="green",
            )

    def _switch_to_aggressive_profile(self) -> None:
        """Switch to high-aggression profile for aggressive mode."""
        self.console.print(
            "\u26a1 Aggressive mode: Searching for high-aggression profile...",
            style="dim",
        )
        if not self.current_strategy:
            return
        profiles: list[StrategyProfile] = self.refining_engine.get_profiles_for_strategy(self.current_strategy.name)
        aggressive_profiles: list[StrategyProfile] = [p for p in profiles if p.aggressiveness >= 0.6]
        if aggressive_profiles:
            self.current_profile = sorted(
                aggressive_profiles,
                key=lambda p: -p.aggressiveness,
            )[0]
            try:
                agg = float(self.current_profile.aggressiveness)
            except (TypeError, ValueError):
                agg = 0.0
            self.console.print(
                f"\u26a1 Switched to aggressive profile (aggression: {agg:.2f})",
                style="yellow",
            )

    def _display_selected_profile(self) -> None:
        """Display selected strategy and profile information."""
        if not self.current_strategy or not self.current_profile:
            self.console.print("\u26a0\ufe0f No strategy/profile active.", style="yellow")
            return

        self.console.print(
            f"\U0001f9e0 Selected Strategy: {self.current_strategy.name}",
            style=self.STYLE_MAGENTA,
        )
        try:
            sr = float(self.current_profile.success_rate)
            agg = float(self.current_profile.aggressiveness)
        except (TypeError, ValueError):
            sr, agg = 0.0, 0.0
        self.console.print(
            f"\U0001f3ad Selected Profile: {self.current_profile.profile_id[:12]}... "
            f"(gen: {self.current_profile.mutation_generation}, "
            f"success_rate: {sr:.1%}, "
            f"aggression: {agg:.2f})",
            style=self.STYLE_CYAN,
        )
        self.console.print(
            f"   \U0001f4cb Step Order: {self.current_profile.step_order}",
            style="dim",
        )
        self.console.print(
            f"   \u2699\ufe0f  Parameters: {json.dumps(self.current_profile.parameters)}",
            style="dim",
        )

    def _show_evolution_info(self, target_type: str) -> None:
        """Show evolution status and applicable policies."""
        from core.agent.state import AttackPhase
        from core.intelligence.self_refining_engine import Policy, PolicyTier

        try:
            status = self.refining_engine.get_evolution_status()
            self.console.print(
                f"\U0001f9ec Evolution Status: {status['active_policies']} policies, "
                f"{status['retired_profiles']} retired profiles, "
                f"{status['max_mutation_generation']} max mutation gen",
                style="dim",
            )
        except (KeyError, ValueError, TypeError, RuntimeError) as e:
            logger.warning("Could not get evolution status: %s", e)

        try:
            context: dict[str, str] = {"target_type": target_type}
            policies: list[Policy] = self.refining_engine.get_applicable_policies(
                context,
            )
            if policies:
                self.console.print(
                    f"\U0001f4dc Active Policies: {len(policies)}",
                    style="yellow",
                )
                for p in policies[:3]:
                    tier_name: str = PolicyTier(p.priority_tier).name
                    self.console.print(
                        f"   - Tier {p.priority_tier} ({tier_name}): {p.action} (weight: {p.weight:.2f})",
                        style="dim",
                    )
        except (KeyError, ValueError, TypeError, RuntimeError) as e:
            logger.exception("Critical initialization error: %s", e)
            self.console.print(
                f"\u274c Critical error during initialization: {e}",
                style=self.STYLE_RED,
            )
            # Still allow basic operation
            if self.state:
                self.state.phase = AttackPhase.INIT
            self.running = True
            self.stagnation_counter = 0
