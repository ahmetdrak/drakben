"""Deep coverage tests for core/agent/refactored_agent.py.

Covers: RefactoredDrakbenAgent initialization, scan mode, state management,
        target classification, profile filtering, iteration logic, error
        categorization, recovery, LLM decision, deterministic fallback.
"""

from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Heavy mocking setup — the agent has many dependencies
# ---------------------------------------------------------------------------
def _create_mock_config_manager():
    """Create mock ConfigManager with all needed properties."""
    mgr = MagicMock()
    mgr.llm_client = None
    mgr.config = MagicMock()
    mgr.config.language = "en"
    mgr.config.auto_approve = False
    mgr.config.target = None
    mgr.language = "en"
    return mgr


def _create_agent():
    """Create a RefactoredDrakbenAgent with fully mocked dependencies."""
    from core.agent.refactored_agent import RefactoredDrakbenAgent

    with patch("core.agent.refactored_agent.get_evolution_memory") as mock_evo, \
         patch("core.agent.refactored_agent.DrakbenBrain") as mock_brain, \
         patch("core.agent.refactored_agent.ToolSelector") as mock_ts, \
         patch("core.agent.refactored_agent.ExecutionEngine") as mock_ee, \
         patch("core.agent.refactored_agent.SelfRefiningEngine") as mock_sre, \
         patch("core.agent.refactored_agent.Planner") as mock_planner, \
         patch("core.agent.refactored_agent.AICoder") as mock_coder, \
         patch("core.agent.refactored_agent.SelfHealer") as mock_healer, \
         patch("core.agent.refactored_agent.DrakbenLogger"), \
         patch("core.agent.refactored_agent.Console") as mock_console:

        mock_evo.return_value = MagicMock()
        mock_brain.return_value = MagicMock()
        mock_ts.return_value = MagicMock()
        mock_ee.return_value = MagicMock()
        mock_sre.return_value = MagicMock()
        mock_planner.return_value = MagicMock()
        mock_coder.return_value = MagicMock()
        mock_healer.return_value = MagicMock()
        mock_console.return_value = MagicMock()

        config = _create_mock_config_manager()
        agent = RefactoredDrakbenAgent(config)

    return agent


# ---------------------------------------------------------------------------
# 1. Initialization
# ---------------------------------------------------------------------------
class TestRefactoredAgentInit:
    def test_creates_successfully(self):
        agent = _create_agent()
        assert agent is not None
        assert agent.running is False
        assert agent.stagnation_counter == 0
        assert agent.tools_created_this_session == 0

    def test_has_all_components(self):
        agent = _create_agent()
        assert agent.brain is not None
        assert agent.planner is not None
        assert agent.executor is not None
        assert agent.evolution is not None
        assert agent.refining_engine is not None
        assert agent.healer is not None
        assert agent.coder is not None

    def test_style_constants(self):
        agent = _create_agent()
        assert agent.STYLE_GREEN == "bold green"
        assert agent.STYLE_RED == "bold red"
        assert agent.STYLE_CYAN == "bold cyan"


# ---------------------------------------------------------------------------
# 2. _setup_scan_mode
# ---------------------------------------------------------------------------
class TestSetupScanMode:
    def test_auto_mode(self):
        agent = _create_agent()
        agent._setup_scan_mode("auto", "10.0.0.1")
        assert agent._scan_mode == "auto"

    def test_stealth_mode(self):
        agent = _create_agent()
        agent._setup_scan_mode("stealth", "10.0.0.1")
        assert agent._scan_mode == "stealth"

    def test_aggressive_mode(self):
        agent = _create_agent()
        agent._setup_scan_mode("aggressive", "10.0.0.1")
        assert agent._scan_mode == "aggressive"

    def test_case_insensitive(self):
        agent = _create_agent()
        agent._setup_scan_mode("STEALTH", "10.0.0.1")
        assert agent._scan_mode == "stealth"

    def test_unknown_mode_defaults(self):
        agent = _create_agent()
        agent._setup_scan_mode("superfast", "10.0.0.1")
        assert agent._scan_mode == "superfast"
        # Console should still print without error


# ---------------------------------------------------------------------------
# 3. _classify_target
# ---------------------------------------------------------------------------
class TestClassifyTarget:
    def test_returns_type(self):
        agent = _create_agent()
        agent.refining_engine.classify_target.return_value = "web_server"
        agent.refining_engine.get_target_signature.return_value = "sig_abc123"
        result = agent._classify_target("10.0.0.1")
        assert result == "web_server"
        assert agent.target_signature == "sig_abc123"


# ---------------------------------------------------------------------------
# 4. _select_and_filter_profile
# ---------------------------------------------------------------------------
class TestSelectAndFilterProfile:
    def test_success(self):
        agent = _create_agent()
        agent._scan_mode = "auto"  # Must be set before _apply_mode_filtering
        mock_strategy = MagicMock()
        mock_profile = MagicMock()
        mock_profile.aggressiveness = 0.5
        agent.refining_engine.select_strategy_and_profile.return_value = (
            mock_strategy,
            mock_profile,
        )
        result = agent._select_and_filter_profile("10.0.0.1")
        assert result is True
        assert agent.current_strategy is mock_strategy
        assert agent.current_profile is mock_profile

    def test_failure_returns_false(self):
        agent = _create_agent()
        agent.refining_engine.select_strategy_and_profile.side_effect = Exception("no strat")
        result = agent._select_and_filter_profile("10.0.0.1")
        assert result is False

    def test_none_strategy_returns_false(self):
        agent = _create_agent()
        agent.refining_engine.select_strategy_and_profile.return_value = (None, None)
        result = agent._select_and_filter_profile("10.0.0.1")
        assert result is False


# ---------------------------------------------------------------------------
# 5. _apply_mode_filtering
# ---------------------------------------------------------------------------
class TestApplyModeFiltering:
    def test_stealth_mode_high_aggression_switches(self):
        agent = _create_agent()
        agent._scan_mode = "stealth"
        agent.current_profile = MagicMock()
        agent.current_profile.aggressiveness = 0.8  # Too aggressive for stealth
        agent.current_strategy = MagicMock()

        with patch.object(agent, "_switch_to_stealth_profile") as mock_switch:
            agent._apply_mode_filtering()
            mock_switch.assert_called_once()

    def test_stealth_mode_low_aggression_no_switch(self):
        agent = _create_agent()
        agent._scan_mode = "stealth"
        agent.current_profile = MagicMock()
        agent.current_profile.aggressiveness = 0.3  # Already stealth-compatible

        with patch.object(agent, "_switch_to_stealth_profile") as mock_switch:
            agent._apply_mode_filtering()
            mock_switch.assert_not_called()

    def test_aggressive_mode_low_aggression_switches(self):
        agent = _create_agent()
        agent._scan_mode = "aggressive"
        agent.current_profile = MagicMock()
        agent.current_profile.aggressiveness = 0.3  # Too passive

        with patch.object(agent, "_switch_to_aggressive_profile") as mock_switch:
            agent._apply_mode_filtering()
            mock_switch.assert_called_once()

    def test_auto_mode_no_switch(self):
        agent = _create_agent()
        agent._scan_mode = "auto"
        agent.current_profile = MagicMock()
        agent.current_profile.aggressiveness = 0.5

        with patch.object(agent, "_switch_to_stealth_profile") as s, \
             patch.object(agent, "_switch_to_aggressive_profile") as a:
            agent._apply_mode_filtering()
            s.assert_not_called()
            a.assert_not_called()


# ---------------------------------------------------------------------------
# 6. _categorize_error
# ---------------------------------------------------------------------------
class TestCategorizeError:
    def test_timeout(self):
        agent = _create_agent()
        assert agent._categorize_error("Connection timeout after 30s") == "timeout"

    def test_connection_refused(self):
        agent = _create_agent()
        assert agent._categorize_error("Connection refused on port 80") == "connection_refused"

    def test_permission_denied(self):
        agent = _create_agent()
        assert agent._categorize_error("Permission denied: /etc/shadow") == "permission_denied"

    def test_tool_missing(self):
        agent = _create_agent()
        assert agent._categorize_error("nmap: command not found") == "tool_missing"
        assert agent._categorize_error("'nikto' is not recognized") == "tool_missing"

    def test_unknown_error(self):
        agent = _create_agent()
        assert agent._categorize_error("Some random error") == "unknown"


# ---------------------------------------------------------------------------
# 7. _reset_and_evolve_state
# ---------------------------------------------------------------------------
class TestResetAndEvolveState:
    def test_resets_state(self):
        agent = _create_agent()
        with patch("core.agent.refactored_agent.reset_state") as mock_reset:
            mock_state = MagicMock()
            mock_reset.return_value = mock_state
            agent._reset_and_evolve_state("10.0.0.1")
        assert agent.state is mock_state

    def test_tool_evolution_failure_graceful(self):
        agent = _create_agent()
        agent.tool_selector.evolve_strategies.side_effect = Exception("db error")
        with patch("core.agent.refactored_agent.reset_state") as mock_reset:
            mock_reset.return_value = MagicMock()
            # Should not raise
            agent._reset_and_evolve_state("10.0.0.1")


# ---------------------------------------------------------------------------
# 8. LLM Decision / Deterministic Fallback
# ---------------------------------------------------------------------------
class TestLLMDecision:
    def test_deterministic_fallback_with_state(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.tool_selector.recommend_next_action.return_value = (
            "phase",
            "nmap_scan",
            {"target": "10.0.0.1"},
        )
        result = agent._get_deterministic_fallback()
        assert result is not None
        assert result["tool"] == "nmap_scan"

    def test_deterministic_fallback_no_state(self):
        agent = _create_agent()
        agent.state = None
        result = agent._get_deterministic_fallback()
        assert result is None

    def test_deterministic_fallback_no_recommendation(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.tool_selector.recommend_next_action.return_value = None
        result = agent._get_deterministic_fallback()
        assert result is None


# ---------------------------------------------------------------------------
# 9. _validate_loop_state
# ---------------------------------------------------------------------------
class TestValidateLoopState:
    def test_no_state_returns_false(self):
        agent = _create_agent()
        agent.state = None
        assert agent._validate_loop_state() is False

    def test_invalid_state_returns_false(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.state.validate.return_value = False
        agent.state.invariant_violations = ["iteration overflow"]
        assert agent._validate_loop_state() is False

    def test_should_halt_returns_false(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.state.validate.return_value = True
        agent.state.should_halt.return_value = (True, "Max iterations reached")
        assert agent._validate_loop_state() is False

    def test_valid_state_returns_true(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.state.validate.return_value = True
        agent.state.should_halt.return_value = (False, "")
        assert agent._validate_loop_state() is True


# ---------------------------------------------------------------------------
# 10. _handle_plan_completion
# ---------------------------------------------------------------------------
class TestHandlePlanCompletion:
    def test_plan_complete(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.planner.is_plan_complete.return_value = True
        agent.running = True
        agent._handle_plan_completion()
        assert agent.running is False

    def test_no_executable_step(self):
        agent = _create_agent()
        agent.planner.is_plan_complete.return_value = False
        agent.running = True
        agent._handle_plan_completion()
        assert agent.running is False


# ---------------------------------------------------------------------------
# 11. _check_stagnation
# ---------------------------------------------------------------------------
class TestCheckStagnation:
    def test_no_stagnation(self):
        agent = _create_agent()
        agent.evolution.detect_stagnation.return_value = False
        assert agent._check_stagnation() is False

    def test_stagnation_triggers_replan(self):
        agent = _create_agent()
        agent.evolution.detect_stagnation.return_value = True
        mock_step = MagicMock()
        agent.planner.get_next_step.return_value = mock_step
        agent.stagnation_counter = 0
        result = agent._check_stagnation()
        assert result is False  # Not halt yet (counter < 3)
        assert agent.stagnation_counter == 1
        agent.planner.replan.assert_called_once()

    def test_stagnation_halt_after_3(self):
        agent = _create_agent()
        agent.evolution.detect_stagnation.return_value = True
        agent.planner.get_next_step.return_value = MagicMock()
        agent.stagnation_counter = 2
        result = agent._check_stagnation()
        assert result is True  # Should halt
        assert agent.stagnation_counter == 3


# ---------------------------------------------------------------------------
# 12. _check_tool_blocked
# ---------------------------------------------------------------------------
class TestCheckToolBlocked:
    def test_blocked_tool(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.state.target = "10.0.0.1"
        agent.evolution.is_tool_blocked.return_value = True
        agent.evolution.get_tool_penalty.return_value = 100.0
        step = MagicMock()
        step.tool = "nmap_scan"
        step.step_id = "s1"
        assert agent._check_tool_blocked(step) is True
        agent.planner.replan.assert_called_once_with("s1")

    def test_unblocked_tool(self):
        agent = _create_agent()
        agent.state = MagicMock()
        agent.state.target = "10.0.0.1"
        agent.evolution.is_tool_blocked.return_value = False
        agent.evolution.get_tool_penalty.return_value = 5.0
        step = MagicMock()
        step.tool = "nmap_scan"
        assert agent._check_tool_blocked(step) is False


# ---------------------------------------------------------------------------
# 13. _display_selected_profile
# ---------------------------------------------------------------------------
class TestDisplaySelectedProfile:
    def test_no_strategy_warns(self):
        agent = _create_agent()
        agent.current_strategy = None
        agent.current_profile = None
        agent._display_selected_profile()
        # Should print warning but not crash

    def test_with_valid_profile(self):
        agent = _create_agent()
        agent.current_strategy = MagicMock()
        agent.current_strategy.name = "web_pentest"
        agent.current_profile = MagicMock()
        agent.current_profile.profile_id = "prof_12345678"
        agent.current_profile.mutation_generation = 3
        agent.current_profile.success_rate = 0.85
        agent.current_profile.aggressiveness = 0.6
        agent.current_profile.step_order = ["recon", "scan"]
        agent.current_profile.parameters = {"timeout": 60}
        agent._display_selected_profile()
        # Should print info without error


# ---------------------------------------------------------------------------
# 14. _attempt_tool_recovery
# ---------------------------------------------------------------------------
class TestAttemptToolRecovery:
    def test_no_adapter(self):
        agent = _create_agent()
        with patch("core.intelligence.universal_adapter.get_universal_adapter", return_value=None):
            result = agent._attempt_tool_recovery("nmap")
        assert result is False

    def test_success(self):
        agent = _create_agent()
        mock_adapter = MagicMock()
        mock_adapter.install_tool.return_value = {"success": True}
        with patch(
            "core.intelligence.universal_adapter.get_universal_adapter",
            return_value=mock_adapter,
        ):
            result = agent._attempt_tool_recovery("nmap")
        assert result is True

    def test_install_failure(self):
        agent = _create_agent()
        mock_adapter = MagicMock()
        mock_adapter.install_tool.return_value = {"success": False, "message": "not found"}
        with patch(
            "core.intelligence.universal_adapter.get_universal_adapter",
            return_value=mock_adapter,
        ):
            result = agent._attempt_tool_recovery("nmap")
        assert result is False

    def test_exception_graceful(self):
        agent = _create_agent()
        with patch(
            "core.intelligence.universal_adapter.get_universal_adapter",
            side_effect=Exception("crash"),
        ):
            result = agent._attempt_tool_recovery("nmap")
        assert result is False
