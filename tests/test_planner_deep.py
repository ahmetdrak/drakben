"""Deep coverage tests for core/agent/planner.py.

Covers: StepStatus, PlanStep, Planner (create, replan, get_next_step,
        mark_step_*, adaptive learning, tool switching).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.agent.planner import Planner, PlanStep, StepStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _make_step(
    step_id="step_1",
    action="port_scan",
    tool="nmap_port_scan",
    target="10.0.0.1",
    status=StepStatus.PENDING,
    depends_on=None,
    max_retries=2,
    retry_count=0,
    error="",
):
    return PlanStep(
        step_id=step_id,
        action=action,
        tool=tool,
        target=target,
        params={},
        depends_on=depends_on or [],
        status=status,
        max_retries=max_retries,
        retry_count=retry_count,
        expected_outcome="",
        actual_outcome="",
        error=error,
    )


def _make_strategy(name="default", steps=None):
    return SimpleNamespace(
        name=name,
        steps=steps or ["port_scan", "service_scan", "vuln_scan"],
    )


def _make_profile(
    profile_id="prof_1",
    step_order=None,
    parameters=None,
    aggressiveness=0.5,
    mutation_generation=1,
    success_rate=0.7,
):
    return SimpleNamespace(
        profile_id=profile_id,
        step_order=step_order if step_order is not None else ["recon", "scan", "exploit"],
        parameters=parameters or {},
        aggressiveness=aggressiveness,
        mutation_generation=mutation_generation,
        success_rate=success_rate,
    )


# ---------------------------------------------------------------------------
# 1. StepStatus enum
# ---------------------------------------------------------------------------
class TestStepStatus:
    def test_all_values(self):
        assert StepStatus.PENDING.value == "pending"
        assert StepStatus.EXECUTING.value == "executing"
        assert StepStatus.SUCCESS.value == "success"
        assert StepStatus.FAILED.value == "failed"
        assert StepStatus.SKIPPED.value == "skipped"

    def test_from_value(self):
        assert StepStatus("pending") == StepStatus.PENDING
        assert StepStatus("success") == StepStatus.SUCCESS


# ---------------------------------------------------------------------------
# 2. PlanStep dataclass
# ---------------------------------------------------------------------------
class TestPlanStep:
    def test_creation(self):
        step = _make_step()
        assert step.step_id == "step_1"
        assert step.status == StepStatus.PENDING

    def test_mutable_status(self):
        step = _make_step()
        step.status = StepStatus.SUCCESS
        assert step.status == StepStatus.SUCCESS


# ---------------------------------------------------------------------------
# 3. Planner — initialization & dict conversion
# ---------------------------------------------------------------------------
class TestPlannerInit:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_init_graceful_without_memory(self, mock_mem):
        planner = Planner()
        assert planner.memory is None
        assert planner.steps == []

    @patch("core.agent.planner.get_evolution_memory", return_value=MagicMock())
    def test_init_with_memory(self, mock_mem):
        planner = Planner()
        assert planner.memory is not None


class TestPlannerDictConversion:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_dict_to_step(self, _):
        planner = Planner()
        d = {
            "step_id": "s1",
            "action": "port_scan",
            "tool": "nmap_port_scan",
            "target": "10.0.0.1",
            "params": {"timeout": 60},
            "depends_on": [],
            "status": "pending",
            "max_retries": 3,
            "retry_count": 0,
            "expected_outcome": "ports",
            "actual_outcome": "",
            "error": "",
        }
        step = planner._dict_to_step(d)
        assert step.step_id == "s1"
        assert step.status == StepStatus.PENDING
        assert step.params == {"timeout": 60}

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_dict_to_step_missing_required_field(self, _):
        planner = Planner()
        with pytest.raises(ValueError, match="Missing required"):
            planner._dict_to_step({"step_id": "s1"})

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_step_to_dict(self, _):
        planner = Planner()
        step = _make_step()
        d = planner._step_to_dict(step)
        assert d["step_id"] == "step_1"
        assert d["status"] == "pending"

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_roundtrip(self, _):
        planner = Planner()
        step = _make_step(step_id="test_rt", action="exploit")
        d = planner._step_to_dict(step)
        restored = planner._dict_to_step(d)
        assert restored.step_id == step.step_id
        assert restored.action == step.action


# ---------------------------------------------------------------------------
# 4. create_plan_from_strategy
# ---------------------------------------------------------------------------
class TestCreatePlanFromStrategy:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_creates_plan(self, _):
        planner = Planner()
        strategy = _make_strategy(steps=["port_scan", "vuln_scan"])
        plan_id = planner.create_plan_from_strategy("10.0.0.1", strategy)
        assert plan_id.startswith("plan_")
        assert len(planner.steps) == 2
        assert planner.current_step_index == 0

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_step_dependencies_chained(self, _):
        planner = Planner()
        strategy = _make_strategy(steps=["port_scan", "service_scan", "vuln_scan"])
        planner.create_plan_from_strategy("10.0.0.1", strategy)
        # Step 0 has no deps, step 1 depends on step 0, etc.
        assert planner.steps[0].depends_on == []
        assert len(planner.steps[1].depends_on) == 1
        assert len(planner.steps[2].depends_on) == 1

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_tool_mapping(self, _):
        planner = Planner()
        strategy = _make_strategy(steps=["port_scan", "web_vuln_scan"])
        planner.create_plan_from_strategy("10.0.0.1", strategy)
        assert planner.steps[0].tool == "nmap_port_scan"
        assert planner.steps[1].tool == "nikto_web_scan"

    @patch("core.agent.planner.get_evolution_memory", return_value=MagicMock())
    def test_persists_to_memory(self, mock_mem):
        planner = Planner()
        strategy = _make_strategy()
        planner.create_plan_from_strategy("10.0.0.1", strategy)
        planner.memory.create_plan.assert_called_once()


# ---------------------------------------------------------------------------
# 5. create_plan_for_target
# ---------------------------------------------------------------------------
class TestCreatePlanForTarget:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_creates_4_step_plan(self, _):
        planner = Planner()
        plan_id = planner.create_plan_for_target("10.0.0.1")
        assert plan_id.startswith("plan_")
        assert len(planner.steps) == 4
        actions = [s.action for s in planner.steps]
        assert "port_scan" in actions
        assert "exploit" in actions


# ---------------------------------------------------------------------------
# 6. create_plan_from_profile
# ---------------------------------------------------------------------------
class TestCreatePlanFromProfile:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_creates_from_profile(self, _):
        planner = Planner()
        profile = _make_profile(aggressiveness=0.8)
        plan_id = planner.create_plan_from_profile("10.0.0.1", profile)
        assert plan_id.startswith("plan_")
        assert len(planner.steps) > 0

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_low_aggressiveness(self, _):
        planner = Planner()
        profile = _make_profile(aggressiveness=0.2, step_order=["recon", "scan"])
        planner.create_plan_from_profile("10.0.0.1", profile)
        actions = [s.action for s in planner.steps]
        assert "passive_recon" in actions  # Low aggression = passive

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_high_aggressiveness(self, _):
        planner = Planner()
        profile = _make_profile(aggressiveness=0.9, step_order=["recon", "exploit"])
        planner.create_plan_from_profile("10.0.0.1", profile)
        actions = [s.action for s in planner.steps]
        assert "port_scan" in actions  # High aggression = active scan
        assert "sqlmap_exploit" in actions  # High aggression = aggressive exploit

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_profile_with_params(self, _):
        planner = Planner()
        profile = _make_profile(
            parameters={"timeout": 120, "threads": 8},
            step_order=["recon"],
        )
        planner.create_plan_from_profile("10.0.0.1", profile)
        assert planner.steps[0].params.get("timeout") == 120
        assert planner.steps[0].params.get("threads") == 8

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_empty_steps_fallback(self, _):
        planner = Planner()
        profile = _make_profile(step_order=[])
        planner.create_plan_from_profile("10.0.0.1", profile)
        # Should fall back to create_plan_for_target
        assert len(planner.steps) == 4  # Default plan


# ---------------------------------------------------------------------------
# 7. get_next_step / mark_step_*
# ---------------------------------------------------------------------------
class TestPlanExecution:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_get_next_step_returns_first_pending(self, _):
        planner = Planner()
        planner.steps = [_make_step("s1"), _make_step("s2")]
        step = planner.get_next_step()
        assert step.step_id == "s1"

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_get_next_step_skips_completed(self, _):
        planner = Planner()
        planner.steps = [
            _make_step("s1", status=StepStatus.SUCCESS),
            _make_step("s2"),
        ]
        step = planner.get_next_step()
        assert step.step_id == "s2"

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_get_next_step_none_when_complete(self, _):
        planner = Planner()
        planner.steps = [_make_step("s1", status=StepStatus.SUCCESS)]
        step = planner.get_next_step()
        assert step is None

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_mark_step_executing(self, _):
        planner = Planner()
        planner.steps = [_make_step("s1")]
        planner.mark_step_executing("s1")
        assert planner.steps[0].status == StepStatus.EXECUTING

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_mark_step_success(self, _):
        planner = Planner()
        planner.steps = [_make_step("s1")]
        planner.mark_step_success("s1", "found 3 ports")
        assert planner.steps[0].status == StepStatus.SUCCESS
        assert planner.steps[0].actual_outcome == "found 3 ports"

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_mark_step_failed_retry(self, _):
        planner = Planner()
        planner.steps = [_make_step("s1", max_retries=2, retry_count=0)]
        should_replan = planner.mark_step_failed("s1", "timeout")
        assert should_replan is False  # Should retry, not replan yet
        assert planner.steps[0].status == StepStatus.PENDING

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_mark_step_failed_exceeds_retries(self, _):
        planner = Planner()
        planner.steps = [_make_step("s1", max_retries=1, retry_count=0)]
        should_replan = planner.mark_step_failed("s1", "timeout")
        assert should_replan is True
        assert planner.steps[0].status == StepStatus.FAILED

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_mark_step_failed_nonexistent(self, _):
        planner = Planner()
        planner.steps = []
        result = planner.mark_step_failed("ghost", "err")
        assert result is False

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_is_plan_complete_true(self, _):
        planner = Planner()
        planner.steps = [
            _make_step("s1", status=StepStatus.SUCCESS),
            _make_step("s2", status=StepStatus.SKIPPED),
        ]
        assert planner.is_plan_complete() is True

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_is_plan_complete_false(self, _):
        planner = Planner()
        planner.steps = [_make_step("s1"), _make_step("s2")]
        assert planner.is_plan_complete() is False


# ---------------------------------------------------------------------------
# 8. get_plan_status
# ---------------------------------------------------------------------------
class TestPlanStatus:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_empty_plan(self, _):
        planner = Planner()
        status = planner.get_plan_status()
        assert status["total_steps"] == 0
        assert status["completed"] == 0

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_mixed_status(self, _):
        planner = Planner()
        planner.current_plan_id = "plan_123"
        planner.steps = [
            _make_step("s1", status=StepStatus.SUCCESS),
            _make_step("s2", status=StepStatus.FAILED),
            _make_step("s3", status=StepStatus.SKIPPED),
            _make_step("s4", status=StepStatus.PENDING),
        ]
        status = planner.get_plan_status()
        assert status["plan_id"] == "plan_123"
        assert status["total_steps"] == 4
        assert status["completed"] == 1
        assert status["failed"] == 1
        assert status["skipped"] == 1
        assert status["pending"] == 1


# ---------------------------------------------------------------------------
# 9. replan — limits, failure analysis, tool switching
# ---------------------------------------------------------------------------
class TestReplan:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_replan_nonexistent_step(self, _):
        planner = Planner()
        planner.steps = []
        assert planner.replan("ghost") is False

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_replan_exceeds_per_step_limit(self, _):
        planner = Planner()
        step = _make_step("s1", error="some error")
        planner.steps = [step]
        planner._replan_counts = {"s1": Planner.MAX_REPLAN_PER_STEP}
        planner._total_replans = 0
        result = planner.replan("s1")
        assert result is True  # Step is skipped
        assert step.status == StepStatus.SKIPPED

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_replan_exceeds_session_limit(self, _):
        planner = Planner()
        step = _make_step("s1", error="some error")
        planner.steps = [step]
        planner._replan_counts = {}
        planner._total_replans = Planner.MAX_REPLAN_PER_SESSION
        result = planner.replan("s1")
        assert result is True
        assert step.status == StepStatus.SKIPPED

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_replan_no_alternative_skips(self, _):
        planner = Planner()
        step = _make_step("s1", action="unknown_action", tool="unknown_tool", error="failed")
        planner.steps = [step]
        result = planner.replan("s1")
        assert result is True
        assert step.status == StepStatus.SKIPPED

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_analyze_failure_timeout(self, _):
        planner = Planner()
        step = _make_step(error="Connection timed out")
        ctx = planner._analyze_failure(step)
        assert ctx["is_timeout"] is True
        assert ctx["is_conn_refused"] is False

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_analyze_failure_connection_refused(self, _):
        planner = Planner()
        step = _make_step(error="Connection refused on port 80")
        ctx = planner._analyze_failure(step)
        assert ctx["is_conn_refused"] is True

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_analyze_failure_missing(self, _):
        planner = Planner()
        step = _make_step(error="nmap: command not found")
        ctx = planner._analyze_failure(step)
        assert ctx["is_missing"] is True

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_format_replan_reason(self, _):
        planner = Planner()
        assert "Timeout" in planner._format_replan_reason({"is_timeout": True, "is_missing": False})
        assert "missing" in planner._format_replan_reason({"is_timeout": False, "is_missing": True}).lower()
        assert "Adaptive" in planner._format_replan_reason({"is_timeout": False, "is_missing": False})


# ---------------------------------------------------------------------------
# 10. Dependency handling
# ---------------------------------------------------------------------------
class TestDependencyHandling:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_skip_step_with_failed_dependency(self, _):
        planner = Planner()
        s1 = _make_step("s1", status=StepStatus.FAILED)
        s2 = _make_step("s2", depends_on=["s1"])
        planner.steps = [s1, s2]
        step = planner.get_next_step()
        # s2 should be skipped because s1 failed
        assert step is None or step.status == StepStatus.SKIPPED

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_deps_satisfied_proceed(self, _):
        planner = Planner()
        s1 = _make_step("s1", status=StepStatus.SUCCESS)
        s2 = _make_step("s2", depends_on=["s1"])
        planner.steps = [s1, s2]
        step = planner.get_next_step()
        assert step.step_id == "s2"


# ---------------------------------------------------------------------------
# 11. _find_alternative_tool
# ---------------------------------------------------------------------------
class TestFindAlternativeTool:
    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_finds_alternative(self, _):
        planner = Planner()
        alt = planner._find_alternative_tool("vuln_scan", "nmap_vuln_scan")
        assert alt is not None
        assert alt != "nmap_vuln_scan"

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_no_alternative(self, _):
        planner = Planner()
        alt = planner._find_alternative_tool("nonexistent_action", "some_tool")
        assert alt is None

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_only_same_tool_returns_none(self, _):
        planner = Planner()
        # port_scan only has nmap_port_scan
        alt = planner._find_alternative_tool("port_scan", "nmap_port_scan")
        assert alt is None


# ---------------------------------------------------------------------------
# 12. _apply_adaptive_learning
# ---------------------------------------------------------------------------
class TestAdaptiveLearning:
    def test_timeout_adjusts_heuristics(self):
        mock_mem = MagicMock()
        with patch("core.agent.planner.get_evolution_memory", return_value=mock_mem):
            planner = Planner()
            step = _make_step(error="timed out")
            context = {"is_timeout": True}
            planner._apply_adaptive_learning(step, context)
            assert mock_mem.update_heuristic.call_count == 2
            assert step.params.get("timeout") == 120

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_no_memory_no_crash(self, _):
        planner = Planner()
        step = _make_step(error="timed out")
        planner._apply_adaptive_learning(step, {"is_timeout": True})
        # Should not raise

    @patch("core.agent.planner.get_evolution_memory", side_effect=Exception("no db"))
    def test_non_timeout_no_adjustment(self, _):
        planner = Planner()
        step = _make_step(error="other error")
        planner._apply_adaptive_learning(step, {"is_timeout": False})
        assert "timeout" not in step.params
