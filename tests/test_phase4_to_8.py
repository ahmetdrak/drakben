"""Tests for Phase 4-8: Infrastructure, Multi-Agent, Reporting, CI/CD, Hardening.

Covers:
- DI Container (core/container.py)
- Health Checker (core/health.py)
- Property-based tests (hypothesis) for input_validator, cvss_calculator
- Multi-agent orchestrator FallbackChain integration
- CVSS v3.1 Calculator (modules/cvss_calculator.py)
- Report Generator enhanced Finding fields
- Graceful shutdown (stop_controller enhancements)
"""

from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# ===================================================================
# 1. DI Container
# ===================================================================


class TestDIContainer:
    """Tests for core.container."""

    def setup_method(self):
        from core.container import Container

        self.c = Container()

    def test_register_and_resolve_factory(self):
        self.c.register("foo", lambda: {"key": "value"})
        result = self.c.resolve("foo")
        assert result == {"key": "value"}

    def test_singleton_behavior(self):
        call_count = 0

        def factory():
            nonlocal call_count
            call_count += 1
            return object()

        self.c.register("obj", factory)
        a = self.c.resolve("obj")
        b = self.c.resolve("obj")
        assert a is b
        assert call_count == 1

    def test_register_instance_directly(self):
        obj = {"direct": True}
        self.c.register("inst", obj)  # Non-callable — stored as instance
        assert self.c.resolve("inst") is obj

    def test_has_registered(self):
        assert not self.c.has("x")
        self.c.register("x", lambda: 1)
        assert self.c.has("x")

    def test_resolve_unknown_raises(self):
        with pytest.raises(KeyError, match="no_such"):
            self.c.resolve("no_such")

    def test_reset_destroys_instances(self):
        obj = MagicMock()
        self.c.register("svc", obj)
        self.c.resolve("svc")
        self.c.reset()
        # After reset, the next resolve creates a new instance
        # (but factory is a MagicMock so calling it returns a new MagicMock)
        new_obj = self.c.resolve("svc")
        assert new_obj is not obj

    def test_reset_calls_close(self):
        mock_svc = MagicMock()
        self.c.register("db", mock_svc)
        self.c.resolve("db")  # Must resolve to cache the instance

        # Now register a real closeable
        class Closeable:
            closed = False

            def close(self):
                self.closed = True

        closeable = Closeable()
        self.c.register("db2", closeable)
        self.c.resolve("db2")
        self.c.reset()
        assert closeable.closed

    def test_clear_removes_everything(self):
        self.c.register("x", lambda: 1)
        self.c.clear()
        assert not self.c.has("x")

    def test_global_singleton(self):
        from core.container import get_container

        c1 = get_container()
        c2 = get_container()
        assert c1 is c2

    def test_reset_container_function(self):
        from core.container import get_container, reset_container

        c = get_container()
        c.register("tmp", lambda: 42)
        c.resolve("tmp")
        reset_container()  # Should not raise
        # Instance is gone, but factory survives
        assert c.resolve("tmp") == 42


# ===================================================================
# 2. Health Checker
# ===================================================================


class TestHealthChecker:
    """Tests for core.health."""

    def test_full_check_returns_report(self):
        from core.health import get_health_checker

        checker = get_health_checker()
        report = checker.full_check()
        assert report.status in ("healthy", "degraded", "unhealthy")
        assert isinstance(report.checks, list)
        assert len(report.checks) >= 3  # runtime, disk, config at minimum

    def test_report_to_dict(self):
        from core.health import get_health_checker

        report = get_health_checker().full_check()
        d = report.to_dict()
        assert "status" in d
        assert "checks" in d
        assert "version" in d

    def test_readiness_returns_bool(self):
        from core.health import get_health_checker

        result = get_health_checker().readiness()
        assert isinstance(result, bool)

    def test_runtime_check_always_healthy(self):
        from core.health import HealthChecker

        ok, _msg, details = HealthChecker._check_runtime()
        assert ok is True
        assert "python_version" in details

    def test_disk_check(self):
        from core.health import HealthChecker

        checker = HealthChecker()
        ok, _msg, details = checker._check_disk()
        assert isinstance(ok, bool)
        assert "free_mb" in details

    def test_docker_check_non_critical(self):
        """Docker check should never fail the overall health (it's optional)."""
        from core.health import HealthChecker

        ok, _msg, _details = HealthChecker._check_docker()
        assert ok is True  # Always True — Docker is optional

    def test_singleton(self):
        from core.health import get_health_checker

        a = get_health_checker()
        b = get_health_checker()
        assert a is b


# ===================================================================
# 3. Property-Based Tests (Hypothesis)
# ===================================================================


class TestInputValidatorProperty:
    """Property-based tests for LLMOutputValidator."""

    def setup_method(self):
        from core.security.input_validator import LLMOutputValidator

        self.validator = LLMOutputValidator()

    @given(
        cmd=st.text(
            min_size=1,
            max_size=200,
            alphabet=st.characters(
                whitelist_categories=("L", "N", "P"),
                whitelist_characters=" .-_/:",
            ),
        )
    )
    @settings(max_examples=50)
    def test_safe_commands_never_crash(self, cmd):
        """Validator should never raise on any input."""
        result = self.validator.validate_command(cmd)
        assert isinstance(result.safe, bool)
        assert isinstance(result.reason, str)

    @given(text=st.text(min_size=0, max_size=500))
    @settings(max_examples=30)
    def test_sanitize_never_crashes(self, text):
        """sanitize_for_display should handle any unicode string."""
        cleaned = self.validator.sanitize_for_display(text, max_length=100)
        assert isinstance(cleaned, str)
        assert "\x1b" not in cleaned

    @given(text=st.text(min_size=0, max_size=200))
    @settings(max_examples=30)
    def test_validate_llm_response_never_crashes(self, text):
        result = self.validator.validate_llm_response(text)
        assert isinstance(result.safe, bool)


class TestCVSSProperty:
    """Property-based tests for CVSS calculator."""

    @given(
        av=st.sampled_from(["N", "A", "L", "P"]),
        ac=st.sampled_from(["L", "H"]),
        pr=st.sampled_from(["N", "L", "H"]),
        ui=st.sampled_from(["N", "R"]),
        s=st.sampled_from(["U", "C"]),
        c=st.sampled_from(["N", "L", "H"]),
        i=st.sampled_from(["N", "L", "H"]),
        a=st.sampled_from(["N", "L", "H"]),
    )
    @settings(max_examples=100)
    def test_score_always_0_to_10(self, av, ac, pr, ui, s, c, i, a):
        from modules.cvss_calculator import CVSSCalculator

        result = CVSSCalculator.from_metrics(
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a,
        )
        assert 0.0 <= result.score <= 10.0
        assert result.severity in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    @given(
        av=st.sampled_from(["N", "A", "L", "P"]),
        ac=st.sampled_from(["L", "H"]),
        pr=st.sampled_from(["N", "L", "H"]),
        ui=st.sampled_from(["N", "R"]),
        s=st.sampled_from(["U", "C"]),
        c=st.sampled_from(["N", "L", "H"]),
        i=st.sampled_from(["N", "L", "H"]),
        a=st.sampled_from(["N", "L", "H"]),
    )
    @settings(max_examples=50)
    def test_vector_roundtrip(self, av, ac, pr, ui, s, c, i, a):
        """from_metrics → vector → from_vector should produce same score."""
        from modules.cvss_calculator import CVSSCalculator

        r1 = CVSSCalculator.from_metrics(
            attack_vector=av,
            attack_complexity=ac,
            privileges_required=pr,
            user_interaction=ui,
            scope=s,
            confidentiality=c,
            integrity=i,
            availability=a,
        )
        r2 = CVSSCalculator.from_vector(r1.vector)
        assert r1.score == r2.score
        assert r1.severity == r2.severity


# ===================================================================
# 4. CVSS Calculator (deterministic tests)
# ===================================================================


class TestCVSSCalculator:
    """Deterministic tests for modules.cvss_calculator."""

    def test_maximum_severity(self):
        from modules.cvss_calculator import CVSSCalculator

        r = CVSSCalculator.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r.score == 9.8
        assert r.severity == "CRITICAL"

    def test_zero_impact(self):
        from modules.cvss_calculator import CVSSCalculator

        r = CVSSCalculator.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert r.score == 0.0
        assert r.severity == "NONE"

    def test_medium_score(self):
        from modules.cvss_calculator import CVSSCalculator

        r = CVSSCalculator.from_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N")
        assert 3.0 <= r.score <= 6.0
        assert r.severity in ("LOW", "MEDIUM")

    def test_scope_changed(self):
        from modules.cvss_calculator import CVSSCalculator

        r = CVSSCalculator.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert r.score == 10.0
        assert r.severity == "CRITICAL"

    def test_invalid_vector_raises(self):
        from modules.cvss_calculator import CVSSCalculator

        with pytest.raises(ValueError, match="Invalid CVSS"):
            CVSSCalculator.from_vector("not-a-vector")

    def test_vector_v30_also_works(self):
        from modules.cvss_calculator import CVSSCalculator

        r = CVSSCalculator.from_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r.score == 9.8

    def test_breakdown_fields(self):
        from modules.cvss_calculator import CVSSCalculator

        r = CVSSCalculator.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert "impact" in r.breakdown
        assert "exploitability" in r.breakdown
        assert "impact_sub_score" in r.breakdown

    def test_severity_from_score(self):
        from modules.cvss_calculator import CVSSCalculator

        assert CVSSCalculator.severity_from_score(0.0) == "NONE"
        assert CVSSCalculator.severity_from_score(2.5) == "LOW"
        assert CVSSCalculator.severity_from_score(5.0) == "MEDIUM"
        assert CVSSCalculator.severity_from_score(8.0) == "HIGH"
        assert CVSSCalculator.severity_from_score(9.5) == "CRITICAL"


# ===================================================================
# 5. Multi-Agent Orchestrator (Phase 5 enhancements)
# ===================================================================


class TestMultiAgentEnhanced:
    """Tests for enhanced MultiAgentOrchestrator."""

    def _mock_client(self, response="OK"):
        client = MagicMock()
        client.query.return_value = response
        return client

    def test_delegate_returns_latency(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        orch = MultiAgentOrchestrator(llm_client=self._mock_client("scan done"))
        result = orch.delegate(AgentRole.SCANNING, "analyze this output")
        assert result["success"] is True
        assert "latency_ms" in result
        assert result["latency_ms"] >= 0

    def test_delegate_with_context(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        client = self._mock_client("found vulns")
        orch = MultiAgentOrchestrator(llm_client=client)
        result = orch.delegate(
            AgentRole.RESEARCHER,
            "find exploits",
            context={"target": "10.0.0.1", "os": "Linux"},
        )
        assert result["success"] is True
        # Context should be injected into prompt
        call_args = client.query.call_args
        assert "10.0.0.1" in call_args.kwargs.get("prompt", call_args[1].get("prompt", ""))

    def test_fallback_chain_integration(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        mock_chain = MagicMock()
        mock_chain.query.return_value = MagicMock(
            success=True,
            response="fallback answer",
            provider_used="backup",
        )
        orch = MultiAgentOrchestrator(fallback_chain=mock_chain)
        result = orch.delegate(AgentRole.REASONING, "plan attack")
        assert result["success"] is True
        assert result["model"] == "backup"

    def test_no_client_returns_failure(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        orch = MultiAgentOrchestrator()
        result = orch.delegate(AgentRole.DEFAULT, "hello")
        assert result["success"] is False

    def test_stats_include_new_fields(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        orch = MultiAgentOrchestrator(llm_client=self._mock_client())
        orch.delegate(AgentRole.PARSING, "parse this")
        stats = orch.get_stats()
        assert "total_delegations" in stats
        assert "success_rate" in stats
        assert "avg_latency_ms" in stats
        assert stats["total_delegations"] == 1
        assert stats["success_rate"] == 1.0

    def test_delegation_record_stored(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        orch = MultiAgentOrchestrator(llm_client=self._mock_client())
        orch.delegate(AgentRole.CODING, "write exploit")
        assert len(orch._delegation_history) == 1
        rec = orch._delegation_history[0]
        assert rec.role == "coding"
        assert rec.success is True

    def test_prompt_registry_integration(self):
        """get_system_prompt should try PromptRegistry first."""
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        orch = MultiAgentOrchestrator()
        # Even without registry match, should fall back to hardcoded
        prompt = orch.get_system_prompt(AgentRole.REASONING)
        assert len(prompt) > 10
        # Could come from registry or hardcoded — both mention strategy/security
        lower = prompt.lower()
        assert any(w in lower for w in ("penetration", "strategic", "strateg", "security"))

    def test_all_roles_have_system_prompt(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        orch = MultiAgentOrchestrator()
        for role in AgentRole:
            prompt = orch.get_system_prompt(role)
            assert isinstance(prompt, str)
            assert len(prompt) > 5

    def test_tier_for_all_roles(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator

        orch = MultiAgentOrchestrator()
        for role in AgentRole:
            tier = orch.get_tier(role)
            assert tier in ("cheap", "mid", "expensive")


# ===================================================================
# 6. Report Generator Enhanced Fields
# ===================================================================


class TestFindingEnhanced:
    """Tests for enhanced Finding dataclass."""

    def test_cvss_vector_field(self):
        from modules.report_generator import Finding, FindingSeverity

        f = Finding(
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            description="Union-based SQLi",
            affected_asset="10.0.0.1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
        )
        d = f.to_dict()
        assert d["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert d["cvss_score"] == 9.8

    def test_evidence_artifacts_field(self):
        from modules.report_generator import Finding, FindingSeverity

        f = Finding(
            title="Open Port",
            severity=FindingSeverity.INFO,
            description="Port 80 open",
            affected_asset="10.0.0.1",
            evidence_artifacts=["nmap output: 80/tcp open http"],
        )
        d = f.to_dict()
        assert len(d["evidence_artifacts"]) == 1
        assert "nmap" in d["evidence_artifacts"][0]

    def test_defaults_backward_compatible(self):
        from modules.report_generator import Finding, FindingSeverity

        f = Finding(
            title="Test",
            severity=FindingSeverity.LOW,
            description="desc",
            affected_asset="host",
        )
        d = f.to_dict()
        assert d["cvss_vector"] is None
        assert d["evidence_artifacts"] == []


# ===================================================================
# 7. Graceful Shutdown (StopController enhancements)
# ===================================================================


class TestGracefulShutdown:
    """Tests for enhanced StopController."""

    def setup_method(self):
        from core.stop_controller import StopController

        # Create a fresh instance (bypass singleton for isolation)
        self.ctrl = StopController.__new__(StopController)
        self.ctrl._initialized = False
        self.ctrl.__init__()

    def test_graceful_shutdown_returns_summary(self):
        result = self.ctrl.graceful_shutdown(timeout=2.0)
        assert result["status"] in ("clean", "partial")
        assert "completed_phases" in result
        assert "signal" in result["completed_phases"]

    def test_graceful_shutdown_sets_stop_flag(self):
        assert not self.ctrl.is_stopped()
        self.ctrl.graceful_shutdown(timeout=1.0)
        assert self.ctrl.is_stopped()

    def test_shutdown_phases_order(self):
        result = self.ctrl.graceful_shutdown(timeout=2.0)
        phases = result["completed_phases"]
        # Signal should always be first
        assert phases[0] == "signal"
        # drain_processes should come before cleanup_callbacks
        if "drain_processes" in phases and "cleanup_callbacks" in phases:
            assert phases.index("drain_processes") < phases.index("cleanup_callbacks")

    def test_cleanup_callback_called_during_shutdown(self):
        called = False

        def my_cleanup():
            nonlocal called
            called = True

        self.ctrl.register_cleanup(my_cleanup)
        self.ctrl.graceful_shutdown(timeout=2.0)
        assert called

    def test_reset_clears_shutdown_phases(self):
        self.ctrl.graceful_shutdown(timeout=1.0)
        assert len(self.ctrl._shutdown_phases) > 0
        self.ctrl.reset()
        assert len(self.ctrl._shutdown_phases) == 0
        assert not self.ctrl.is_stopped()

    def test_check_stop_convenience(self):
        from core.stop_controller import check_stop, stop_controller

        stop_controller.reset()
        assert not check_stop()
        stop_controller.stop()
        assert check_stop()
        stop_controller.reset()
