"""Tests for Strix-gap closure improvements.

Covers:
1. Error handling: specific exception catches
2. AgentProtocol mixin base (TYPE_CHECKING-only Protocol)
3. OpenTelemetry bridge in observability module
"""

from __future__ import annotations

import importlib
import threading
from unittest.mock import MagicMock, patch

import pytest

# =====================================================================
# 1. Error‑handling specificity — verify handlers catch the right types
# =====================================================================


class TestErrorHandlingSpecificity:
    """Verify that narrowed except clauses catch expected types."""

    def test_config_catches_oserror(self):
        """Config.llm_client handler catches OSError (not bare Exception)."""
        from core.config import ConfigManager

        with patch("core.config.API_ENV_PATH", "/nonexistent/api.env"):
            mgr = ConfigManager.__new__(ConfigManager)
            mgr._settings = {}
            mgr._lock = threading.RLock()
            mgr._llm_client = None

        with patch(
            "llm.openrouter_client.OpenRouterClient",
            side_effect=OSError("disk full"),
        ):
            client = mgr.llm_client
            assert client is None  # Graceful degradation

    def test_config_does_not_catch_bare_exception(self):
        """Config.llm_client does NOT swallow bare Exception."""
        from core.config import ConfigManager

        with patch("core.config.API_ENV_PATH", "/nonexistent/api.env"):
            mgr = ConfigManager.__new__(ConfigManager)
            mgr._settings = {}
            mgr._lock = threading.RLock()
            mgr._llm_client = None

        with patch(
            "llm.openrouter_client.OpenRouterClient",
            side_effect=Exception("unexpected"),
        ):
            with pytest.raises(Exception, match="unexpected"):
                _ = mgr.llm_client

    def test_planner_catches_runtime_error(self):
        """Planner.__init__ catches RuntimeError for evolution memory."""
        with patch(
            "core.agent.planner.get_evolution_memory",
            side_effect=RuntimeError("no db"),
        ):
            from core.agent.planner import Planner

            p = Planner()
            assert p.memory is None

    def test_planner_does_not_catch_type_error(self):
        """Planner.__init__ does NOT catch TypeError (not in its handler)."""
        with patch(
            "core.agent.planner.get_evolution_memory",
            side_effect=TypeError("bad arg"),
        ):
            from core.agent.planner import Planner

            with pytest.raises(TypeError, match="bad arg"):
                Planner()

    def test_health_checker_catches_os_error(self):
        """HealthChecker._check_disk catches OSError."""
        from core.health import HealthChecker

        checker = HealthChecker()
        with patch("shutil.disk_usage", side_effect=OSError("perm")):
            healthy, msg, _details = checker._check_disk()
            assert healthy is False
            assert "perm" in msg

    def test_stop_controller_catches_import_error(self):
        """StopController.graceful_shutdown catches ImportError for cleanup."""
        from core.stop_controller import StopController

        sc = StopController()
        sc._stop_event.set()
        # Shouldn't raise — ImportError is caught internally
        sc.graceful_shutdown()


# =====================================================================
# 2. AgentProtocol — TYPE_CHECKING-only mixin base
# =====================================================================


class TestAgentProtocol:
    """Verify the AgentProtocol mixin pattern works correctly."""

    def test_protocol_importable(self):
        """AgentProtocol can be imported."""
        from core.agent._agent_protocol import AgentProtocol

        assert AgentProtocol is not None

    def test_protocol_has_core_attributes(self):
        """AgentProtocol declares required core attributes."""

        from core.agent._agent_protocol import AgentProtocol

        hints = {}
        for cls in AgentProtocol.__mro__:
            if hasattr(cls, "__annotations__"):
                hints.update(cls.__annotations__)

        required = [
            "console",
            "state",
            "brain",
            "tool_selector",
            "executor",
            "running",
            "stagnation_counter",
            "current_strategy",
            "MSG_STATE_NOT_NONE",
            "STYLE_GREEN",
        ]
        for attr in required:
            assert attr in hints, f"Missing attribute: {attr}"

    def test_protocol_has_cross_mixin_methods(self):
        """AgentProtocol declares cross-mixin method signatures."""
        from core.agent._agent_protocol import AgentProtocol

        assert hasattr(AgentProtocol, "_diagnose_error")
        assert hasattr(AgentProtocol, "_format_tool_result")
        assert hasattr(AgentProtocol, "_handle_tool_failure")

    def test_mixin_inherits_protocol_at_typecheck_only(self):
        """Mixins inherit from _MixinBase which is object at runtime."""
        from core.agent.ra_tool_executors import RAToolExecutorsMixin

        # At runtime, the base should be plain object (not AgentProtocol)
        bases = RAToolExecutorsMixin.__bases__
        assert object in bases or all(b.__name__ in ("object", "_MixinBase") for b in bases)

    def test_all_mixins_have_mixin_base(self):
        """All 8 RA mixins use _MixinBase pattern."""
        mixin_modules = [
            "core.agent.ra_tool_executors",
            "core.agent.ra_state_updates",
            "core.agent.ra_tool_recovery",
            "core.agent.ra_tool_runner",
            "core.agent.ra_failure_recovery",
            "core.agent.ra_output_analysis",
            "core.agent.ra_profile_selection",
            "core.agent.ra_reflection",
        ]
        for mod_name in mixin_modules:
            mod = importlib.import_module(mod_name)
            # Module should have _MixinBase
            assert hasattr(mod, "_MixinBase"), f"{mod_name} missing _MixinBase"

    def test_refactored_agent_inherits_all_mixins(self):
        """RefactoredDrakbenAgent still composes all mixins."""
        with patch.dict("os.environ", {"OPENROUTER_API_KEY": "test"}):
            from core.agent.refactored_agent import RefactoredDrakbenAgent

            mro_names = [c.__name__ for c in RefactoredDrakbenAgent.__mro__]
            expected_mixins = [
                "RAToolExecutorsMixin",
                "RAStateUpdatesMixin",
                "RAToolRecoveryMixin",
                "RAToolRunnerMixin",
            ]
            for mixin in expected_mixins:
                assert mixin in mro_names, f"{mixin} not in MRO"


# =====================================================================
# 3. OpenTelemetry bridge
# =====================================================================


class TestOpenTelemetryBridge:
    """Verify OTEL integration in observability module."""

    def test_tracer_works_without_otel(self):
        """Tracer works normally when OTEL is not installed."""
        from core.observability import Tracer

        Tracer.reset()
        tracer = Tracer()

        with tracer.span("test_op", {"key": "value"}) as sp:
            sp.set_attribute("result", 42)

        traces = tracer.get_traces(limit=5)
        assert len(traces) >= 1
        assert traces[-1]["name"] == "test_op"
        assert traces[-1]["attributes"]["result"] == 42
        Tracer.reset()

    def test_otel_bridge_flag_exists(self):
        """Module exposes _OTEL_AVAILABLE flag."""
        from core import observability

        assert hasattr(observability, "_OTEL_AVAILABLE")
        assert isinstance(observability._OTEL_AVAILABLE, bool)

    def test_mirror_to_otel_noop_without_otel(self):
        """_mirror_to_otel is no-op when OTEL is absent."""
        from core.observability import Span, Tracer

        Tracer.reset()
        sp = Span(name="test", attributes={"a": 1})
        sp.end_time = sp.start_time + 0.1
        sp.status = "ok"
        # Should not raise
        Tracer._mirror_to_otel(sp)
        Tracer.reset()

    def test_otel_bridge_with_mock_otel(self):
        """When OTEL is available, spans are mirrored."""
        from core.observability import Span, Tracer

        mock_otel_span = MagicMock()
        mock_otel_tracer = MagicMock()
        mock_otel_tracer.start_span.return_value = mock_otel_span

        # Mock OTEL status code
        mock_status = MagicMock()
        mock_status.OK = "OK"
        mock_status.ERROR = "ERROR"

        import core.observability as obs

        orig_available = obs._OTEL_AVAILABLE
        orig_tracer = obs._otel_tracer
        orig_status = getattr(obs, "OtelStatusCode", None)

        try:
            obs._OTEL_AVAILABLE = True
            obs._otel_tracer = mock_otel_tracer
            obs.OtelStatusCode = mock_status

            sp = Span(name="mirrored_op", attributes={"target": "10.0.0.1"})
            sp.end_time = sp.start_time + 0.5
            sp.status = "ok"

            Tracer._mirror_to_otel(sp)

            mock_otel_tracer.start_span.assert_called_once()
            call_args = mock_otel_tracer.start_span.call_args
            assert call_args[0][0] == "mirrored_op"
            mock_otel_span.set_status.assert_called_once()
            mock_otel_span.end.assert_called_once()
        finally:
            obs._OTEL_AVAILABLE = orig_available
            obs._otel_tracer = orig_tracer
            if orig_status is not None:
                obs.OtelStatusCode = orig_status

    def test_otel_bridge_error_span(self):
        """Error spans are properly mirrored with ERROR status."""
        from core.observability import Span, Tracer

        mock_span = MagicMock()
        mock_tracer = MagicMock()
        mock_tracer.start_span.return_value = mock_span
        mock_status = MagicMock()
        mock_status.OK = "OK"
        mock_status.ERROR = "ERROR"

        import core.observability as obs

        orig = (obs._OTEL_AVAILABLE, obs._otel_tracer, getattr(obs, "OtelStatusCode", None))

        try:
            obs._OTEL_AVAILABLE = True
            obs._otel_tracer = mock_tracer
            obs.OtelStatusCode = mock_status

            sp = Span(name="failing_op")
            sp.set_status("error", "connection refused")
            sp.end_time = sp.start_time + 1.0

            Tracer._mirror_to_otel(sp)

            mock_span.set_status.assert_called_once_with("ERROR", "connection refused")
        finally:
            obs._OTEL_AVAILABLE, obs._otel_tracer = orig[0], orig[1]
            if orig[2] is not None:
                obs.OtelStatusCode = orig[2]

    def test_metrics_still_work(self):
        """MetricsCollector continues to work with OTEL changes."""
        from core.observability import MetricsCollector

        MetricsCollector.reset()
        mc = MetricsCollector()

        mc.increment("test.counter", 5, tags={"env": "test"})
        mc.gauge("test.gauge", 42.5)
        mc.histogram("test.hist", 100.0)

        data = mc.get_all()
        assert "test.counter{env=test}" in data["counters"]
        assert data["counters"]["test.counter{env=test}"] == 5
        assert data["gauges"]["test.gauge"] == 42.5
        assert "test.hist" in data["histograms"]
        MetricsCollector.reset()


# =====================================================================
# 4. Integration: mixin + error handling together
# =====================================================================


class TestMixinIntegration:
    """Integration tests ensuring mixins + error handling coexist."""

    def test_mixin_base_does_not_affect_runtime_behavior(self):
        """_MixinBase = object at runtime, so no method resolution change."""
        from core.agent.ra_tool_executors import _MixinBase

        assert _MixinBase is object

    def test_protocol_is_protocol_type(self):
        """AgentProtocol is a typing.Protocol subclass."""
        from core.agent._agent_protocol import AgentProtocol

        # Protocol classes have _is_protocol attribute
        assert getattr(AgentProtocol, "_is_protocol", False) is True
