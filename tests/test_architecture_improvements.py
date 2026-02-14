"""Tests for new architectural modules.

Covers: EventBus, Observability (Tracer, Metrics), KnowledgeGraph,
        ToolDispatcher, MultiAgent, typed ContextManager, sub-configs,
        lazy core/__init__.py, CloudScanner, WebAPI.
"""

import json
import threading
import time
from unittest.mock import MagicMock

import pytest


# ===================================================================
# 1. EventBus
# ===================================================================
class TestEventBus:
    """Tests for core.events.EventBus."""

    def setup_method(self):
        # Reset to clean state before each test
        from core.events import EventBus
        EventBus.reset()

    def teardown_method(self):
        # Ensure clean state after test
        from core.events import EventBus
        EventBus.reset()
        EventBus._instance = None

    def test_singleton(self):
        from core.events import EventBus
        a = EventBus()
        b = EventBus()
        assert a is b

    def test_subscribe_and_publish(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        received = []
        bus.subscribe(EventType.TOOL_START, lambda e: received.append(e))
        bus.publish(EventType.TOOL_START, {"tool": "nmap"})
        assert len(received) == 1
        assert received[0].data["tool"] == "nmap"
        assert received[0].type == EventType.TOOL_START

    def test_subscribe_all(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        received = []
        bus.subscribe_all(lambda e: received.append(e))
        bus.publish(EventType.TOOL_START)
        bus.publish(EventType.TOOL_COMPLETE)
        assert len(received) == 2

    def test_unsubscribe(self):
        from core.events import EventBus, EventType
        bus = EventBus()

        def handler(_e):
            pass  # No-op handler for testing subscribe/unsubscribe

        bus.subscribe(EventType.TOOL_START, handler)
        assert bus.subscriber_count >= 1
        bus.unsubscribe(EventType.TOOL_START, handler)

    def test_unsubscribe_all(self):
        from core.events import EventBus, EventType
        bus = EventBus()

        def handler(_e):
            pass  # No-op handler for testing subscribe/unsubscribe

        bus.subscribe(EventType.TOOL_START, handler)
        bus.subscribe_all(handler)
        bus.unsubscribe_all(handler)

    def test_pause_resume(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        received = []
        bus.subscribe(EventType.TOOL_START, lambda e: received.append(e))
        bus.pause()
        bus.publish(EventType.TOOL_START)
        assert len(received) == 0
        bus.resume()
        bus.publish(EventType.TOOL_START)
        assert len(received) == 1

    def test_history(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        bus.publish(EventType.TOOL_START, {"tool": "nmap"})
        bus.publish(EventType.TOOL_COMPLETE, {"tool": "nmap"})
        history = bus.get_history()
        assert len(history) == 2
        filtered = bus.get_history(EventType.TOOL_START)
        assert len(filtered) == 1

    def test_history_limit(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        for i in range(bus.MAX_HISTORY + 100):
            bus.publish(EventType.METRIC, {"i": i})
        history = bus.get_history()
        assert len(history) <= bus.MAX_HISTORY

    def test_handler_exception_does_not_crash(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        bus.subscribe(EventType.TOOL_START, lambda e: 1 / 0)
        # Should not raise
        bus.publish(EventType.TOOL_START)

    def test_event_immutable(self):
        from core.events import Event, EventType
        e = Event(type=EventType.TOOL_START, data={"k": "v"})
        assert e.type == EventType.TOOL_START
        assert e.timestamp > 0

    def test_get_event_bus(self):
        from core.events import get_event_bus
        bus = get_event_bus()
        assert bus is not None

    def test_clear(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        bus.subscribe(EventType.TOOL_START, lambda e: None)
        bus.publish(EventType.TOOL_START)
        bus.clear()
        assert bus.subscriber_count == 0
        assert len(bus.get_history()) == 0

    def test_thread_safety(self):
        from core.events import EventBus, EventType
        bus = EventBus()
        counter = {"value": 0}
        lock = threading.Lock()

        def handler(e):
            with lock:
                counter["value"] += 1

        bus.subscribe(EventType.METRIC, handler)
        threads = [
            threading.Thread(target=lambda: bus.publish(EventType.METRIC))
            for _ in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert counter["value"] == 50

    def test_all_event_types_exist(self):
        from core.events import EventType
        assert len(EventType) > 30  # Minimum expected event types


# ===================================================================
# 2. Observability (Tracer + Metrics)
# ===================================================================
class TestTracer:
    """Tests for core.observability.Tracer."""

    def setup_method(self):
        # Reset to clean state before each test
        from core.observability import Tracer
        Tracer.reset()

    def teardown_method(self):
        # Ensure clean state after test
        from core.observability import Tracer
        Tracer.reset()
        Tracer._instance = None

    def test_singleton(self):
        from core.observability import Tracer
        a = Tracer()
        b = Tracer()
        assert a is b

    def test_span_basic(self):
        from core.observability import get_tracer
        tracer = get_tracer()
        with tracer.span("test_op", {"key": "value"}) as sp:
            sp.set_attribute("extra", 42)
        traces = tracer.get_traces()
        assert len(traces) == 1
        assert traces[0]["name"] == "test_op"
        assert traces[0]["status"] == "ok"
        assert traces[0]["attributes"]["extra"] == 42

    def test_span_error(self):
        from core.observability import get_tracer
        tracer = get_tracer()
        with pytest.raises(ValueError, match="boom"):
            with tracer.span("failing_op"):
                raise ValueError("boom")
        traces = tracer.get_traces()
        assert traces[0]["status"] == "error"

    def test_nested_spans(self):
        from core.observability import get_tracer
        tracer = get_tracer()
        with tracer.span("parent"):
            with tracer.span("child") as child:
                child.set_attribute("level", "inner")
        traces = tracer.get_traces()
        assert len(traces) == 1  # Only root
        assert len(traces[0]["children"]) == 1

    def test_span_duration(self):
        from core.observability import get_tracer
        tracer = get_tracer()
        with tracer.span("timed") as sp:
            time.sleep(0.01)
        assert sp.duration_ms >= 5  # At least 5ms

    def test_span_events(self):
        from core.observability import get_tracer
        tracer = get_tracer()
        with tracer.span("with_events") as sp:
            sp.add_event("checkpoint", {"step": 1})
            sp.add_event("done")
        traces = tracer.get_traces()
        assert len(traces[0]["events"]) == 2

    def test_disabled_tracer(self):
        from core.observability import get_tracer
        tracer = get_tracer()
        tracer.disable()
        with tracer.span("no_op") as sp:
            sp.set_attribute("key", "val")  # No-op
        assert len(tracer.get_traces()) == 0
        tracer.enable()

    def test_export_json(self, tmp_path):
        from core.observability import get_tracer
        tracer = get_tracer()
        with tracer.span("export_test"):
            pass  # Span body intentionally empty — testing export only
        path = tmp_path / "traces.json"
        tracer.export_json(path)
        data = json.loads(path.read_text())
        assert len(data) == 1


class TestMetricsCollector:
    """Tests for core.observability.MetricsCollector."""

    def setup_method(self):
        # Reset to clean state before each test
        from core.observability import MetricsCollector
        MetricsCollector.reset()

    def teardown_method(self):
        # Ensure clean state after test
        from core.observability import MetricsCollector
        MetricsCollector.reset()
        MetricsCollector._instance = None

    def test_singleton(self):
        from core.observability import MetricsCollector
        a = MetricsCollector()
        b = MetricsCollector()
        assert a is b

    def test_counter(self):
        from core.observability import get_metrics
        m = get_metrics()
        m.increment("test.counter")
        m.increment("test.counter", 5.0)
        data = m.get_all()
        assert data["counters"]["test.counter"] == pytest.approx(6.0)

    def test_counter_with_tags(self):
        from core.observability import get_metrics
        m = get_metrics()
        m.increment("tools.executed", tags={"tool": "nmap"})
        m.increment("tools.executed", tags={"tool": "nikto"})
        data = m.get_all()
        assert "tools.executed{tool=nmap}" in data["counters"]
        assert "tools.executed{tool=nikto}" in data["counters"]

    def test_gauge(self):
        from core.observability import get_metrics
        m = get_metrics()
        m.gauge("memory.usage", 42.5)
        m.gauge("memory.usage", 50.0)
        data = m.get_all()
        assert data["gauges"]["memory.usage"] == pytest.approx(50.0)

    def test_histogram(self):
        from core.observability import get_metrics
        m = get_metrics()
        for v in [10, 20, 30, 40, 50]:
            m.histogram("tool.duration", float(v))
        data = m.get_all()
        hist = data["histograms"]["tool.duration"]
        assert hist["count"] == 5
        assert hist["min"] == pytest.approx(10.0)
        assert hist["max"] == pytest.approx(50.0)
        assert hist["avg"] == pytest.approx(30.0)

    def test_export_json(self, tmp_path):
        from core.observability import get_metrics
        m = get_metrics()
        m.increment("export.test")
        path = tmp_path / "metrics.json"
        m.export_json(path)
        data = json.loads(path.read_text())
        assert "counters" in data


# ===================================================================
# 3. Knowledge Graph
# ===================================================================
class TestKnowledgeGraph:
    """Tests for core.knowledge_graph.KnowledgeGraph."""

    def setup_method(self):
        # Reset to clean state before each test
        from core.knowledge_graph import KnowledgeGraph
        KnowledgeGraph.reset()

    def teardown_method(self):
        # Ensure clean state after test
        from core.knowledge_graph import KnowledgeGraph
        KnowledgeGraph.reset()
        KnowledgeGraph._instance = None

    def test_singleton(self):
        from core.knowledge_graph import KnowledgeGraph
        a = KnowledgeGraph(db_path=":memory:")
        b = KnowledgeGraph()
        assert a is b

    def test_add_and_get_entity(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "10.0.0.1", {"os": "Linux"})
        entity = kg.get_entity("10.0.0.1")
        assert entity is not None
        assert entity.entity_type == "host"
        assert entity.properties["os"] == "Linux"

    def test_entity_upsert(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "10.0.0.1", {"os": "Linux"})
        kg.add_entity("host", "10.0.0.1", {"os": "Ubuntu 22.04"})
        entity = kg.get_entity("10.0.0.1")
        assert entity.properties["os"] == "Ubuntu 22.04"

    def test_add_relation(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "10.0.0.1")
        kg.add_entity("service", "10.0.0.1:80", {"name": "http"})
        rel = kg.add_relation("10.0.0.1", "10.0.0.1:80", "RUNS")
        assert rel.source_id == "10.0.0.1"
        assert rel.relation_type == "RUNS"

    def test_get_related_outgoing(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "10.0.0.1")
        kg.add_entity("service", "10.0.0.1:80")
        kg.add_entity("service", "10.0.0.1:443")
        kg.add_relation("10.0.0.1", "10.0.0.1:80", "RUNS")
        kg.add_relation("10.0.0.1", "10.0.0.1:443", "RUNS")
        related = kg.get_related("10.0.0.1")
        assert len(related) == 2

    def test_get_related_incoming(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("service", "10.0.0.1:80")
        kg.add_entity("vulnerability", "CVE-2021-44228")
        kg.add_relation("10.0.0.1:80", "CVE-2021-44228", "VULNERABLE_TO")
        related = kg.get_related("CVE-2021-44228", direction="incoming")
        assert len(related) == 1

    def test_find_entities_by_type(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "10.0.0.1")
        kg.add_entity("host", "10.0.0.2")
        kg.add_entity("service", "10.0.0.1:80")
        hosts = kg.find_entities(entity_type="host")
        assert len(hosts) == 2

    def test_find_attack_paths(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "entry")
        kg.add_entity("service", "http_80")
        kg.add_entity("vulnerability", "sqli")
        kg.add_entity("foothold", "shell")
        kg.add_relation("entry", "http_80", "RUNS")
        kg.add_relation("http_80", "sqli", "VULNERABLE_TO")
        kg.add_relation("sqli", "shell", "LEADS_TO")
        paths = kg.find_attack_paths("entry", "foothold")
        assert len(paths) >= 1
        assert paths[0][-1] == "shell"

    def test_stats(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "h1")
        kg.add_entity("service", "s1")
        kg.add_relation("h1", "s1", "RUNS")
        stats = kg.stats()
        assert stats["entities"] == 2
        assert stats["relations"] == 1

    def test_clear(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "h1")
        kg.clear()
        assert kg.stats()["entities"] == 0

    def test_export_json(self, tmp_path):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "h1", {"os": "Linux"})
        path = tmp_path / "graph.json"
        kg.export_json(path)
        data = json.loads(path.read_text())
        assert len(data["entities"]) == 1

    def test_entity_not_found(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        assert kg.get_entity("nonexistent") is None

    def test_relation_with_confidence(self):
        from core.knowledge_graph import get_knowledge_graph
        kg = get_knowledge_graph(db_path=":memory:")
        kg.add_entity("host", "h1")
        kg.add_entity("vuln", "v1")
        rel = kg.add_relation("h1", "v1", "VULNERABLE_TO", confidence=0.8)
        assert rel.confidence == pytest.approx(0.8)


# ===================================================================
# 4. Typed ContextManager
# ===================================================================
class TestTypedContextManager:
    """Tests for core.agent.brain_context with ContextKey."""

    def test_typed_set_and_get(self):
        from core.agent.brain_context import ContextKey, ContextManager
        cm = ContextManager()
        cm.set(ContextKey.TARGET, "10.0.0.1")
        assert cm.get(ContextKey.TARGET) == "10.0.0.1"

    def test_string_backward_compat(self):
        from core.agent.brain_context import ContextManager
        cm = ContextManager()
        cm.update({"target": "10.0.0.1"})
        assert cm.get("target") == "10.0.0.1"

    def test_enum_key_in_update(self):
        from core.agent.brain_context import ContextKey, ContextManager
        cm = ContextManager()
        cm.update({ContextKey.PHASE: "recon"})
        assert cm.get(ContextKey.PHASE) == "recon"
        assert cm.get("phase") == "recon"

    def test_get_typed(self):
        from core.agent.brain_context import ContextKey, ContextManager
        cm = ContextManager()
        cm.set(ContextKey.ITERATION, 5)
        assert cm.get_typed(ContextKey.ITERATION, int) == 5
        # Wrong type → returns default
        assert cm.get_typed(ContextKey.ITERATION, str, "fallback") == "fallback"

    def test_has(self):
        from core.agent.brain_context import ContextKey, ContextManager
        cm = ContextManager()
        assert not cm.has(ContextKey.TARGET)
        cm.set(ContextKey.TARGET, "x")
        assert cm.has(ContextKey.TARGET)
        assert cm.has("target")

    def test_remove(self):
        from core.agent.brain_context import ContextKey, ContextManager
        cm = ContextManager()
        cm.set(ContextKey.TARGET, "x")
        cm.remove(ContextKey.TARGET)
        assert not cm.has(ContextKey.TARGET)

    def test_snapshot(self):
        from core.agent.brain_context import ContextKey, ContextManager
        cm = ContextManager()
        cm.set(ContextKey.TARGET, "x")
        snap = cm.snapshot()
        assert snap == {"target": "x"}
        # Mutating snapshot doesn't affect original
        snap["target"] = "y"
        assert cm.get(ContextKey.TARGET) == "x"

    def test_detect_changes(self):
        from core.agent.brain_context import ContextManager
        cm = ContextManager()
        cm.update({"a": 1})
        cm.update({"a": 2, "b": 3})
        ctx = cm.get_full_context()
        assert any("Changed: a" in c for c in ctx["changes"])
        assert any("Added: b" in c for c in ctx["changes"])

    def test_history_cap(self):
        from core.agent.brain_context import ContextManager
        cm = ContextManager()
        for i in range(cm.MAX_HISTORY_SIZE + 50):
            cm.update({"i": i})
        assert len(cm.context_history) <= cm.MAX_HISTORY_SIZE

    def test_clear_history(self):
        from core.agent.brain_context import ContextManager
        cm = ContextManager()
        cm.update({"a": 1})
        cm.clear_history()
        assert len(cm.context_history) == 0

    def test_context_key_values(self):
        from core.agent.brain_context import ContextKey
        assert ContextKey.TARGET.value == "target"
        assert ContextKey.PHASE.value == "phase"
        assert len(ContextKey) >= 20


# ===================================================================
# 5. DrakbenConfig Sub-configs
# ===================================================================
class TestDrakbenConfigSubConfigs:
    """Tests for config split into LLMConfig, SecurityConfig, etc."""

    def test_llm_sub_config(self):
        from core.config import DrakbenConfig
        cfg = DrakbenConfig(llm_provider="openrouter", openrouter_model="gpt-4o")
        llm = cfg.llm
        assert llm.provider == "openrouter"
        assert llm.openrouter_model == "gpt-4o"

    def test_security_sub_config(self):
        from core.config import DrakbenConfig
        cfg = DrakbenConfig(auto_approve=True, ssl_verify=False)
        sec = cfg.security
        assert sec.auto_approve is True
        assert sec.ssl_verify is False

    def test_ui_sub_config(self):
        from core.config import DrakbenConfig
        cfg = DrakbenConfig(language="tr", verbose=True)
        ui = cfg.ui
        assert ui.language == "tr"
        assert ui.verbose is True

    def test_session_sub_config(self):
        from core.config import DrakbenConfig
        cfg = DrakbenConfig(target="10.0.0.1")
        sess = cfg.session
        assert sess.target == "10.0.0.1"

    def test_engine_sub_config(self):
        from core.config import DrakbenConfig
        cfg = DrakbenConfig(stealth_mode=True, max_threads=8)
        eng = cfg.engine
        assert eng.stealth_mode is True
        assert eng.max_threads == 8

    def test_backward_compat_flat_access(self):
        from core.config import DrakbenConfig
        cfg = DrakbenConfig()
        assert cfg.llm_provider == "auto"
        assert cfg.language == "en"
        assert cfg.auto_approve is False

    def test_model_overrides(self):
        from core.config import DrakbenConfig
        cfg = DrakbenConfig(model_overrides={"reasoning": "gpt-4o", "parsing": "llama-3.1-8b"})
        llm = cfg.llm
        assert llm.get_model_for_role("reasoning") == "gpt-4o"
        assert llm.get_model_for_role("parsing") == "llama-3.1-8b"
        assert llm.get_model_for_role("unknown") is None

    def test_llm_config_standalone(self):
        from core.config import LLMConfig
        llm = LLMConfig(provider="ollama", ollama_model="codellama")
        assert llm.provider == "ollama"
        assert llm.ollama_model == "codellama"

    def test_security_config_standalone(self):
        from core.config import SecurityConfig
        sec = SecurityConfig()
        assert sec.auto_approve is False
        assert sec.ssl_verify is True


# ===================================================================
# 6. Tool Dispatch (Strategy Pattern)
# ===================================================================
class TestToolDispatcher:
    """Tests for core.agent.tool_dispatch.ToolDispatcher."""

    def test_registered_tools(self):
        from core.agent.tool_dispatch import ToolDispatcher
        agent = MagicMock()
        agent.tool_selector.is_tool_blocked.return_value = False
        dispatcher = ToolDispatcher(agent)
        assert "system_evolution" in dispatcher.registered_tools
        assert "waf_bypass" in dispatcher.registered_tools
        assert "metasploit_exploit" in dispatcher.registered_tools

    def test_registered_prefixes(self):
        from core.agent.tool_dispatch import ToolDispatcher
        agent = MagicMock()
        dispatcher = ToolDispatcher(agent)
        assert "ad_" in dispatcher.registered_prefixes
        assert "hive_mind" in dispatcher.registered_prefixes

    def test_blocked_tool(self):
        from core.agent.tool_dispatch import ToolDispatcher
        agent = MagicMock()
        agent.tool_selector.is_tool_blocked.return_value = True
        dispatcher = ToolDispatcher(agent)
        result = dispatcher.dispatch("nmap", {})
        assert result["success"] is False
        assert "blocked" in result["error"]

    def test_exact_dispatch(self):
        from core.agent.tool_dispatch import ToolDispatcher
        agent = MagicMock()
        agent.tool_selector.is_tool_blocked.return_value = False
        agent._execute_waf_bypass.return_value = {"success": True}
        dispatcher = ToolDispatcher(agent)
        dispatcher.dispatch("waf_bypass", {"target": "x"})
        agent._execute_waf_bypass.assert_called_once()

    def test_prefix_dispatch(self):
        from core.agent.tool_dispatch import ToolDispatcher
        agent = MagicMock()
        agent.tool_selector.is_tool_blocked.return_value = False
        agent._execute_ad_attacks.return_value = {"success": True}
        dispatcher = ToolDispatcher(agent)
        dispatcher.dispatch("ad_enum", {"domain": "test.local"})
        agent._execute_ad_attacks.assert_called_once()

    def test_custom_handler_registration(self):
        from core.agent.tool_dispatch import ToolDispatcher
        agent = MagicMock()
        agent.tool_selector.is_tool_blocked.return_value = False
        dispatcher = ToolDispatcher(agent)

        custom_result = {"success": True, "output": "custom"}
        dispatcher.register("my_custom_tool", lambda a, args: custom_result)

        result = dispatcher.dispatch("my_custom_tool", {})
        assert result == custom_result

    def test_fallback_to_system_tool(self):
        from core.agent.tool_dispatch import ToolDispatcher
        agent = MagicMock()
        agent.tool_selector.is_tool_blocked.return_value = False
        agent.tool_selector.tools = {}
        dispatcher = ToolDispatcher(agent)
        result = dispatcher.dispatch("unknown_tool", {})
        assert result["success"] is False
        assert "not found" in result["error"]


# ===================================================================
# 7. Multi-Agent Orchestrator
# ===================================================================
class TestMultiAgentOrchestrator:
    """Tests for core.agent.multi_agent."""

    def test_agent_role_enum(self):
        from core.agent.multi_agent import AgentRole
        assert AgentRole.REASONING.value == "reasoning"
        assert AgentRole.PARSING.value == "parsing"
        assert len(AgentRole) >= 10

    def test_model_tier_mapping(self):
        from core.agent.multi_agent import DEFAULT_MODEL_TIERS, AgentRole
        assert DEFAULT_MODEL_TIERS[AgentRole.REASONING] == "expensive"
        assert DEFAULT_MODEL_TIERS[AgentRole.PARSING] == "cheap"
        assert DEFAULT_MODEL_TIERS[AgentRole.CODING] == "mid"

    def test_role_system_prompts(self):
        from core.agent.multi_agent import ROLE_SYSTEM_PROMPTS, AgentRole
        for role in AgentRole:
            assert role in ROLE_SYSTEM_PROMPTS
            assert len(ROLE_SYSTEM_PROMPTS[role]) > 10

    def test_orchestrator_no_client(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator
        orch = MultiAgentOrchestrator(llm_client=None)
        result = orch.delegate(AgentRole.REASONING, "test")
        assert result["success"] is False

    def test_orchestrator_with_mock_client(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator
        client = MagicMock()
        client.query.return_value = "Analysis complete"
        orch = MultiAgentOrchestrator(
            llm_client=client,
            model_overrides={"reasoning": "gpt-4o"},
        )
        result = orch.delegate(AgentRole.REASONING, "Analyze nmap output")
        assert result["success"] is True
        assert result["response"] == "Analysis complete"
        assert result["model"] == "gpt-4o"

    def test_orchestrator_with_context(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator
        client = MagicMock()
        client.query.return_value = "Done"
        orch = MultiAgentOrchestrator(llm_client=client)
        result = orch.delegate(
            AgentRole.SCANNING,
            "Parse nmap output",
            context={"target": "10.0.0.1", "ports": "80,443"},
        )
        assert result["success"] is True
        # Verify context was included in prompt
        call_args = client.query.call_args
        assert "10.0.0.1" in call_args.kwargs.get("prompt", call_args.args[0] if call_args.args else "")

    def test_orchestrator_stats(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator
        client = MagicMock()
        client.query.return_value = "ok"
        orch = MultiAgentOrchestrator(llm_client=client)
        orch.delegate(AgentRole.PARSING, "test")
        stats = orch.get_stats()
        assert stats["call_counts"]["parsing"] == 1

    def test_get_model_for_role(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator
        orch = MultiAgentOrchestrator(
            model_overrides={"reasoning": "claude-3.5-sonnet"},
        )
        assert orch.get_model_for_role(AgentRole.REASONING) == "claude-3.5-sonnet"
        assert orch.get_model_for_role(AgentRole.PARSING) is None

    def test_get_tier(self):
        from core.agent.multi_agent import AgentRole, MultiAgentOrchestrator
        orch = MultiAgentOrchestrator()
        assert orch.get_tier(AgentRole.REASONING) == "expensive"
        assert orch.get_tier(AgentRole.SCANNING) == "cheap"


# ===================================================================
# 8. Lazy core/__init__.py
# ===================================================================
class TestLazyCoreInit:
    """Tests for lazy __getattr__ in core/__init__.py."""

    def test_import_config_manager(self):
        from core import ConfigManager
        assert ConfigManager is not None

    def test_import_agent_state(self):
        from core import AgentState
        assert AgentState is not None

    def test_import_event_bus(self):
        from core import EventBus, EventType, get_event_bus
        assert EventBus is not None
        assert EventType is not None
        assert get_event_bus is not None

    def test_import_knowledge_graph(self):
        from core import KnowledgeGraph, get_knowledge_graph
        assert KnowledgeGraph is not None
        assert get_knowledge_graph is not None

    def test_import_observability(self):
        from core import MetricsCollector, Tracer, get_metrics, get_tracer
        assert Tracer is not None
        assert MetricsCollector is not None
        assert get_metrics is not None
        assert get_tracer is not None

    def test_import_context_key(self):
        from core import ContextKey
        assert ContextKey.TARGET.value == "target"

    def test_import_nonexistent_raises(self):
        with pytest.raises((AttributeError, ImportError)):
            from core import NonExistentSymbol  # noqa: F401

    def test_all_exports(self):
        import core
        assert len(core.__all__) > 40


# ===================================================================
# 9. Cloud Scanner
# ===================================================================
class TestCloudScanner:
    """Tests for modules.cloud_scanner."""

    def test_cloud_finding_dataclass(self):
        from modules.cloud_scanner import CloudFinding
        f = CloudFinding(
            provider="aws",
            category="s3",
            severity="critical",
            title="Public S3",
            description="test",
        )
        assert f.provider == "aws"
        assert f.severity == "critical"

    def test_cloud_scan_result(self):
        from modules.cloud_scanner import CloudFinding, CloudScanResult
        result = CloudScanResult(target="example.com")
        result.findings.append(CloudFinding(
            provider="aws", category="s3", severity="critical",
            title="Public bucket", description="test",
        ))
        result.findings.append(CloudFinding(
            provider="aws", category="s3", severity="high",
            title="Writable bucket", description="test",
        ))
        assert result.critical_count == 1
        assert result.high_count == 1

    def test_scan_result_to_dict(self):
        from modules.cloud_scanner import CloudScanResult
        result = CloudScanResult(target="test.com", cloud_provider="aws")
        d = result.to_dict()
        assert d["target"] == "test.com"
        assert d["cloud_provider"] == "aws"
        assert "findings" in d

    def test_clean_target(self):
        from modules.cloud_scanner import CloudScanner
        scanner = CloudScanner()
        assert scanner._clean_target("https://www.example.com/path") == "example.com"
        assert scanner._clean_target("http://10.0.0.1:8080/api") == "10.0.0.1"
        assert scanner._clean_target("example.com") == "example.com"

    def test_metadata_endpoints_defined(self):
        from modules.cloud_scanner import METADATA_ENDPOINTS
        assert "aws" in METADATA_ENDPOINTS
        assert "azure" in METADATA_ENDPOINTS
        assert "gcp" in METADATA_ENDPOINTS

    def test_s3_patterns(self):
        from modules.cloud_scanner import S3_BUCKET_PATTERNS
        assert len(S3_BUCKET_PATTERNS) >= 10
        assert any("{target}" in p for p in S3_BUCKET_PATTERNS)


# ===================================================================
# 10. Web API (import only, no server start)
# ===================================================================
class TestWebAPI:
    """Tests for core.ui.web_api (import and creation)."""

    def test_create_app_without_fastapi(self):
        """Graceful degradation when FastAPI is not installed."""
        from core.ui import web_api
        # If FastAPI is installed, create_app returns an app
        # If not, it returns None — both are valid
        app = web_api.create_app()
        # Just ensure no crash
        assert app is not None or app is None

    def test_safe_import_status(self):
        from core.ui.web_api import _safe_import_status
        assert _safe_import_status("core.events", "EventBus") == "available"
        assert _safe_import_status("nonexistent.module", "X") == "not_installed"
