"""Deep coverage tests for core/agent/brain.py.

Covers: get_model_timeout, MasterOrchestrator, ContinuousReasoning,
        ContextManager, SelfCorrection, DecisionEngine.
"""

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.agent.brain import (
    MODEL_TIMEOUTS,
    ContextManager,
    ContinuousReasoning,
    MasterOrchestrator,
    SelfCorrection,
    get_model_timeout,
)


# ---------------------------------------------------------------------------
# 1. get_model_timeout
# ---------------------------------------------------------------------------
class TestGetModelTimeout:
    """Tests for model-based timeout lookup."""

    def test_exact_model_names_without_prefix_conflict(self):
        """Models whose key is not a prefix of an earlier key."""
        safe = {"gpt-4", "claude-3", "llama-3.1-70b", "llama-3.1-8b", "mistral"}
        for model, expected in MODEL_TIMEOUTS.items():
            if model == "default" or model not in safe:
                continue
            assert get_model_timeout(model) == expected

    def test_prefix_match_wins(self):
        """First-match-wins: shorter prefix returns its own timeout."""
        # "gpt-4" matches before "gpt-4-turbo" in dict iteration
        assert get_model_timeout("gpt-4-turbo") == MODEL_TIMEOUTS["gpt-4"]
        assert get_model_timeout("claude-3-opus") == MODEL_TIMEOUTS["claude-3"]

    def test_case_insensitive_lookup(self):
        assert get_model_timeout("GPT-4") == MODEL_TIMEOUTS["gpt-4"]
        assert get_model_timeout("MISTRAL") == MODEL_TIMEOUTS["mistral"]

    def test_partial_match(self):
        # "gpt-4" key also matches inside longer strings
        assert get_model_timeout("openrouter/gpt-4-turbo-preview") == MODEL_TIMEOUTS["gpt-4"]

    def test_unknown_model_returns_default(self):
        assert get_model_timeout("unknown-model-xyz") == MODEL_TIMEOUTS["default"]

    def test_empty_string_returns_default(self):
        assert get_model_timeout("") == MODEL_TIMEOUTS["default"]

    def test_model_with_version_suffix(self):
        assert get_model_timeout("mistral-7b-instruct") == MODEL_TIMEOUTS["mistral"]

    def test_llama_models(self):
        assert get_model_timeout("meta-llama/llama-3.1-70b-instruct:free") == MODEL_TIMEOUTS["llama-3.1-70b"]
        assert get_model_timeout("llama-3.1-8b-instruct") == MODEL_TIMEOUTS["llama-3.1-8b"]


# ---------------------------------------------------------------------------
# Helpers — fake ExecutionContext
# ---------------------------------------------------------------------------
def _make_context(target=None, language="en", is_root=False, phase="recon"):
    ctx = SimpleNamespace(
        target=target,
        language=language,
        system_info={"is_root": is_root, "phase": phase},
    )
    return ctx


# ---------------------------------------------------------------------------
# 2. ContinuousReasoning — Intent Detection
# ---------------------------------------------------------------------------
class TestContinuousReasoningIntentDetection:
    """Tests for _detect_intent, _is_chat_request, rule-based analysis."""

    @pytest.fixture()
    def reasoning(self):
        with patch("core.agent.brain.AICoder"):
            r = ContinuousReasoning.__new__(ContinuousReasoning)
            r.llm_client = None
            r.reasoning_history = []
            r._lock = threading.Lock()
            r._system_context = {"os": "Linux", "is_kali": True, "tools": []}
            r.system_context = r._system_context
            r._ai_coder = None
            r._first_error_shown = False
            return r

    # --- _detect_intent ---
    def test_detect_scan_intent(self, reasoning):
        assert reasoning._detect_intent("scan the target") == "scan"
        assert reasoning._detect_intent("port taraması yap") == "scan"

    def test_detect_vuln_intent(self, reasoning):
        assert reasoning._detect_intent("find vulnerability") == "find_vulnerability"
        assert reasoning._detect_intent("zafiyet ara") == "find_vulnerability"

    def test_detect_exploit_intent(self, reasoning):
        assert reasoning._detect_intent("exploit the server") == "exploit"
        assert reasoning._detect_intent("istismar et") == "exploit"

    def test_detect_shell_intent(self, reasoning):
        assert reasoning._detect_intent("get reverse shell") == "get_shell"

    def test_detect_payload_intent(self, reasoning):
        assert reasoning._detect_intent("generate payload") == "generate_payload"

    def test_detect_chat_intent_questions(self, reasoning):
        assert reasoning._detect_intent("merhaba nasılsın") == "chat"
        assert reasoning._detect_intent("hello hi there") == "chat"
        assert reasoning._detect_intent("bu mümkün mü") == "chat"
        assert reasoning._detect_intent("what if we tried something") == "chat"

    def test_detect_chat_fallback(self, reasoning):
        assert reasoning._detect_intent("just chatting") == "chat"

    def test_detect_intent_dict_input(self, reasoning):
        result = reasoning._detect_intent({"command": "scan network"})
        assert result == "scan"

    def test_detect_intent_dict_without_command(self, reasoning):
        result = reasoning._detect_intent({"foo": "bar"})
        assert result == "chat"

    def test_detect_intent_int_input(self, reasoning):
        result = reasoning._detect_intent(42)
        assert result == "chat"

    def test_question_with_explicit_action_is_not_chat(self, reasoning):
        # "nasıl" would normally be chat, but "scan" overrides
        result = reasoning._detect_intent("nasıl scan yaparım, başla")
        assert result == "scan"

    # --- _assess_risks ---
    def test_assess_risks_exploit_intent(self, reasoning):
        ctx = _make_context()
        risks = reasoning._assess_risks("exploit", ctx)
        assert "Potentially destructive operation" in risks
        assert "Requires authorization" in risks

    def test_assess_risks_scan_not_root(self, reasoning):
        ctx = _make_context(is_root=False)
        risks = reasoning._assess_risks("scan", ctx)
        assert "May need elevated privileges" in risks

    def test_assess_risks_scan_root(self, reasoning):
        ctx = _make_context(is_root=True)
        risks = reasoning._assess_risks("scan", ctx)
        assert "May need elevated privileges" not in risks

    def test_assess_risks_chat_no_risks(self, reasoning):
        ctx = _make_context()
        risks = reasoning._assess_risks("chat", ctx)
        assert risks == []

    # --- _plan_steps ---
    def test_plan_steps_scan(self, reasoning):
        ctx = _make_context(target="10.0.0.1")
        steps = reasoning._plan_steps("scan", ctx)
        assert len(steps) == 4
        assert steps[0]["action"] == "check_tools"

    def test_plan_steps_find_vulnerability(self, reasoning):
        ctx = _make_context(target="10.0.0.1")
        steps = reasoning._plan_steps("find_vulnerability", ctx)
        assert any(s["action"] == "vuln_scan" for s in steps)

    def test_plan_steps_get_shell(self, reasoning):
        ctx = _make_context(target="10.0.0.1")
        steps = reasoning._plan_steps("get_shell", ctx)
        assert any(s["action"] == "verify_shell" for s in steps)

    def test_plan_steps_no_target(self, reasoning):
        ctx = _make_context(target=None)
        steps = reasoning._plan_steps("scan", ctx)
        assert steps == []

    def test_plan_steps_chat(self, reasoning):
        ctx = _make_context(target="10.0.0.1")
        steps = reasoning._plan_steps("chat", ctx)
        assert steps == []

    def test_plan_steps_generate_payload(self, reasoning):
        ctx = _make_context(target="10.0.0.1")
        steps = reasoning._plan_steps("generate_payload", ctx)
        assert any(s["action"] == "generate_payloads" for s in steps)

    # --- _generate_reasoning ---
    def test_reasoning_scan_tr(self, reasoning):
        steps = [1, 2, 3, 4]
        r = reasoning._generate_reasoning("scan", steps, [], "tr")
        assert "taraması" in r
        assert "4 adım" in r

    def test_reasoning_scan_en(self, reasoning):
        steps = [1, 2, 3, 4]
        r = reasoning._generate_reasoning("scan", steps, [], "en")
        assert "Port scan" in r

    def test_reasoning_vulnerability_tr(self, reasoning):
        r = reasoning._generate_reasoning("find_vulnerability", [], [], "tr")
        assert "Zafiyet" in r

    def test_reasoning_get_shell_with_risks(self, reasoning):
        steps = [1, 2, 3]
        r = reasoning._generate_reasoning("get_shell", steps, ["risk1"], "en")
        assert "Risky operation!" in r

    def test_reasoning_get_shell_no_risks_tr(self, reasoning):
        steps = [1, 2, 3]
        r = reasoning._generate_reasoning("get_shell", steps, [], "tr")
        assert "Shell erişimi" in r

    def test_reasoning_chat(self, reasoning):
        r = reasoning._generate_reasoning("chat", [], [], "en")
        assert "Chat mode" in r

    def test_reasoning_chat_tr(self, reasoning):
        r = reasoning._generate_reasoning("chat", [], [], "tr")
        assert "sohbet" in r

    # --- _analyze_rule_based ---
    def test_analyze_rule_based_scan(self, reasoning):
        ctx = _make_context(target="10.0.0.1", language="en")
        result = reasoning._analyze_rule_based("scan ports", ctx)
        assert result["intent"] == "scan"
        assert result["success"] is True
        assert result["confidence"] == pytest.approx(0.85)
        assert len(result["steps"]) > 0

    def test_analyze_rule_based_chat(self, reasoning):
        ctx = _make_context(target="10.0.0.1", language="en")
        result = reasoning._analyze_rule_based("hello world", ctx)
        assert result["intent"] == "chat"

    # --- _add_to_history ---
    def test_add_to_history_thread_safe(self, reasoning):
        for i in range(5):
            reasoning._add_to_history({"test": i})
        assert len(reasoning.reasoning_history) == 5

    # --- re_evaluate ---
    def test_re_evaluate_continue(self, reasoning):
        ctx = _make_context()
        result = reasoning.re_evaluate({"success": True}, ctx)
        assert result["action"] == "continue"

    def test_re_evaluate_adjust_plan(self, reasoning):
        ctx = _make_context()
        result = reasoning.re_evaluate({"success": False, "error": "timeout"}, ctx)
        assert result["action"] == "adjust_plan"

    # --- _generate_recovery_steps ---
    def test_recovery_command_not_found(self, reasoning):
        steps = reasoning._generate_recovery_steps({"error": "command not found", "tool": "nmap"})
        assert steps[0]["action"] == "install_tool"

    def test_recovery_permission_denied(self, reasoning):
        steps = reasoning._generate_recovery_steps({"error": "Permission denied"})
        assert steps[0]["action"] == "escalate_privileges"

    def test_recovery_generic(self, reasoning):
        steps = reasoning._generate_recovery_steps({"error": "some other error"})
        # First step logs the unknown error, second tries alternative
        assert steps[0]["action"] == "log_unknown_error"
        assert steps[1]["action"] == "try_alternative_method"


# ---------------------------------------------------------------------------
# 3. ContextManager
# ---------------------------------------------------------------------------
class TestContextManager:
    def test_update_and_get(self):
        cm = ContextManager()
        cm.update({"target": "10.0.0.1"})
        assert cm.get("target") == "10.0.0.1"

    def test_get_default(self):
        cm = ContextManager()
        assert cm.get("nonexistent", "default_val") == "default_val"

    def test_get_full_context_initial(self):
        cm = ContextManager()
        full = cm.get_full_context()
        assert full["changes"] == ["Initial context"]
        assert full["previous"] == {}

    def test_detect_changes_added(self):
        cm = ContextManager()
        cm.update({"a": 1})
        cm.update({"b": 2})
        full = cm.get_full_context()
        changes = full["changes"]
        assert any("Added: b" in c for c in changes)

    def test_detect_changes_changed(self):
        cm = ContextManager()
        cm.update({"a": 1})
        cm.update({"a": 2})
        full = cm.get_full_context()
        changes = full["changes"]
        assert any("Changed: a" in c for c in changes)

    def test_clear_history(self):
        cm = ContextManager()
        cm.update({"a": 1})
        cm.update({"b": 2})
        assert len(cm.context_history) == 2
        cm.clear_history()
        assert len(cm.context_history) == 0

    def test_multiple_updates_preserve_history(self):
        cm = ContextManager()
        cm.update({"a": 1})
        cm.update({"a": 2})
        cm.update({"a": 3})
        assert len(cm.context_history) == 3


# ---------------------------------------------------------------------------
# 4. SelfCorrection
# ---------------------------------------------------------------------------
class TestSelfCorrection:
    def test_review_safe_decision(self):
        sc = SelfCorrection()
        # Use a command that doesn't trigger cache optimization hint
        decision = {"action": "scan", "command": "ping 10.0.0.1", "steps": [1]}
        result = sc.review(decision)
        assert "corrected" not in result or result.get("corrected") is False or result == decision

    def test_review_dangerous_command(self):
        sc = SelfCorrection()
        decision = {"action": "exploit", "command": "rm -rf /important"}
        result = sc.review(decision)
        assert result.get("needs_approval") is True
        assert "safety_warning" in result

    def test_review_fork_bomb(self):
        sc = SelfCorrection()
        decision = {"command": ":(){ :|:& };:"}
        result = sc.review(decision)
        assert result.get("needs_approval") is True

    def test_review_dd_command(self):
        sc = SelfCorrection()
        decision = {"command": "dd if=/dev/zero of=/dev/sda"}
        result = sc.review(decision)
        assert result.get("needs_approval") is True

    def test_review_missing_prerequisites(self):
        sc = SelfCorrection()
        decision = {
            "command": "scan",
            "required_tools": ["nmap", "nikto"],
            "tools_available": {"nmap": True, "nikto": False},
        }
        result = sc.review(decision)
        assert "nikto" in result.get("prerequisites", [])

    def test_review_optimization_suggestion(self):
        sc = SelfCorrection()
        decision = {"command": "scan", "steps": [1, 2, 3, 4, 5]}
        result = sc.review(decision)
        assert any("parallel" in o.lower() for o in result.get("optimizations", []))

    def test_review_no_command_not_dangerous(self):
        sc = SelfCorrection()
        decision = {"action": "chat"}
        result = sc.review(decision)
        assert result.get("needs_approval") is not True

    def test_review_empty_command_not_dangerous(self):
        sc = SelfCorrection()
        decision = {"command": ""}
        result = sc.review(decision)
        assert result.get("needs_approval") is not True

    def test_correction_history_tracked(self):
        sc = SelfCorrection()
        sc.review({"command": "rm -rf /data"})
        stats = sc.get_correction_stats()
        assert stats["total_corrections"] >= 1

    def test_correction_stats_empty(self):
        sc = SelfCorrection()
        stats = sc.get_correction_stats()
        assert stats["total_corrections"] == 0

    def test_review_chmod_777(self):
        sc = SelfCorrection()
        decision = {"command": "chmod 777 /sensitive"}
        result = sc.review(decision)
        assert result.get("needs_approval") is True


# ---------------------------------------------------------------------------
# 5. MasterOrchestrator (mocked modules)
# ---------------------------------------------------------------------------
class TestMasterOrchestrator:
    @pytest.fixture()
    def orchestrator(self):
        from core.agent.brain import ExecutionContext
        with patch("core.agent.brain.AICoder"):
            orch = MasterOrchestrator.__new__(MasterOrchestrator)
            orch.reasoning_engine = MagicMock()
            orch.decision_engine = MagicMock()
            orch.context_manager = MagicMock()
            orch.context_manager.current_context = {}
            orch.self_correction = MagicMock()
            orch.context = ExecutionContext()
            return orch

    def test_validate_modules_all_present(self, orchestrator):
        result = orchestrator._validate_modules()
        assert result is None

    def test_validate_modules_missing_reasoning(self, orchestrator):
        orchestrator.reasoning_engine = None
        result = orchestrator._validate_modules()
        assert result is not None
        assert result["action"] == "error"

    def test_check_infinite_loop_no_history(self, orchestrator):
        decision = {"action": "scan"}
        assert orchestrator._check_infinite_loop(decision) is None

    def test_check_infinite_loop_diverse_actions(self, orchestrator):
        orchestrator.context.history = [
            {"action": {"type": "scan"}}, {"action": {"type": "exploit"}}, {"action": {"type": "report"}}
        ]
        decision = {"action": "recon"}
        assert orchestrator._check_infinite_loop(decision) is None

    def test_check_infinite_loop_repeated_actions(self, orchestrator):
        orchestrator.context.history = [
            {"action": {"type": "scan"}}, {"action": {"type": "scan"}}, {"action": {"type": "scan"}}
        ]
        decision = {"action": "scan"}
        result = orchestrator._check_infinite_loop(decision)
        assert result is not None
        assert result["action"] == "error"

    def test_update_context(self, orchestrator):
        orchestrator._update_context({"target": "10.0.0.1"})
        orchestrator.context_manager.update.assert_called_once()

    def test_make_error_response(self, orchestrator):
        result = orchestrator._make_error_response("test error")
        assert result["action"] == "error"
        assert "test error" in result["error"]


# ---------------------------------------------------------------------------
# 6. ContinuousReasoning — _construct_system_prompt
# ---------------------------------------------------------------------------
class TestConstructSystemPrompt:
    @pytest.fixture()
    def reasoning(self):
        with patch("core.agent.brain.AICoder"):
            r = ContinuousReasoning.__new__(ContinuousReasoning)
            r.llm_client = None
            r.reasoning_history = []
            r._lock = threading.Lock()
            r._system_context = {"os": "Linux", "is_kali": True, "tools": ["nmap"]}
            r.system_context = r._system_context
            r._ai_coder = None
            r._first_error_shown = False
            # Set the compact system prompt template
            r.COMPACT_SYSTEM_PROMPT = (
                "Target: {target}\nPhase: {phase}\nOS: {os_name}\n"
                "Kali: {is_kali}\nLang: {lang}"
            )
            return r

    def test_prompt_with_target_en(self, reasoning):
        ctx = _make_context(target="10.0.0.1", language="en")
        prompt = reasoning._construct_system_prompt("en", ctx)
        assert "10.0.0.1" in prompt
        assert "English" in prompt

    def test_prompt_with_target_tr(self, reasoning):
        ctx = _make_context(target="example.com", language="tr")
        prompt = reasoning._construct_system_prompt("tr", ctx)
        assert "example.com" in prompt
        assert "Turkish" in prompt

    def test_prompt_no_target(self, reasoning):
        ctx = SimpleNamespace(system_info={"phase": "recon"})
        prompt = reasoning._construct_system_prompt("en", ctx)
        assert "Not set" in prompt

    def test_prompt_kali_detection(self, reasoning):
        reasoning._system_context = {"os": "Linux", "is_kali": True, "tools": []}
        ctx = _make_context(target="10.0.0.1")
        prompt = reasoning._construct_system_prompt("en", ctx)
        assert "Yes" in prompt

    def test_prompt_non_kali(self, reasoning):
        reasoning._system_context = {"os": "Windows", "is_kali": False, "tools": []}
        ctx = _make_context(target="10.0.0.1")
        prompt = reasoning._construct_system_prompt("en", ctx)
        assert "No" in prompt


# ---------------------------------------------------------------------------
# 7. ContinuousReasoning — _parse_llm_response
# ---------------------------------------------------------------------------
class TestParseLLMResponse:
    @pytest.fixture()
    def reasoning(self):
        with patch("core.agent.brain.AICoder"):
            r = ContinuousReasoning.__new__(ContinuousReasoning)
            r.llm_client = None
            r.reasoning_history = []
            r._history_lock = threading.Lock()
            r.system_context = {}
            r._ai_coder = None
            return r

    def test_parse_json_code_block(self, reasoning):
        response = '```json\n{"intent": "scan", "confidence": 0.9}\n```'
        result = reasoning._parse_llm_response(response)
        assert result is not None
        assert result["intent"] == "scan"

    def test_parse_raw_json(self, reasoning):
        response = '{"intent": "exploit", "confidence": 0.8}'
        result = reasoning._parse_llm_response(response)
        assert result is not None
        assert result["intent"] == "exploit"

    def test_parse_invalid_json(self, reasoning):
        response = "This is not JSON at all"
        result = reasoning._parse_llm_response(response)
        # Should return None or a fallback dict
        assert result is None or isinstance(result, dict)

    def test_parse_empty_response(self, reasoning):
        result = reasoning._parse_llm_response("")
        assert result is None or isinstance(result, dict)

    def test_parse_nested_json_block(self, reasoning):
        response = 'Some text\n```json\n{"steps": [{"action": "scan"}]}\n```\nMore text'
        result = reasoning._parse_llm_response(response)
        assert result is not None
        assert "steps" in result
