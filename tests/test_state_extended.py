# tests/test_state_extended.py
"""Extended tests for core/agent/state.py — agentic protections & helpers."""



from core.agent.state import (
    AgentState,
    AttackPhase,
    ServiceInfo,
)


def _fresh_state(target: str | None = None) -> AgentState:
    """Get a fresh state (clear singleton)."""
    import core.agent.state as _mod

    with _mod._state_lock:
        _mod._state_instance = None
        # Force reinit
        state = AgentState.__new__(AgentState)
        _mod._state_instance = state
    state._initialized = False
    state.__init__(target)
    return state


# ── record_tool_call & consecutive detection ─────────────────

class TestRecordToolCall:
    def test_basic_record(self) -> None:
        s = _fresh_state()
        s.record_tool_call("nmap")
        assert s.tool_call_history == ["nmap"]

    def test_consecutive_same_tool(self) -> None:
        s = _fresh_state()
        s.record_tool_call("nmap")
        s.record_tool_call("nmap")
        assert s.consecutive_same_tool == 1

    def test_different_tool_resets_counter(self) -> None:
        s = _fresh_state()
        s.record_tool_call("nmap")
        s.record_tool_call("nmap")
        s.record_tool_call("sqlmap")
        assert s.consecutive_same_tool == 0

    def test_history_cap(self) -> None:
        s = _fresh_state()
        for i in range(20):
            s.record_tool_call(f"tool_{i}")
        assert len(s.tool_call_history) <= 10


# ── compute_state_hash ───────────────────────────────────────

class TestComputeStateHash:
    def test_produces_string(self) -> None:
        s = _fresh_state()
        h = s.compute_state_hash()
        assert isinstance(h, str) and len(h) == 8

    def test_deterministic(self) -> None:
        s = _fresh_state()
        assert s.compute_state_hash() == s.compute_state_hash()

    def test_changes_on_mutation(self) -> None:
        s = _fresh_state()
        h1 = s.compute_state_hash()
        s.phase = AttackPhase.RECON
        h2 = s.compute_state_hash()
        assert h1 != h2


# ── check_state_changed ─────────────────────────────────────

class TestCheckStateChanged:
    def test_first_call_always_true(self) -> None:
        s = _fresh_state()
        assert s.check_state_changed() is True

    def test_second_call_no_change(self) -> None:
        s = _fresh_state()
        s.check_state_changed()
        assert s.check_state_changed() is False

    def test_mutation_detected(self) -> None:
        s = _fresh_state()
        s.check_state_changed()
        s.phase = AttackPhase.EXPLOIT
        assert s.check_state_changed() is True


# ── check_hallucination ─────────────────────────────────────

class TestCheckHallucination:
    def test_exit_code_nonzero_claimed_success(self) -> None:
        s = _fresh_state()
        assert s.check_hallucination("nmap", 1, "", True) is True
        assert len(s.hallucination_flags) == 1

    def test_exploit_no_shell(self) -> None:
        s = _fresh_state()
        assert s.check_hallucination("exploit_modules", 0, "scan done", True) is True

    def test_sqli_no_confirmation(self) -> None:
        s = _fresh_state()
        assert s.check_hallucination("sqlmap", 0, "done", True) is True

    def test_no_hallucination(self) -> None:
        s = _fresh_state()
        assert s.check_hallucination("nmap", 0, "scan complete", True) is False

    def test_exit_zero_not_claimed(self) -> None:
        s = _fresh_state()
        assert s.check_hallucination("tool", 1, "", False) is False


# ── is_tool_allowed_for_phase ────────────────────────────────

class TestToolAllowedForPhase:
    def test_recon_in_init(self) -> None:
        s = _fresh_state()
        s.phase = AttackPhase.INIT
        assert s.is_tool_allowed_for_phase("recon") is True

    def test_exploit_in_init(self) -> None:
        s = _fresh_state()
        s.phase = AttackPhase.INIT
        assert s.is_tool_allowed_for_phase("exploit") is False

    def test_exploit_in_vuln_scan(self) -> None:
        s = _fresh_state()
        s.phase = AttackPhase.VULN_SCAN
        assert s.is_tool_allowed_for_phase("exploit") is True

    def test_post_exploit_in_exploit(self) -> None:
        s = _fresh_state()
        s.phase = AttackPhase.EXPLOIT
        assert s.is_tool_allowed_for_phase("post_exploit") is False


# ── should_halt ──────────────────────────────────────────────

class TestShouldHalt:
    def test_no_halt_initially(self) -> None:
        s = _fresh_state()
        halt, _ = s.should_halt()
        assert halt is False

    def test_max_iteration(self) -> None:
        s = _fresh_state()
        s.iteration_count = s.max_iterations
        halt, _ = s.should_halt()
        assert halt is True
        assert "Max iteration" in _

    def test_consecutive_tool_halt(self) -> None:
        s = _fresh_state()
        s.consecutive_same_tool = 5
        halt, _ = s.should_halt()
        assert halt is True
        assert "Same tool" in _

    def test_complete_phase(self) -> None:
        s = _fresh_state()
        s.phase = AttackPhase.COMPLETE
        halt, _ = s.should_halt()
        assert halt is True

    def test_failed_phase(self) -> None:
        s = _fresh_state()
        s.phase = AttackPhase.FAILED
        halt, _ = s.should_halt()
        assert halt is True


# ── clear ────────────────────────────────────────────────────

class TestClear:
    def test_clears_target(self) -> None:
        s = _fresh_state("10.0.0.1")
        s.clear()
        assert s.target is None

    def test_clears_with_new_target(self) -> None:
        s = _fresh_state("10.0.0.1")
        s.clear("10.0.0.2")
        assert s.target == "10.0.0.2"

    def test_resets_phase(self) -> None:
        s = _fresh_state()
        s.phase = AttackPhase.EXPLOIT
        s.clear()
        assert s.phase == AttackPhase.INIT

    def test_clears_collections(self) -> None:
        s = _fresh_state()
        s.tool_call_history.append("nmap")
        s.hallucination_flags.append("x")
        s.tested_attack_surface.add("22:ssh")
        s.clear()
        assert s.tool_call_history == []
        assert s.hallucination_flags == []
        assert len(s.tested_attack_surface) == 0


# ── require_precondition ─────────────────────────────────────

class TestRequirePrecondition:
    def test_has_foothold_false(self) -> None:
        s = _fresh_state()
        assert s.require_precondition("has_foothold") is False

    def test_has_foothold_true(self) -> None:
        s = _fresh_state()
        s.has_foothold = True
        assert s.require_precondition("has_foothold") is True

    def test_has_vulnerability_false(self) -> None:
        s = _fresh_state()
        assert s.require_precondition("has_vulnerability") is False

    def test_has_services_true(self) -> None:
        s = _fresh_state()
        s.open_services[80] = ServiceInfo(80, "tcp", "http")
        assert s.require_precondition("has_services") is True

    def test_port_open(self) -> None:
        s = _fresh_state()
        s.open_services[22] = ServiceInfo(22, "tcp", "ssh")
        assert s.require_precondition("port_22_open") is True
        assert s.require_precondition("port_80_open") is False

    def test_unknown_precondition_allows(self) -> None:
        s = _fresh_state()
        assert s.require_precondition("unknown_xyz") is True


# ── set_observation ──────────────────────────────────────────

class TestSetObservation:
    def test_stores_observation(self) -> None:
        s = _fresh_state()
        s.set_observation("Found 3 open ports")
        assert s.last_observation == "Found 3 open ports"

    def test_truncates_long(self) -> None:
        s = _fresh_state()
        s.set_observation("A" * 10_000)
        assert len(s.last_observation) <= 500


# ── validate ─────────────────────────────────────────────────

class TestValidate:
    def test_valid_initial(self) -> None:
        s = _fresh_state()
        assert s.validate() is True

    def test_post_exploit_without_foothold(self) -> None:
        s = _fresh_state()
        s.post_exploit_completed.add("privesc")
        assert s.validate() is False

    def test_snapshot(self) -> None:
        s = _fresh_state("10.0.0.1")
        snap = s.snapshot()
        assert snap["target"] == "10.0.0.1"
        assert snap["phase"] == "init"
