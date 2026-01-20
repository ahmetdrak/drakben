import pytest
import asyncio

from core.refactored_agent import RefactoredDrakbenAgent
from core.config import ConfigManager
from core.state import reset_state, AgentState, AttackPhase
from modules import payload as payload_module
from modules import exploit as exploit_module


def test_invariant_kill_crashes_agent():
    cfg = ConfigManager()
    agent = RefactoredDrakbenAgent(cfg)
    agent.initialize(target="127.0.0.1")

    # Force validate() to raise
    def bad_validate():
        raise RuntimeError("forced invariant failure")

    agent.state.validate = bad_validate

    with pytest.raises(RuntimeError):
        agent.run_autonomous_loop()


def test_payload_without_foothold_blocked():
    state = reset_state("127.0.0.1")
    state.has_foothold = False
    state.phase = AttackPhase.EXPLOIT

    # reverse_shell is async
    res = asyncio.run(payload_module.reverse_shell(state, "127.0.0.1", 4444))
    assert isinstance(res, dict)
    assert res.get("blocked") is True


def test_iteration_overflow_halts():
    cfg = ConfigManager()
    agent = RefactoredDrakbenAgent(cfg)
    agent.initialize(target="127.0.0.1")
    # set iteration to max to force halt
    agent.state.iteration_count = agent.state.max_iterations

    # Should exit quickly without raising
    agent.run_autonomous_loop()
    assert agent.state.should_halt()[0] is True


def test_tool_bypass_raises():
    state = reset_state("127.0.0.1")
    # Prepare a state that passes preconditions but where ToolSelector will block the tool
    state.phase = AttackPhase.EXPLOIT
    # Add open service for port 80 so precondition 3 passes
    from core.state import ServiceInfo
    state.open_services[80] = ServiceInfo(port=80, protocol="tcp", service="http")

    # Force ToolSelector to block by setting phase to a mismatched value in selector validation
    # We expect ToolSelector.validate_tool_selection to raise RuntimeError inside run_sqlmap
    with pytest.raises(RuntimeError):
        exploit_module.run_sqlmap(state, "http://127.0.0.1:80")
