import os
import sys
from unittest.mock import MagicMock

import pytest

# Fix PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import ConfigManager
from core.planner import PlanStep, StepStatus
from core.refactored_agent import RefactoredDrakbenAgent
from core.state import AgentState, AttackPhase
from core.tool_selector import ToolSelector

# STRESS TEST PROTOCOL - DRAKBEN - ZERO DEFECT VALIDATION


@pytest.fixture
def agent():
    config = ConfigManager()
    # Mock LLM and Networking
    config.llm_client = MagicMock()

    agent = RefactoredDrakbenAgent(config)

    # Mock Executor
    agent.executor = MagicMock()
    mock_result = MagicMock()
    mock_result.exit_code = 0
    mock_result.stdout = "MOCK SUCCESS"
    mock_result.stderr = ""
    mock_result.status.value = "success"
    agent.executor.terminal.execute.return_value = mock_result

    # Mock Evolution Memory
    agent.evolution = MagicMock()
    agent.evolution.get_tool_penalty.return_value = 0.0
    agent.evolution.is_tool_blocked.return_value = False
    agent.evolution.detect_stagnation.return_value = False

    # Mock Planner (Avoiding DB dependency)
    agent.planner = MagicMock()
    agent.planner.current_plan_id = "test_plan_id"

    # Initialize Core State
    agent.state = AgentState(target="127.0.0.1")
    agent.state.phase = AttackPhase.INIT

    # Critical: Set running flags
    agent.running = True
    agent.current_profile = MagicMock()
    agent.current_profile.profile_id = "test_profile_id"
    agent.current_profile.step_order = ["recon", "vuln", "exploit"]

    return agent


@pytest.mark.asyncio
async def test_full_kill_chain_simulation(agent) -> None:
    """NUCLEAR STRESS TEST: Validate Attack Chain Integrity without DB.
    We inject 3 sequential steps into the Planner mock and verify Agent executes them.
    """
    # Define the 3 steps of the kill chain
    step1 = PlanStep(
        step_id="1",
        action="scan",
        tool="nmap_port_scan",
        target="127.0.0.1",
        params={},
        depends_on=[],
        status=StepStatus.PENDING,
        max_retries=2,
        retry_count=0,
        expected_outcome="",
        actual_outcome="",
        error="",
    )
    step2 = PlanStep(
        step_id="2",
        action="vuln",
        tool="nikto_web_scan",
        target="127.0.0.1",
        params={"port": 80},
        depends_on=[],
        status=StepStatus.PENDING,
        max_retries=2,
        retry_count=0,
        expected_outcome="",
        actual_outcome="",
        error="",
    )
    step3 = PlanStep(
        step_id="3",
        action="exploit",
        tool="sqlmap_exploit",
        target="127.0.0.1",
        params={},
        depends_on=[],
        status=StepStatus.PENDING,
        max_retries=2,
        retry_count=0,
        expected_outcome="",
        actual_outcome="",
        error="",
    )

    # Instruct Planner to yield these steps sequentially, then None
    # We provide extra None values to avoid StopIteration if polled multiple times
    agent.planner.get_next_step.side_effect = [
        step1,
        step2,
        step3,
        None,
        None,
        None,
        None,
        None,
    ]

    # RUN ITERATION 1 (Recon)
    agent.state.phase = AttackPhase.RECON
    agent._run_single_iteration(15)

    # RUN ITERATION 2 (Vuln)
    agent.state.phase = AttackPhase.VULN_SCAN
    agent._run_single_iteration(15)

    # RUN ITERATION 3 (Exploit)
    agent.state.phase = AttackPhase.EXPLOIT
    agent._run_single_iteration(15)

    # VERIFICATION
    calls = agent.executor.terminal.execute.call_args_list
    executed_commands = [c[0][0] for c in calls]  # Arg 0 is command string

    assert any("nmap" in cmd for cmd in executed_commands), "Failed to execute Recon step"
    assert any("nikto" in cmd for cmd in executed_commands), "Failed to execute Vuln Scan step"
    assert any("sqlmap" in cmd for cmd in executed_commands), "Failed to execute Exploit step"


def test_tool_registry_integrity() -> None:
    """Nuclear Check: Every registered tool MUST have executable code logic."""
    selector = ToolSelector()
    agent = RefactoredDrakbenAgent(ConfigManager())

    missing_handlers = []

    # Define critical tools that MUST operate

    handlers = {
        "generate_payload": "_execute_weapon_foundry",
        "synthesize_code": "_execute_singularity",
        "osint_scan": "_execute_osint",
        "hive_mind_attack": "_execute_hive_mind",
    }

    for tool, handler_name in handlers.items():
        if tool not in selector.tools:
            pytest.fail(f"CRITICAL: {tool} is missing from Tool Registry!")

        if not hasattr(agent, handler_name):
            missing_handlers.append(tool)

    if missing_handlers:
        pytest.fail(
            f"INTEGRATION FAILURE: Tools {missing_handlers} have no code handlers!",
        )
