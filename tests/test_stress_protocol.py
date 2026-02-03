import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Fix PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent.planner import PlanStep, StepStatus
from core.agent.refactored_agent import RefactoredDrakbenAgent
from core.agent.state import AgentState, AttackPhase
from core.config import ConfigManager
from core.execution.tool_selector import ToolSelector

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
    mock_result.duration = 0.5
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


def test_full_kill_chain_simulation(agent) -> None:
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

    # Mock _execute_tool_with_progress to avoid threading/timeout issues
    executed_tools = []

    def mock_execute(tool_name: str, args: dict) -> dict:
        executed_tools.append(tool_name)
        return {
            "success": True,
            "output": f"Mock executed {tool_name}",
            "args": args,
        }

    # Instruct Planner to yield these steps sequentially, then None
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

    with patch.object(agent, "_execute_tool_with_progress", side_effect=mock_execute):
        # RUN ITERATION 1 (Recon)
        agent.state.phase = AttackPhase.RECON
        agent._run_single_iteration(15)

        # RUN ITERATION 2 (Vuln)
        agent.state.phase = AttackPhase.VULN_SCAN
        agent._run_single_iteration(15)

        # RUN ITERATION 3 (Exploit)
        agent.state.phase = AttackPhase.EXPLOIT
        agent._run_single_iteration(15)

    # VERIFICATION - Check that mock was called with correct tools
    assert "nmap_port_scan" in executed_tools, "Failed to execute Recon step"
    assert "nikto_web_scan" in executed_tools, "Failed to execute Vuln Scan step"
    assert "sqlmap_exploit" in executed_tools, "Failed to execute Exploit step"


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
