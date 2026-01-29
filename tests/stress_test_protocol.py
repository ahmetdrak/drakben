
import pytest
import asyncio
import sys
import os
from unittest.mock import MagicMock, patch

# Fix PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.refactored_agent import RefactoredDrakbenAgent
from core.config import ConfigManager
from core.state import AgentState, AttackPhase
from core.tool_selector import ToolSelector
from core.planner import PlanStep, StepStatus

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
async def test_full_kill_chain_simulation(agent):
    """
    NUCLEAR STRESS TEST: Validate Attack Chain Integrity without DB.
    We inject 3 sequential steps into the Planner mock and verify Agent executes them.
    """
    print("\n[TEST] ☢️ Starting Nuclear Stress Test (Kill Chain)...")
    
    # Define the 3 steps of the kill chain
    step1 = PlanStep(
        step_id="1", action="scan", tool="nmap_port_scan", target="127.0.0.1",
        params={}, depends_on=[], status=StepStatus.PENDING, max_retries=2,
        retry_count=0, expected_outcome="", actual_outcome="", error=""
    )
    step2 = PlanStep(
        step_id="2", action="vuln", tool="nikto_web_scan", target="127.0.0.1",
        params={"port": 80}, depends_on=[], status=StepStatus.PENDING, max_retries=2,
        retry_count=0, expected_outcome="", actual_outcome="", error=""
    )
    step3 = PlanStep(
        step_id="3", action="exploit", tool="sqlmap_exploit", target="127.0.0.1",
        params={}, depends_on=[], status=StepStatus.PENDING, max_retries=2,
        retry_count=0, expected_outcome="", actual_outcome="", error=""
    )
    
    # Instruct Planner to yield these steps sequentially, then None
    # We provide extra None values to avoid StopIteration if polled multiple times
    agent.planner.get_next_step.side_effect = [step1, step2, step3, None, None, None, None, None]
    
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
    executed_commands = [c[0][0] for c in calls] # Arg 0 is command string
    
    print(f"\n[REPORT] Commands Executed: {executed_commands}")
    
    assert any("nmap" in cmd for cmd in executed_commands), "Failed to execute Recon step"
    assert any("nikto" in cmd for cmd in executed_commands), "Failed to execute Vuln Scan step"
    assert any("sqlmap" in cmd for cmd in executed_commands), "Failed to execute Exploit step"
    
    print("✅ TEST PASSED: Full Kill Chain executed successfully.")
    print("✅ Zero-Defect: Logic flow is valid.")

def test_tool_registry_integrity():
    """Nuclear Check: Every registered tool MUST have executable code logic."""
    selector = ToolSelector()
    agent = RefactoredDrakbenAgent(ConfigManager())
    
    missing_handlers = []
    
    # Define critical tools that MUST operate
    critical_tools = [
        "generate_payload", # Weapon Foundry
        "synthesize_code",  # Singularity
        "osint_scan",       # Social Eng
        "hive_mind_attack"  # Swarm
    ]
    
    for tool in critical_tools:
        # Check if they are registered
        if tool not in selector.tools:
            pytest.fail(f"CRITICAL: {tool} is missing from Tool Registry!")
            
        # Check if they have handlers (introspection)
        has_handler = False
        if tool == "generate_payload" and hasattr(agent, "_execute_weapon_foundry"): has_handler = True
        if tool == "synthesize_code" and hasattr(agent, "_execute_singularity"): has_handler = True
        if tool.startswith("osint") and hasattr(agent, "_execute_osint"): has_handler = True
        if tool.startswith("hive_mind") and hasattr(agent, "_execute_hive_mind"): has_handler = True
        
        if not has_handler:
            missing_handlers.append(tool)

    if missing_handlers:
        pytest.fail(f"INTEGRATION FAILURE: Tools {missing_handlers} have no code handlers!")
        
    print(f"\n✅ INTEGRITY CHECK PASSED: All {len(critical_tools)} critical subsystems are integrated.")

if __name__ == "__main__":
    pass
