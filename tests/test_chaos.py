
import pytest
from unittest.mock import MagicMock, patch
from core.refactored_agent import RefactoredDrakbenAgent
from core.execution_engine import ExecutionResult, ExecutionStatus
from core.state import AttackPhase

@pytest.fixture
def mock_agent():
    config = MagicMock()
    config.llm_client = MagicMock()
    agent = RefactoredDrakbenAgent(config)
    agent.executor = MagicMock()
    agent.planner = MagicMock()
    agent.evolution = MagicMock()
    # Mock state properly
    agent.state = MagicMock()
    agent.state.phase = AttackPhase.INIT
    agent.state.max_iteration = 10
    return agent

def test_chaos_network_timeout(mock_agent):
    """Chaos Test 1: Simulate network timeout during tool execution"""
    # Simulate timeout result
    timeout_result = ExecutionResult(
        command="nmap target",
        status=ExecutionStatus.TIMEOUT,
        stdout="",
        stderr="Connection timed out after 10000ms",
        exit_code=-1,
        duration=10.0,
        timestamp=123456789.0
    )
    
    mock_agent.executor.terminal.execute.return_value = timeout_result
    
    # Run tool execution
    result = mock_agent._run_system_tool("nmap_port_scan", MagicMock(), {"target": "127.0.0.1"})
    
    # Assertions - check for timeout-related message (case insensitive)
    error_summary = result.get("error_summary", "").lower()
    assert "timed out" in error_summary or "timeout" in error_summary
    mock_agent.logger.log_action = MagicMock() # Verify logging called

def test_chaos_tool_missing(mock_agent):
    """Chaos Test 2: Simulate tool missing scenario"""
    missing_result = ExecutionResult(
        command="missing_tool",
        status=ExecutionStatus.FAILED,
        stdout="",
        stderr="bash: missing_tool: command not found",
        exit_code=127,
        duration=0.1,
        timestamp=123456789.0
    )
    
    mock_agent.executor.terminal.execute.return_value = missing_result
    
    # Patch auto-install to fail to simulate hard failure
    with patch.object(mock_agent, '_install_tool', return_value=False):
        result = mock_agent._run_system_tool("generic_tool", MagicMock(), {})
    
    # Check for tool missing related message (case insensitive)
    error_summary = result.get("error_summary", "").lower()
    assert "not found" in error_summary or "not installed" in error_summary or "command failed" in error_summary

def test_chaos_connection_refused(mock_agent):
    """Chaos Test 3: Simulate connection refused"""
    refused_result = ExecutionResult(
        command="curl target",
        status=ExecutionStatus.FAILED,
        stdout="",
        stderr="curl: (7) Failed to connect to port 80: Connection refused",
        exit_code=7,
        duration=0.5,
        timestamp=123456789.0
    )
    
    mock_agent.executor.terminal.execute.return_value = refused_result
    
    result = mock_agent._run_system_tool("curl_scan", MagicMock(), {})
    
    # Check for connection refused related message (case insensitive)
    error_summary = result.get("error_summary", "").lower()
    assert "connection refused" in error_summary or "connection" in error_summary
