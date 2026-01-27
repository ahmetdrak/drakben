
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from core.brain import ContinuousReasoning, ExecutionContext
from core.planner import Planner
from modules.subdomain import SubdomainEnumerator

# Set global timeout for all tests in this file
pytestmark = pytest.mark.timeout(5)  # 5 seconds timeout

@pytest.fixture
def mock_llm():
    llm = MagicMock()
    # Return a simple JSON response to avoid retries
    llm.query.return_value = '{"success": true, "intent": "scan", "response": "ok", "steps": []}'
    return llm

@pytest.fixture
def brain(mock_llm):
    return ContinuousReasoning(llm_client=mock_llm)

@pytest.fixture
def planner():
    return Planner()

def test_brain_analyze_loop(brain):
    """Test for infinite loops in Brain.analyze"""
    context = MagicMock(spec=ExecutionContext)
    context.system_info = {}
    context.target = "example.com"
    context.language = "en"
    
    # This should return instantly (ms)
    # If it loops, pytest-timeout will kill it
    result = brain.analyze("scan target", context)
    assert result["success"] is True

def test_planner_create_plan_loop(planner):
    """Test for infinite loops in Planner.create_plan"""
    # This should be fast
    plan_id = planner.create_plan_for_target("example.com", "scan")
    assert isinstance(plan_id, str)
    assert len(planner.steps) > 0

@pytest.mark.asyncio
async def test_subdomain_enum_loop():
    """Test for infinite loops in Subdomain Enumerator"""
    # Mock external tools to avoid real network/process waits
    enumerator = SubdomainEnumerator(use_external_tools=False)
    
    # Mock internal methods to avoid actual HTTP calls but keep logic flow
    enumerator._crtsh_enum = AsyncMock(return_value=[])
    enumerator._web_archive_enum = AsyncMock(return_value=[])
    enumerator._virustotal_enum = AsyncMock(return_value=[])
    enumerator._bruteforce_enum = AsyncMock(return_value=[])
    enumerator._resolve_subdomains = AsyncMock(side_effect=lambda x: x) # Return input as is
    
    results = await enumerator.enumerate("example.com", use_bruteforce=True)
    assert isinstance(results, list)

def test_fibonacci_stress_check():
    """Control test: Should pass quickly. Ensures valid environment."""
    a, b = 0, 1
    for _ in range(100):
        a, b = b, a + b
    assert a > 0
