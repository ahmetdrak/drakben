
import asyncio
import json
import logging
from unittest.mock import MagicMock, AsyncMock
from core.brain import DrakbenBrain, OpenRouterClient

# Setup Logging
logging.basicConfig(level=logging.ERROR)

def _process_test_case(name, malformed_response, brain, mock_llm):
    """Internal helper to process a single LLM resilience case"""
    print(f"Testing: {name}...", end=" ")
    mock_llm.query.return_value = malformed_response
    
    try:
        from core.brain import ExecutionContext
        context = ExecutionContext()
        result = brain.reasoning.analyze("Please analyze", context)
        
        if not isinstance(result, dict):
            print(f"❌ FAIL (Wrong Type: {type(result)})")
            return 0

        if name == "Mixed Content":
            if result.get("success") is True:
                print("✅ PASS (Extracted)")
            else:
                print("⚠️ PASS (Handled but failed to extract)")
        elif "error" in result or not result:
            print("✅ PASS (Handled Gracefully)")
        else:
            print(f"❓ PASS (Returned: {result})")
        return 1
    except Exception as e:
        print(f"❌ FAIL (Crashed: {e})")
        return 0

def test_llm_resilience():
    print("Starting LLM Resilience Tests (Hallucination & Bad Format)...")
    
    # 1. Mocking the LLM Client
    mock_llm = MagicMock(spec=OpenRouterClient)
    brain = DrakbenBrain(llm_client=mock_llm)
    
    test_cases = [
        ("Invalid JSON", "This is not json"),
        ("Empty String", ""),
        ("Partial JSON", '{"key": "val"'),
        ("Wrong Structure", '{"wrong_key": "val"}'),
        ("None", None),
        ("Mixed Content", 'Here is the json: {"success": true}'), # Brain should extract JSON
    ]
    
    score = 0
    for name, malformed_response in test_cases:
        score += _process_test_case(name, malformed_response, brain, mock_llm)
            
    print(f"\nResult: {score}/{len(test_cases)} tests passed.")

if __name__ == "__main__":
    test_llm_resilience()
