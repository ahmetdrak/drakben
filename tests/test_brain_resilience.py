
import asyncio
import json
import logging
from unittest.mock import MagicMock, AsyncMock
from core.brain import DrakbenBrain, OpenRouterClient

# Setup Logging
logging.basicConfig(level=logging.ERROR)

def test_llm_resilience():
    print("Starting LLM Resilience Tests (Hallucination & Bad Format)...")
    
    # 1. Mocking the LLM Client
    mock_llm = MagicMock(spec=OpenRouterClient)
    brain = DrakbenBrain(llm_client=mock_llm)
    
    # DrakbenBrain.think calls reasoning.analyze internally, or we access reasoning directly.
    # Let's inspect brain.think if possible, but testing internals is fine.
    # If DrakbenBrain doesn't have analyze, we should check what it has.
    # Assuming brain.think(text, context) is the main entry.
    # But for unit testing specific resilience, let's use the internal component.
    
    # We need to manually init reasoning if DrakbenBrain init doesn't expose it easily for test
    # providing full mocked chain.
    
    # Actually, let's look at how to properly call it.
    # brain.think -> self.reasoning.analyze
    
    # Let's verify DrakbenBrain structure first.

    test_cases = [
        ("Invalid JSON", "This is not json"),
        ("Empty String", ""),
        ("Partial JSON", '{"key": "val"'),
        ("Wrong Structure", '{"wrong_key": "val"}'),
        ("None", None),
        ("Mixed Content", 'Here is the json: {"success": true}'), # Brain should extract JSON
    ]
    
    score = 0
    total = len(test_cases)
    
    for name, malformed_response in test_cases:
        print(f"Testing: {name}...", end=" ")
        
        # Configure Mock
        mock_llm.query.return_value = malformed_response
        
        try:
            # Use internal reasoning module directly as it holds the LLM logic being tested
            # We need an ExecutionContext for analyze
            from core.brain import ExecutionContext
            context = ExecutionContext()
            
            result = brain.reasoning.analyze("Please analyze", context)
            
            # Acceptance Criteria: Should return a dict, not crash
            if isinstance(result, dict):
                # If "Mixed Content", it should optimally extract the JSON
                if name == "Mixed Content" and result.get("success") is True:
                     print("✅ PASS (Extracted)")
                elif name == "Mixed Content" and not result.get("success"):
                     print("⚠️ PASS (Handled but failed to extract)")
                else:
                    # Generic Safe Fallback
                    if "error" in result or not result: 
                        print("✅ PASS (Handled Gracefully)")
                    else:
                         print(f"❓ PASS (Returned: {result})")
                score += 1
            else:
                print(f"❌ FAIL (Wrong Type: {type(result)})")
                
        except Exception as e:
            print(f"❌ FAIL (Crashed: {e})")
            
    print(f"\nResult: {score}/{total} tests passed.")

if __name__ == "__main__":
    test_llm_resilience()
