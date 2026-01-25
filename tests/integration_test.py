#!/usr/bin/env python3
"""DRAKBEN Integration Test"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

errors = []
passed = []

# Test 1: Core imports
try:
    from core.brain import DrakbenBrain, ContinuousReasoning
    from core.config import ConfigManager
    from core.state import AgentState, reset_state
    from core.evolution_memory import get_evolution_memory
    from core.planner import Planner
    from core.tool_selector import ToolSelector
    from core.coder import AICoder, ASTSecurityChecker
    from core.execution_engine import SmartTerminal
    from core.logging_config import setup_logging, get_logger
    passed.append('Core imports')
except Exception as e:
    errors.append(f'Core imports: {e}')

# Test 2: LLM imports
try:
    from llm.openrouter_client import OpenRouterClient, LLMCache, RateLimiter
    passed.append('LLM imports')
except Exception as e:
    errors.append(f'LLM imports: {e}')

# Test 3: Module imports
try:
    from modules.recon import passive_recon, passive_recon_sync, detect_cms
    from modules.exploit import suggest_exploit, check_exploit_preconditions
    from modules.payload import PAYLOAD_TEMPLATES, list_payloads
    passed.append('Module imports')
except Exception as e:
    errors.append(f'Module imports: {e}')

# Test 4: Main entry
try:
    from drakben import main
    passed.append('Main entry')
except Exception as e:
    errors.append(f'Main entry: {e}')

# Test 5: State singleton
try:
    from core.state import AgentState
    s1 = AgentState("test1")
    s2 = AgentState("test2")  # Should return same instance
    assert s1 is s2, 'Singleton failed'
    passed.append('State singleton')
except Exception as e:
    errors.append(f'State singleton: {e}')

# Test 6: AST Security
try:
    checker = ASTSecurityChecker()
    violations = checker.check('eval("test")')
    assert len(violations) > 0
    passed.append('AST Security')
except Exception as e:
    errors.append(f'AST Security: {e}')

# Test 7: LLM Cache
try:
    cache = LLMCache()
    cache.set('p', 's', 'm', 'response')
    assert cache.get('p', 's', 'm') == 'response'
    passed.append('LLM Cache')
except Exception as e:
    errors.append(f'LLM Cache: {e}')

# Test 8: Payload templates
try:
    assert len(PAYLOAD_TEMPLATES) > 10
    payloads = list_payloads()
    assert len(payloads) > 0
    passed.append('Payload templates')
except Exception as e:
    errors.append(f'Payload templates: {e}')

# Test 9: Recon functions
try:
    from modules.recon import extract_domain, detect_technologies
    assert extract_domain("https://example.com") == "example.com"
    techs = detect_technologies("<script src='jquery.js'></script>", {"Server": "nginx"})
    assert len(techs) > 0
    passed.append('Recon functions')
except Exception as e:
    errors.append(f'Recon functions: {e}')

# Test 10: Exploit suggestions
try:
    suggestion = suggest_exploit("sqli")
    assert "tool" in suggestion
    passed.append('Exploit suggestions')
except Exception as e:
    errors.append(f'Exploit suggestions: {e}')

if __name__ == "__main__":
    print('='*50)
    print('INTEGRATION TEST RESULTS')
    print('='*50)
    print(f'Passed: {len(passed)}')
    for p in passed:
        print(f'  [OK] {p}')

    if errors:
        print(f'Failed: {len(errors)}')
        for e in errors:
            print(f'  [FAIL] {e}')
        sys.exit(1)
    else:
        print('All tests passed!')
    print('='*50)
    sys.exit(0)
else:
    # If imported by pytest, raise error if any tests failed so pytest sees it
    if errors:
        raise RuntimeError(f"Integration tests failed: {errors}")
