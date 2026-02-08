#!/usr/bin/env python3
"""DRAKBEN Integration Test."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_full_integration() -> None:
    """DRAKBEN Integration Test - Verify all main subsystems connect correctly."""
    # Test 1: Core imports
    from core.agent.state import AgentState
    from core.intelligence.coder import ASTSecurityChecker

    # Test 2: LLM imports
    from llm.openrouter_client import LLMCache

    # Test 3: Module imports
    from modules.exploit import suggest_exploit
    from modules.payload import PAYLOAD_TEMPLATES, list_payloads

    # Test 5: State singleton
    s1 = AgentState("test1")
    s2 = AgentState("test2")  # Should return same instance
    assert s1 is s2, "Singleton failed"

    # Test 6: AST Security
    checker = ASTSecurityChecker()
    violations = checker.check('eval("test")')
    assert len(violations) > 0

    # Test 7: LLM Cache
    cache = LLMCache()
    cache.set("p", "s", "m", "response")
    assert cache.get("p", "s", "m") == "response"

    # Test 8: Payload templates
    assert len(PAYLOAD_TEMPLATES) > 10
    payloads = list_payloads()
    assert len(payloads) > 0

    # Test 9: Recon functions
    from modules.recon import detect_technologies, extract_domain

    assert extract_domain("https://example.com") == "example.com"
    techs = detect_technologies(
        "<script src='jquery.js'></script>",
        {"Server": "nginx"},
    )
    assert len(techs) > 0

    # Test 10: Exploit suggestions
    suggestion = suggest_exploit("sqli")
    assert "tool" in suggestion


if __name__ == "__main__":
    try:
        test_full_integration()
    except Exception:
        sys.exit(1)
