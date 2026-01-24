# tests/test_improvements.py
# DRAKBEN Improvement Tests
# Verifies that implemented improvements work correctly

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import logging

def test_logging_config():
    """Test structured logging configuration"""
    print("=" * 50)
    print("TEST 1: Logging Configuration")
    print("=" * 50)
    
    try:
        from core.logging_config import setup_logging, get_logger, log_tool_execution
        
        # Setup logging - use correct parameter name 'level' not 'log_level'
        setup_logging(level="DEBUG", log_to_file=False)
        logger = get_logger("test")
        
        logger.info("Test log message")
        logger.debug("Debug message")
        logger.warning("Warning message")
        
        # Test log_tool_execution helper - requires logger as first arg
        log_tool_execution(logger, "test_tool", "target", True, 1.5)
        
        print("[PASS] Logging configuration works correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] Logging test failed: {e}\n")
        return False


def test_brain_history_limit():
    """Test brain.py reasoning_history limit"""
    print("=" * 50)
    print("TEST 2: Brain Reasoning History Limit")
    print("=" * 50)
    
    try:
        from core.brain import ContinuousReasoning
        
        reasoning = ContinuousReasoning(llm_client=None)
        
        # Check MAX_REASONING_HISTORY exists
        assert hasattr(reasoning, 'MAX_REASONING_HISTORY'), "MAX_REASONING_HISTORY not found"
        assert reasoning.MAX_REASONING_HISTORY == 100, f"Expected 100, got {reasoning.MAX_REASONING_HISTORY}"
        
        # Check _add_to_history method exists
        assert hasattr(reasoning, '_add_to_history'), "_add_to_history method not found"
        
        # Test history limiting
        for i in range(150):
            reasoning._add_to_history({"step": i})
        
        assert len(reasoning.reasoning_history) == 100, f"Expected 100 items, got {len(reasoning.reasoning_history)}"
        
        print("[PASS] Brain reasoning history limit works correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] Brain history limit test failed: {e}\n")
        return False


def test_recon_module():
    """Test recon.py improvements"""
    print("=" * 50)
    print("TEST 3: Recon Module")
    print("=" * 50)
    
    try:
        from modules.recon import (
            passive_recon, 
            passive_recon_sync,
            detect_cms, 
            detect_technologies,
            extract_domain
        )
        
        # Test extract_domain
        assert extract_domain("https://example.com") == "example.com"
        assert extract_domain("https://example.com:8080/path") == "example.com"
        assert extract_domain("http://sub.domain.com") == "sub.domain.com"
        
        # Test detect_cms
        html = "<html><body>Powered by WordPress</body></html>"
        assert detect_cms(html, {}) == "WordPress"
        
        # Test detect_technologies
        html = "<html><head><script src='jquery.min.js'></script></head></html>"
        techs = detect_technologies(html, {"Server": "nginx"})
        assert "jQuery" in techs
        assert "Server: nginx" in techs
        
        # Test sync wrapper exists
        assert callable(passive_recon_sync)
        
        print("[PASS] Recon module improvements work correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] Recon module test failed: {e}\n")
        return False


def test_exploit_module():
    """Test exploit.py improvements"""
    print("=" * 50)
    print("TEST 4: Exploit Module")
    print("=" * 50)
    
    try:
        from modules.exploit import (
            check_exploit_preconditions,
            suggest_exploit,
            RetryConfig,
            retry_on_failure
        )
        
        # Test RetryConfig
        config = RetryConfig(max_retries=5, base_delay=2.0)
        assert config.max_retries == 5
        assert config.base_delay == 2.0
        
        # Test suggest_exploit
        sqli_suggestion = suggest_exploit("sqli")
        assert sqli_suggestion["tool"] == "sqlmap"
        assert "payloads" in sqli_suggestion
        
        xss_suggestion = suggest_exploit("xss")
        assert "payloads" in xss_suggestion
        
        unknown = suggest_exploit("unknown_type")
        assert "error" in unknown
        assert "available" in unknown
        
        print("[PASS] Exploit module improvements work correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] Exploit module test failed: {e}\n")
        return False


def test_payload_module():
    """Test payload.py improvements"""
    print("=" * 50)
    print("TEST 5: Payload Module")
    print("=" * 50)
    
    try:
        from modules.payload import (
            PAYLOAD_TEMPLATES,
            list_payloads,
            check_payload_preconditions
        )
        
        # Test PAYLOAD_TEMPLATES
        assert len(PAYLOAD_TEMPLATES) > 10, "Should have many payload templates"
        assert "reverse_shell_bash" in PAYLOAD_TEMPLATES
        assert "web_shell_php" in PAYLOAD_TEMPLATES
        
        # Test list_payloads
        all_payloads = list_payloads()
        assert len(all_payloads) > 0
        
        linux_payloads = list_payloads(os_filter="linux")
        assert all(p["os"] in ["linux", "any"] for p in linux_payloads)
        
        print("[PASS] Payload module improvements work correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] Payload module test failed: {e}\n")
        return False


def test_coder_ast_security():
    """Test coder.py AST-based security check"""
    print("=" * 50)
    print("TEST 6: Coder AST Security Check")
    print("=" * 50)
    
    try:
        from core.coder import ASTSecurityChecker
        
        checker = ASTSecurityChecker()
        
        # Test dangerous functions
        dangerous_code = "eval('print(1)')"
        violations = checker.check(dangerous_code)
        assert len(violations) > 0, "Should detect eval()"
        
        # Test dangerous imports
        dangerous_import = "import pickle\nx = pickle.loads(data)"
        violations = checker.check(dangerous_import)
        assert len(violations) > 0, "Should detect pickle import"
        
        # Test os.system
        os_system_code = "import os\nos.system('rm -rf /')"
        violations = checker.check(os_system_code)
        assert len(violations) > 0, "Should detect os.system()"
        
        # Test safe code
        safe_code = """
import socket

def run(target, args=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((target, 80))
        s.close()
        return {"success": True, "output": str(result), "error": None}
    except Exception as e:
        return {"success": False, "output": "", "error": str(e)}
"""
        violations = checker.check(safe_code)
        assert len(violations) == 0, f"Safe code should pass: {violations}"
        
        print("[PASS] Coder AST security check works correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] Coder AST security test failed: {e}\n")
        return False


def test_thread_safety():
    """Test thread safety improvements in config and state"""
    print("=" * 50)
    print("TEST 7: Thread Safety")
    print("=" * 50)
    
    try:
        from core.config import ConfigManager
        from core.state import AgentState, get_state
        import threading
        
        # Test ConfigManager has lock
        config = ConfigManager()
        assert hasattr(config, '_lock'), "ConfigManager should have _lock"
        
        # Test AgentState has lock
        state = get_state()
        assert hasattr(state, '_lock'), "AgentState should have _lock"
        
        # Test singleton pattern
        state2 = get_state()
        assert state is state2, "get_state() should return same instance"
        
        print("[PASS] Thread safety improvements work correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] Thread safety test failed: {e}\n")
        return False


def test_llm_client_features():
    """Test LLM client improvements"""
    print("=" * 50)
    print("TEST 8: LLM Client Features")
    print("=" * 50)
    
    try:
        from llm.openrouter_client import LLMCache, RateLimiter
        
        # Test LLMCache - uses (prompt, system_prompt, model) signature
        cache = LLMCache(default_ttl=300, max_entries=100)
        cache.set("test_prompt", "system", "model", "test_response")
        result = cache.get("test_prompt", "system", "model")
        assert result == "test_response", "Cache should return stored value"
        
        # Test cache miss
        miss = cache.get("nonexistent", "system", "model")
        assert miss is None, "Cache should return None for missing keys"
        
        # Test RateLimiter
        limiter = RateLimiter(requests_per_minute=60)
        assert limiter.acquire(), "First acquire should succeed"
        
        print("[PASS] LLM client features work correctly\n")
        return True
    except Exception as e:
        print(f"[FAIL] LLM client features test failed: {e}\n")
        return False


def run_all_tests():
    """Run all improvement tests"""
    print("\n" + "=" * 60)
    print("DRAKBEN IMPROVEMENT TESTS")
    print("=" * 60 + "\n")
    
    tests = [
        test_logging_config,
        test_brain_history_limit,
        test_recon_module,
        test_exploit_module,
        test_payload_module,
        test_coder_ast_security,
        test_thread_safety,
        test_llm_client_features,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__} raised exception: {e}\n")
            failed += 1
    
    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
