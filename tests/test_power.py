import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.waf_evasion import WAFEvasion

try:
    from modules.stealth_client import StealthSession
    CURL_AVAILABLE = True
except ImportError:
    CURL_AVAILABLE = False


def test_waf_sql_mutation() -> None:
    """SQL payloads must be mutated by WAF evasion."""
    waf = WAFEvasion()
    raw = "UNION SELECT password FROM users"
    obfuscated = waf.obfuscate_sql(raw)
    assert obfuscated != raw, f"SQL not mutated: {obfuscated}"


def test_waf_xss_mutation() -> None:
    """XSS payloads must be mutated by WAF evasion."""
    waf = WAFEvasion()
    raw = "<script>alert(1)</script>"
    obfuscated = waf.obfuscate_xss(raw)
    assert obfuscated != raw, f"XSS not mutated: {obfuscated}"


def test_waf_shell_mutation() -> None:
    """Shell command payloads must be mutated by WAF evasion."""
    waf = WAFEvasion()
    raw = "cat /etc/passwd"
    obfuscated = waf.obfuscate_shell(raw)
    assert obfuscated != raw, f"Shell not mutated: {obfuscated}"


def test_stealth_session_instantiation() -> None:
    """StealthSession should instantiate without error."""
    if not CURL_AVAILABLE:
        import pytest
        pytest.skip("curl_cffi not installed")
    session = StealthSession(impersonate="chrome120")
    ua = session.headers.get("User-Agent", "")
    assert "Chrome" in ua or ua != "", "User-Agent not set"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
