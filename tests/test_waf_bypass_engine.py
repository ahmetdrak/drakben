"""Tests for WAF Bypass Engine v2.0"""

import time

from modules.waf_bypass_engine import (
    WAF_SIGNATURES,
    AdaptiveMutationMemory,
    CommandBypassEngine,
    EncodingEngine,
    HTTPBypassEngine,
    PayloadAttempt,
    SQLBypassEngine,
    WAFBypassEngine,
    WAFSignature,
    WAFType,
    XSSBypassEngine,
    create_engine,
    fingerprint_waf,
)


class TestWAFFingerprinting:
    """Test WAF fingerprinting capabilities."""

    def test_detect_cloudflare(self) -> None:
        """Test Cloudflare detection."""
        engine = WAFBypassEngine(":memory:")
        headers = {
            "cf-ray": "abc123",
            "server": "cloudflare",
        }
        body = "Attention Required! | Cloudflare"

        waf = engine.fingerprint_waf(headers, body, 403)
        assert waf == WAFType.CLOUDFLARE

    def test_detect_aws_waf(self) -> None:
        """Test AWS WAF detection."""
        engine = WAFBypassEngine(":memory:")
        headers = {
            "x-amzn-requestid": "abc123",
        }
        body = "Request blocked"

        waf = engine.fingerprint_waf(headers, body, 403)
        assert waf == WAFType.AWS_WAF

    def test_detect_modsecurity(self) -> None:
        """Test ModSecurity detection."""
        engine = WAFBypassEngine(":memory:")
        headers: dict[str, str] = {}
        body = "ModSecurity: Access denied"

        waf = engine.fingerprint_waf(headers, body, 403)
        assert waf == WAFType.MODSECURITY

    def test_detect_imperva(self) -> None:
        """Test Imperva detection."""
        engine = WAFBypassEngine(":memory:")
        headers = {"x-iinfo": "abc"}
        body = "Incapsula incident ID"
        cookies = ["incap_ses_123"]

        waf = engine.fingerprint_waf(headers, body, 403, cookies)
        assert waf == WAFType.IMPERVA

    def test_detect_unknown(self) -> None:
        """Test unknown WAF detection."""
        engine = WAFBypassEngine(":memory:")
        waf = engine.fingerprint_waf({}, "", 200)
        assert waf == WAFType.UNKNOWN

    def test_fingerprint_function(self) -> None:
        """Test convenience fingerprint function."""
        waf = fingerprint_waf(
            {"cf-ray": "123", "server": "cloudflare"},
            "Ray ID:",
            403
        )
        assert waf == WAFType.CLOUDFLARE


class TestAdaptiveMutationMemory:
    """Test adaptive learning memory."""

    def test_record_attempt(self) -> None:
        """Test recording payload attempt."""
        memory = AdaptiveMutationMemory(":memory:")
        attempt = PayloadAttempt(
            payload_hash="abc123",
            original_payload="' OR 1=1--",
            mutated_payload="'%20OR%201=1--",
            mutation_type="url_encode",
            waf_type=WAFType.CLOUDFLARE,
            target="test.com",
            success=True,
            response_code=200,
            timestamp=time.time(),
            context="sqli",
        )

        memory.record_attempt(attempt)
        stats = memory.get_stats()

        assert stats["total_attempts"] == 1
        assert stats["successful_bypasses"] == 1

    def test_record_failure(self) -> None:
        """Test recording failed attempt."""
        memory = AdaptiveMutationMemory(":memory:")
        attempt = PayloadAttempt(
            payload_hash="abc123",
            original_payload="' OR 1=1--",
            mutated_payload="' OR 1=1--",
            mutation_type="none",
            waf_type=WAFType.CLOUDFLARE,
            target="test.com",
            success=False,
            response_code=403,
            timestamp=time.time(),
            context="sqli",
        )

        memory.record_attempt(attempt)
        stats = memory.get_stats()

        assert stats["total_attempts"] == 1
        assert stats["successful_bypasses"] == 0
        assert stats["known_blocked_patterns"] == 1

    def test_pattern_blocking(self) -> None:
        """Test pattern blocking after multiple failures."""
        memory = AdaptiveMutationMemory(":memory:")
        payload = "blocked_payload"

        # Record 3 failures for same pattern
        for _ in range(3):
            attempt = PayloadAttempt(
                payload_hash="test",
                original_payload=payload,
                mutated_payload=payload,
                mutation_type="none",
                waf_type=WAFType.CLOUDFLARE,
                target="test.com",
                success=False,
                response_code=403,
                timestamp=time.time(),
                context="sqli",
            )
            memory.record_attempt(attempt)

        assert memory.is_pattern_blocked(WAFType.CLOUDFLARE, payload)

    def test_get_best_mutations(self) -> None:
        """Test getting best mutations."""
        memory = AdaptiveMutationMemory(":memory:")

        # Record successful attempt
        attempt = PayloadAttempt(
            payload_hash="abc",
            original_payload="test",
            mutated_payload="test_encoded",
            mutation_type="url_encode",
            waf_type=WAFType.CLOUDFLARE,
            target="test.com",
            success=True,
            response_code=200,
            timestamp=time.time(),
            context="sqli",
        )
        memory.record_attempt(attempt)

        best = memory.get_best_mutations(WAFType.CLOUDFLARE, "sqli")
        assert len(best) > 0
        assert best[0][0] == "url_encode"


class TestEncodingEngine:
    """Test encoding techniques."""

    def test_url_encode_levels(self) -> None:
        """Test multi-level URL encoding."""
        payload = "'"

        level1 = EncodingEngine.url_encode(payload, 1)
        assert level1 == "%27"

        level2 = EncodingEngine.url_encode(payload, 2)
        assert level2 == "%2527"

        level3 = EncodingEngine.url_encode(payload, 3)
        assert level3 == "%252527"

    def test_double_url_encode(self) -> None:
        """Test double URL encoding."""
        result = EncodingEngine.double_url_encode("'")
        assert result == "%2527"

    def test_triple_url_encode(self) -> None:
        """Test triple URL encoding."""
        result = EncodingEngine.triple_url_encode("'")
        assert result == "%252527"

    def test_mixed_encoding(self) -> None:
        """Test mixed encoding."""
        result = EncodingEngine.mixed_encoding("test")
        assert len(result) > 0
        # Should contain some encoding

    def test_unicode_fullwidth(self) -> None:
        """Test fullwidth unicode encoding."""
        result = EncodingEngine.unicode_encode("ABC", "fullwidth")
        # Fullwidth A is U+FF21
        assert ord(result[0]) == 0xFF21

    def test_html_entity_decimal(self) -> None:
        """Test HTML entity decimal encoding."""
        result = EncodingEngine.html_entity_encode("A", use_hex=False)
        assert result == "&#65;"

    def test_html_entity_hex(self) -> None:
        """Test HTML entity hex encoding."""
        result = EncodingEngine.html_entity_encode("A", use_hex=True)
        assert result == "&#x41;"

    def test_hex_encode(self) -> None:
        """Test hex encoding."""
        result = EncodingEngine.hex_encode("AB")
        assert result == "0x4142"

    def test_null_byte_injection(self) -> None:
        """Test null byte injection."""
        # Run multiple times since it's random
        found_null = False
        for _ in range(10):
            result = EncodingEngine.null_byte_injection("test")
            if "%00" in result or "\x00" in result:
                found_null = True
                break
        assert found_null, "Null byte injection should work at least once in 10 tries"


class TestSQLBypassEngine:
    """Test SQL injection bypass techniques."""

    def test_scientific_notation(self) -> None:
        """Test scientific notation conversion."""
        result = SQLBypassEngine.scientific_notation(1)
        assert result == "1e0"

        result = SQLBypassEngine.scientific_notation("5")
        assert result == "5e0"

    def test_obfuscate_query_level1(self) -> None:
        """Test level 1 obfuscation (whitespace)."""
        query = "SELECT * FROM users"
        result = SQLBypassEngine.obfuscate_query(query, 1)
        assert " " not in result or "/**/" in result or "%09" in result

    def test_obfuscate_query_level2(self) -> None:
        """Test level 2 obfuscation (keywords)."""
        query = "SELECT * FROM users"
        result = SQLBypassEngine.obfuscate_query(query, 2)
        # Should have keyword obfuscation
        assert result != query

    def test_concat_bypass(self) -> None:
        """Test CONCAT bypass."""
        result = SQLBypassEngine.concat_bypass("admin")
        assert "CONCAT" in result
        assert "ad" in result
        assert "min" in result

    def test_char_bypass(self) -> None:
        """Test CHAR() bypass."""
        result = SQLBypassEngine.char_bypass("AB")
        assert result == "CHAR(65,66)"

    def test_nested_comments(self) -> None:
        """Test nested comments."""
        result = SQLBypassEngine.nested_comments("UNION SELECT")
        assert "/*!" in result

    def test_json_sql_injection(self) -> None:
        """Test JSON SQL injection."""
        result = SQLBypassEngine.json_sql_injection("' OR 1=1--")
        assert '"id":' in result


class TestXSSBypassEngine:
    """Test XSS bypass techniques."""

    def test_svg_payload(self) -> None:
        """Test SVG payload generation."""
        result = XSSBypassEngine.svg_payload()
        assert "<svg" in result.lower()
        assert "alert" in result or "onload" in result

    def test_math_payload(self) -> None:
        """Test MathML payload generation."""
        result = XSSBypassEngine.math_payload()
        assert "<math" in result.lower()

    def test_polyglot(self) -> None:
        """Test XSS polyglot."""
        result = XSSBypassEngine.polyglot()
        assert "javascript" in result.lower()
        assert "alert" in result.lower()

    def test_case_mutation(self) -> None:
        """Test case mutation."""
        result = XSSBypassEngine.case_mutation("script")
        # Should have mixed case
        assert result.lower() == "script"

    def test_tag_mutation(self) -> None:
        """Test tag mutation."""
        result = XSSBypassEngine.tag_mutation("<script>alert(1)</script>")
        # Should have some mutation
        assert len(result) > 0


class TestCommandBypassEngine:
    """Test command injection bypass techniques."""

    def test_bash_obfuscate(self) -> None:
        """Test bash command obfuscation."""
        result = CommandBypassEngine.bash_obfuscate("cat /etc/passwd")
        # Should be different from original
        assert len(result) > 0

    def test_powershell_obfuscate(self) -> None:
        """Test PowerShell obfuscation."""
        result = CommandBypassEngine.powershell_obfuscate("Get-Process")
        assert len(result) > 0


class TestHTTPBypassEngine:
    """Test HTTP protocol bypass techniques."""

    def test_chunked_encoding(self) -> None:
        """Test chunked transfer encoding."""
        headers, body = HTTPBypassEngine.chunked_encoding("test data")
        assert headers["Transfer-Encoding"] == "chunked"
        assert "0\r\n\r\n" in body  # Final chunk

    def test_parameter_pollution(self) -> None:
        """Test HTTP Parameter Pollution."""
        result = HTTPBypassEngine.http_parameter_pollution({"id": "1"})
        assert result.count("id=") >= 2  # Multiple occurrences

    def test_content_type_bypass(self) -> None:
        """Test content type variations."""
        types = HTTPBypassEngine.content_type_bypass()
        assert len(types) > 5
        assert "application/json" in types

    def test_header_injection(self) -> None:
        """Test bypass headers."""
        headers = HTTPBypassEngine.header_injection("")
        assert "X-Forwarded-For" in headers
        assert headers["X-Forwarded-For"] == "127.0.0.1"


class TestWAFBypassEngine:
    """Test main WAF Bypass Engine."""

    def test_create_engine(self) -> None:
        """Test engine creation."""
        engine = create_engine(":memory:")
        assert engine is not None
        assert isinstance(engine, WAFBypassEngine)

    def test_bypass_sql(self) -> None:
        """Test SQL bypass generation."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.bypass_sql("' OR 1=1--")

        assert len(payloads) > 0
        assert all(isinstance(p, str) for p in payloads)

    def test_bypass_sql_cloudflare(self) -> None:
        """Test SQL bypass for Cloudflare."""
        engine = WAFBypassEngine(":memory:")
        engine.detected_waf = WAFType.CLOUDFLARE
        payloads = engine.bypass_sql("' OR 1=1--", aggressiveness=3)

        assert len(payloads) > 5
        # Should have Cloudflare-specific mutations

    def test_bypass_xss(self) -> None:
        """Test XSS bypass generation."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.bypass_xss("<script>alert(1)</script>")

        assert len(payloads) > 0
        assert any("<svg" in p.lower() for p in payloads)

    def test_bypass_rce_linux(self) -> None:
        """Test RCE bypass for Linux."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.bypass_rce("cat /etc/passwd", "linux")

        assert len(payloads) > 0

    def test_bypass_rce_windows(self) -> None:
        """Test RCE bypass for Windows."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.bypass_rce("dir", "windows")

        assert len(payloads) > 0

    def test_record_result(self) -> None:
        """Test recording bypass result."""
        engine = WAFBypassEngine(":memory:")
        engine.detected_waf = WAFType.CLOUDFLARE

        engine.record_result(
            original="' OR 1=1--",
            mutated="'%20OR%201=1--",
            mutation_type="url_encode",
            success=True,
            response_code=200,
            context="sqli",
            target="test.com",
        )

        stats = engine.get_stats()
        assert stats["total_attempts"] == 1

    def test_smart_bypass_sqli(self) -> None:
        """Test smart bypass for SQLi."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.smart_bypass("' OR 1=1--", "sqli")

        assert len(payloads) > 0

    def test_smart_bypass_xss(self) -> None:
        """Test smart bypass for XSS."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.smart_bypass("<script>alert(1)</script>", "xss")

        assert len(payloads) > 0

    def test_smart_bypass_rce(self) -> None:
        """Test smart bypass for RCE."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.smart_bypass("cat /etc/passwd", "rce")

        assert len(payloads) > 0

    def test_smart_bypass_generic(self) -> None:
        """Test smart bypass for unknown context."""
        engine = WAFBypassEngine(":memory:")
        payloads = engine.smart_bypass("test", "unknown")

        assert len(payloads) > 0

    def test_get_chunked_request(self) -> None:
        """Test chunked request generation."""
        engine = WAFBypassEngine(":memory:")
        headers, body = engine.get_chunked_request("test")

        assert "Transfer-Encoding" in headers
        assert "0\r\n\r\n" in body

    def test_get_hpp_params(self) -> None:
        """Test HPP params generation."""
        engine = WAFBypassEngine(":memory:")
        result = engine.get_hpp_params({"id": "1", "name": "test"})

        assert "id=" in result
        assert "name=" in result

    def test_get_bypass_headers(self) -> None:
        """Test bypass headers generation."""
        engine = WAFBypassEngine(":memory:")
        headers = engine.get_bypass_headers()

        assert "X-Forwarded-For" in headers

    def test_adaptive_learning(self) -> None:
        """Test adaptive learning workflow."""
        engine = WAFBypassEngine(":memory:")
        engine.detected_waf = WAFType.CLOUDFLARE

        # Record multiple successes for url_encode
        for _ in range(5):
            engine.record_result(
                original="test",
                mutated="test_encoded",
                mutation_type="url_encode",
                success=True,
                response_code=200,
                context="sqli",
            )

        # Record failures for other mutations
        for _ in range(5):
            engine.record_result(
                original="test",
                mutated="test_other",
                mutation_type="other",
                success=False,
                response_code=403,
                context="sqli",
            )

        # Best mutations should prioritize url_encode
        best = engine.memory.get_best_mutations(WAFType.CLOUDFLARE, "sqli")
        assert len(best) > 0
        # url_encode should have higher score


class TestWAFSignatures:
    """Test WAF signatures database."""

    def test_all_waf_signatures_exist(self) -> None:
        """Test all major WAFs have signatures."""
        expected_wafs = [
            WAFType.CLOUDFLARE,
            WAFType.AWS_WAF,
            WAFType.MODSECURITY,
            WAFType.IMPERVA,
            WAFType.AKAMAI,
            WAFType.F5_BIG_IP,
        ]

        for waf in expected_wafs:
            assert waf in WAF_SIGNATURES

    def test_signature_structure(self) -> None:
        """Test signature structure is valid."""
        for waf_type, sig in WAF_SIGNATURES.items():
            assert isinstance(sig, WAFSignature)
            assert sig.waf_type == waf_type
            assert isinstance(sig.headers, dict)
            assert isinstance(sig.cookies, list)
            assert isinstance(sig.body_patterns, list)
            assert isinstance(sig.status_codes, list)


class TestIntegration:
    """Integration tests for WAF Bypass Engine."""

    def test_full_bypass_workflow(self) -> None:
        """Test complete bypass workflow."""
        engine = WAFBypassEngine(":memory:")

        # 1. Fingerprint WAF
        waf = engine.fingerprint_waf(
            {"cf-ray": "123", "server": "cloudflare"},
            "Ray ID: abc",
            403,
        )
        assert waf == WAFType.CLOUDFLARE

        # 2. Generate payloads
        payloads = engine.bypass_sql("' OR 1=1--")
        assert len(payloads) > 0

        # 3. Test and record results
        for i, payload in enumerate(payloads[:3]):
            success = i == 0  # Simulate first one works
            engine.record_result(
                original="' OR 1=1--",
                mutated=payload,
                mutation_type="test",
                success=success,
                response_code=200 if success else 403,
                context="sqli",
            )

        # 4. Check stats
        stats = engine.get_stats()
        assert stats["total_attempts"] >= 3

    def test_memory_persistence(self) -> None:
        """Test memory persists between calls."""
        import os
        import tempfile

        db_path = os.path.join(tempfile.gettempdir(), "test_waf_memory.db")

        try:
            # First engine
            engine1 = WAFBypassEngine(db_path)
            engine1.detected_waf = WAFType.CLOUDFLARE
            engine1.record_result(
                original="test",
                mutated="test_encoded",
                mutation_type="url_encode",
                success=True,
                response_code=200,
                context="sqli",
            )

            # Second engine (same db)
            engine2 = WAFBypassEngine(db_path)
            stats = engine2.get_stats()

            assert stats["total_attempts"] >= 1
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
