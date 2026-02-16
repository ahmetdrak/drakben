# tests/test_final_polish.py
# Tests for the final polish items:
# - LLM Response Cache
# - Protocol/ABC Interfaces
# - Report template enhancements (evidence_artifacts, cvss_vector, methodology)
# - Docker compose & CI validation

from __future__ import annotations

import hashlib
import time
from unittest.mock import MagicMock

# ═══════════════════════════════════════════════════════════════════
# 1. LLM Cache Tests
# ═══════════════════════════════════════════════════════════════════


class TestLLMCache:
    """Tests for core.llm.llm_cache.LLMCache."""

    def _make_cache(self, **kwargs):
        from core.llm.llm_cache import LLMCache

        return LLMCache(**kwargs)

    def test_make_key_deterministic(self):
        from core.llm.llm_cache import LLMCache

        k1 = LLMCache.make_key("hello", "sys", "gpt-4o")
        k2 = LLMCache.make_key("hello", "sys", "gpt-4o")
        assert k1 == k2

    def test_make_key_different_prompts(self):
        from core.llm.llm_cache import LLMCache

        k1 = LLMCache.make_key("prompt A", "sys", "gpt-4o")
        k2 = LLMCache.make_key("prompt B", "sys", "gpt-4o")
        assert k1 != k2

    def test_put_and_get(self):
        cache = self._make_cache()
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("test", "sys", "m")
        cache.put(key, "result-123")
        assert cache.get(key) == "result-123"

    def test_miss_returns_none(self):
        cache = self._make_cache()
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("nonexistent", "", "")
        assert cache.get(key) is None

    def test_ttl_expiry(self):
        cache = self._make_cache(default_ttl=0.05)
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("expire-me", "", "")
        cache.put(key, "val")
        time.sleep(0.1)
        assert cache.get(key) is None

    def test_invalidate(self):
        cache = self._make_cache()
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("inv", "", "")
        cache.put(key, "val")
        assert cache.invalidate(key) is True
        assert cache.get(key) is None
        assert cache.invalidate(key) is False

    def test_clear(self):
        cache = self._make_cache()
        from core.llm.llm_cache import LLMCache

        for i in range(5):
            cache.put(LLMCache.make_key(f"p{i}", "", ""), f"v{i}")
        assert cache.size == 5
        removed = cache.clear()
        assert removed == 5
        assert cache.size == 0

    def test_max_size_eviction(self):
        cache = self._make_cache(max_size=3)
        from core.llm.llm_cache import LLMCache

        for i in range(5):
            cache.put(LLMCache.make_key(f"p{i}", "", ""), f"v{i}")
        assert cache.size <= 3

    def test_stats_tracking(self):
        cache = self._make_cache()
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("stats", "", "")

        cache.get(key)  # miss
        cache.put(key, "val")
        cache.get(key)  # hit
        cache.get(key)  # hit

        stats = cache.get_stats()
        assert stats["misses"] >= 1
        assert stats["hits"] >= 2
        assert stats["hit_rate"] > 0

    def test_custom_ttl_per_entry(self):
        cache = self._make_cache(default_ttl=300)
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("custom-ttl", "", "")
        cache.put(key, "val", ttl=0.05)
        time.sleep(0.1)
        assert cache.get(key) is None

    def test_dict_value_caching(self):
        cache = self._make_cache()
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("dict", "", "")
        cache.put(key, {"tool": "nmap", "result": "open"})
        assert cache.get(key) == {"tool": "nmap", "result": "open"}

    def test_cache_key_uses_sha256(self):
        from core.llm.llm_cache import LLMCache

        key = LLMCache.make_key("a", "b", "c")
        expected = hashlib.sha256(b"a\x00b\x00c").hexdigest()
        assert key.digest == expected


# ═══════════════════════════════════════════════════════════════════
# 2. LLM Engine Cache Integration Tests
# ═══════════════════════════════════════════════════════════════════


class TestLLMEngineCacheIntegration:
    """Test that LLMEngine uses cache when enabled."""

    def _make_engine(self, client=None, **kwargs):
        from core.llm.llm_engine import LLMEngine

        mock_client = client or MagicMock()
        mock_client.query = MagicMock(return_value="LLM response")
        return LLMEngine(
            llm_client=mock_client,
            enable_rag=False,
            enable_validation=False,
            enable_token_management=False,
            enable_cache=True,
            cache_ttl=300,
            **kwargs,
        )

    def test_cache_initialized(self):
        engine = self._make_engine()
        assert engine._cache is not None

    def test_cache_disabled(self):
        from core.llm.llm_engine import LLMEngine

        engine = LLMEngine(
            llm_client=MagicMock(),
            enable_cache=False,
            enable_rag=False,
            enable_validation=False,
            enable_token_management=False,
        )
        assert engine._cache is None

    def test_second_identical_query_uses_cache(self):
        mock_client = MagicMock()
        mock_client.query = MagicMock(return_value="cached-answer")
        from core.llm.llm_engine import LLMEngine

        engine = LLMEngine(
            llm_client=mock_client,
            enable_rag=False,
            enable_validation=False,
            enable_token_management=False,
            enable_cache=True,
            cache_ttl=300,
        )

        r1 = engine.query("same prompt", "same system")
        r2 = engine.query("same prompt", "same system")

        assert r1 == r2 == "cached-answer"
        # Client should only be called once — second is from cache
        assert mock_client.query.call_count == 1
        assert engine._stats["cache_hits"] == 1

    def test_different_queries_not_cached(self):
        mock_client = MagicMock()
        mock_client.query = MagicMock(side_effect=["r1", "r2"])
        engine = self._make_engine(client=mock_client)

        engine.query("prompt A")
        engine.query("prompt B")
        assert mock_client.query.call_count == 2

    def test_validate_bypasses_cache(self):
        mock_client = MagicMock()
        mock_client.query = MagicMock(return_value="resp")
        engine = self._make_engine(client=mock_client)

        engine.query("p", validate=True)
        engine.query("p", validate=True)
        # validate=True should bypass cache → both hit client
        assert mock_client.query.call_count == 2


# ═══════════════════════════════════════════════════════════════════
# 3. Protocol / Interface Tests
# ═══════════════════════════════════════════════════════════════════


class TestProtocolInterfaces:
    """Verify Protocol classes are importable and runtime-checkable."""

    def test_all_protocols_importable(self):
        from core.interfaces import (
            CredentialStoreProtocol,
            ExecutionEngineProtocol,
            HealthCheckerProtocol,
            LLMClientProtocol,
            LLMEngineProtocol,
            ReportGeneratorProtocol,
            ToolRegistryProtocol,
        )

        assert all(
            p is not None
            for p in [
                LLMEngineProtocol,
                ExecutionEngineProtocol,
                ReportGeneratorProtocol,
                ToolRegistryProtocol,
                LLMClientProtocol,
                CredentialStoreProtocol,
                HealthCheckerProtocol,
            ]
        )

    def test_llm_engine_satisfies_protocol(self):
        from core.interfaces import LLMEngineProtocol
        from core.llm.llm_engine import LLMEngine

        engine = LLMEngine(
            llm_client=MagicMock(),
            enable_rag=False,
            enable_validation=False,
            enable_token_management=False,
            enable_cache=False,
        )
        assert isinstance(engine, LLMEngineProtocol)

    def test_report_generator_satisfies_protocol(self):
        from core.interfaces import ReportGeneratorProtocol
        from modules.report_generator import ReportGenerator

        rg = ReportGenerator()
        assert isinstance(rg, ReportGeneratorProtocol)

    def test_mock_satisfies_llm_client_protocol(self):
        from core.interfaces import LLMClientProtocol

        class FakeLLM:
            def query(self, prompt, system_prompt="", *, timeout=30):
                return "ok"

        assert isinstance(FakeLLM(), LLMClientProtocol)

    def test_mock_satisfies_credential_store_protocol(self):
        from core.interfaces import CredentialStoreProtocol

        class FakeStore:
            def get(self, key):
                return None

            def set(self, key, value):
                return True

            def delete(self, key):
                return True

        assert isinstance(FakeStore(), CredentialStoreProtocol)

    def test_mock_satisfies_health_checker_protocol(self):
        from core.interfaces import HealthCheckerProtocol

        class FakeHealth:
            def check(self):
                return {}

            def readiness(self):
                return True

        assert isinstance(FakeHealth(), HealthCheckerProtocol)


# ═══════════════════════════════════════════════════════════════════
# 4. Report Template Enhancement Tests
# ═══════════════════════════════════════════════════════════════════


class TestReportTemplateEnhancements:
    """Verify evidence_artifacts, cvss_vector, methodology rendering."""

    def _make_generator(self, include_methodology=True):
        from modules.report_generator import (
            Finding,
            FindingSeverity,
            ReportConfig,
            ReportGenerator,
        )

        config = ReportConfig(
            include_methodology=include_methodology,
            use_llm_summary=False,
        )
        rg = ReportGenerator(config=config)
        rg.set_target("10.0.0.1")
        rg.start_assessment()
        rg.add_finding(
            Finding(
                title="SQL Injection",
                severity=FindingSeverity.CRITICAL,
                description="Blind SQL injection in login form",
                affected_asset="https://target.com/login",
                evidence="sqlmap output: injectable",
                remediation="Use parameterized queries",
                cve_id="CVE-2024-1234",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                evidence_artifacts=[
                    "POST /login HTTP/1.1\nuser=admin'--",
                    "HTTP/1.1 200 OK\nWelcome admin",
                ],
            )
        )
        rg.end_assessment()
        return rg

    def test_html_contains_cvss_vector(self):
        rg = self._make_generator()
        html = rg._generate_html()
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in html

    def test_html_contains_evidence_artifacts(self):
        rg = self._make_generator()
        html = rg._generate_html()
        assert "Evidence Artifacts" in html
        assert "POST /login HTTP/1.1" in html
        assert "Welcome admin" in html

    def test_html_contains_methodology(self):
        rg = self._make_generator(include_methodology=True)
        html = rg._generate_html()
        assert "Assessment Methodology" in html
        assert "OWASP Testing Guide" in html
        assert "PTES" in html

    def test_html_no_methodology_when_disabled(self):
        rg = self._make_generator(include_methodology=False)
        html = rg._generate_html()
        assert "Assessment Methodology" not in html

    def test_markdown_contains_cvss_vector(self):
        rg = self._make_generator()
        md = rg._generate_markdown()
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in md

    def test_markdown_contains_evidence_artifacts(self):
        rg = self._make_generator()
        md = rg._generate_markdown()
        assert "Evidence Artifacts" in md
        assert "POST /login HTTP/1.1" in md

    def test_markdown_contains_methodology(self):
        rg = self._make_generator(include_methodology=True)
        md = rg._generate_markdown()
        assert "Assessment Methodology" in md
        assert "OWASP" in md

    def test_markdown_no_methodology_when_disabled(self):
        rg = self._make_generator(include_methodology=False)
        md = rg._generate_markdown()
        assert "Assessment Methodology" not in md

    def test_finding_without_cve_but_with_vector(self):
        """cvss_vector alone (no CVE) should still render."""
        from modules.report_generator import (
            Finding,
            FindingSeverity,
            ReportConfig,
            ReportGenerator,
        )

        rg = ReportGenerator(ReportConfig(include_methodology=False, use_llm_summary=False))
        rg.set_target("10.0.0.1")
        rg.start_assessment()
        rg.add_finding(
            Finding(
                title="Weak Cipher",
                severity=FindingSeverity.MEDIUM,
                description="TLS 1.0 supported",
                affected_asset="10.0.0.1:443",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            )
        )
        rg.end_assessment()

        html = rg._generate_html()
        assert "CVSS Vector" in html
        assert "CVSS:3.1/AV:N/AC:H" in html


# ═══════════════════════════════════════════════════════════════════
# 5. Docker / CI Validation Tests
# ═══════════════════════════════════════════════════════════════════


class TestDockerAndCIConfig:
    """Validate docker-compose and CI configuration files."""

    def test_docker_compose_has_healthcheck(self):
        from pathlib import Path

        content = Path("docker-compose.yml").read_text(encoding="utf-8")
        assert "healthcheck:" in content
        assert "interval:" in content
        assert "retries:" in content

    def test_docker_compose_has_resource_limits(self):
        from pathlib import Path

        content = Path("docker-compose.yml").read_text(encoding="utf-8")
        assert "limits:" in content
        assert "memory:" in content
        assert "cpus:" in content

    def test_ci_has_coverage_gate(self):
        from pathlib import Path

        content = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        assert "--cov-fail-under=" in content

    def test_ci_no_continue_on_error_for_mypy(self):
        from pathlib import Path

        lines = Path(".github/workflows/ci.yml").read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if "Mypy type check" in line:
                context = "\n".join(lines[i : i + 5])
                assert "continue-on-error" not in context
                break

    def test_ci_bandit_no_silent_fail(self):
        from pathlib import Path

        content = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        assert "bandit" in content
        # "|| true" should NOT be present after bandit line
        for line in content.splitlines():
            if "bandit" in line.lower() and "-r core/" in line:
                assert "|| true" not in line

    def test_ci_has_sonarcloud_step(self):
        from pathlib import Path

        content = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        assert "SonarCloud Scan" in content or "sonarqube-scan-action" in content

    def test_requirements_has_pytest_cov(self):
        from pathlib import Path

        content = Path("requirements.txt").read_text(encoding="utf-8")
        assert "pytest-cov" in content

    def test_requirements_has_hypothesis(self):
        from pathlib import Path

        content = Path("requirements.txt").read_text(encoding="utf-8")
        assert "hypothesis" in content
