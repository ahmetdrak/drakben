# tests/test_report_generator.py
"""Comprehensive tests for modules/report_generator.py."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.report_generator import (
    Finding,
    FindingSeverity,
    ReportConfig,
    ReportFormat,
    ReportGenerator,
    ScanResult,
)

# ── Finding ────────────────────────────────────────────────────

class TestFinding:
    """Tests for the Finding dataclass."""

    def test_create_minimal(self) -> None:
        f = Finding(
            title="XSS Found",
            severity=FindingSeverity.HIGH,
            description="Reflected XSS",
            affected_asset="https://example.com/search",
        )
        assert f.title == "XSS Found"
        assert f.severity == FindingSeverity.HIGH
        assert f.evidence == ""
        assert f.cve_id is None
        assert f.screenshots == []

    def test_to_dict(self) -> None:
        f = Finding(
            title="SQLi",
            severity=FindingSeverity.CRITICAL,
            description="SQL injection in login",
            affected_asset="login.php",
            evidence="' OR 1=1 --",
            remediation="Use parameterized queries",
            cve_id="CVE-2024-1234",
            cvss_score=9.8,
            references=["https://owasp.org"],
            screenshots=["/tmp/ss.png"],
        )
        d = f.to_dict()
        assert d["severity"] == "critical"
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["cvss_score"] == pytest.approx(9.8)
        assert len(d["references"]) == 1
        assert len(d["screenshots"]) == 1

    def test_all_severity_levels(self) -> None:
        for sev in FindingSeverity:
            f = Finding(
                title="test", severity=sev,
                description="d", affected_asset="a",
            )
            assert f.to_dict()["severity"] == sev.value


# ── ScanResult ─────────────────────────────────────────────────

class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_create(self) -> None:
        sr = ScanResult(
            target="10.0.0.1",
            scan_type="nmap",
            timestamp="2025-01-01T00:00:00",
            duration_seconds=42.5,
        )
        assert sr.target == "10.0.0.1"
        assert sr.findings == []

    def test_to_dict(self) -> None:
        finding = Finding(
            title="Open SSH",
            severity=FindingSeverity.LOW,
            description="SSH open on port 22",
            affected_asset="10.0.0.1:22",
        )
        sr = ScanResult(
            target="10.0.0.1",
            scan_type="port_scan",
            timestamp="2025-01-01",
            duration_seconds=3.2,
            findings=[finding],
            raw_output="PORT 22 open",
            tool_used="nmap",
        )
        d = sr.to_dict()
        assert d["target"] == "10.0.0.1"
        assert len(d["findings"]) == 1
        assert d["tool_used"] == "nmap"

    def test_to_dict_empty(self) -> None:
        sr = ScanResult(
            target="x", scan_type="y",
            timestamp="z", duration_seconds=0,
        )
        d = sr.to_dict()
        assert d["findings"] == []
        assert d["raw_output"] == ""


# ── ReportConfig ───────────────────────────────────────────────

class TestReportConfig:
    """Tests for ReportConfig defaults."""

    def test_defaults(self) -> None:
        cfg = ReportConfig()
        assert cfg.title == "DRAKBEN Penetration Test Report"
        assert cfg.classification == "CONFIDENTIAL"
        assert cfg.include_executive_summary is True
        assert cfg.use_llm_summary is False

    def test_custom(self) -> None:
        cfg = ReportConfig(title="Custom", company="ACME", classification="SECRET")
        assert cfg.title == "Custom"
        assert cfg.company == "ACME"
        assert cfg.classification == "SECRET"


# ── ReportGenerator ────────────────────────────────────────────

class TestReportGenerator:
    """Tests for ReportGenerator class."""

    def _make_generator(self) -> ReportGenerator:
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        rg.start_assessment()
        rg.add_finding(
            Finding(
                title="Critical SQLi",
                severity=FindingSeverity.CRITICAL,
                description="SQL injection",
                affected_asset="login.php",
                evidence="test'",
            ),
        )
        rg.add_finding(
            Finding(
                title="Info Disclosure",
                severity=FindingSeverity.INFO,
                description="Server headers",
                affected_asset="headers",
            ),
        )
        rg.end_assessment()
        return rg

    def test_init_default(self) -> None:
        rg = ReportGenerator()
        assert rg.target == ""
        assert rg.findings == []
        assert rg.scan_results == []

    def test_set_target(self) -> None:
        rg = ReportGenerator()
        rg.set_target("example.com")
        assert rg.target == "example.com"

    def test_start_end_assessment(self) -> None:
        rg = ReportGenerator()
        rg.start_assessment()
        assert rg.start_time is not None
        rg.end_assessment()
        assert rg.end_time is not None

    def test_add_finding(self) -> None:
        rg = ReportGenerator()
        f = Finding(
            title="x", severity=FindingSeverity.MEDIUM,
            description="y", affected_asset="z",
        )
        rg.add_finding(f)
        assert len(rg.findings) == 1

    def test_add_scan_result(self) -> None:
        finding = Finding(
            title="x", severity=FindingSeverity.LOW,
            description="d", affected_asset="a",
        )
        sr = ScanResult(
            target="t", scan_type="s",
            timestamp="ts", duration_seconds=1.0,
            findings=[finding],
        )
        rg = ReportGenerator()
        rg.add_scan_result(sr)
        assert len(rg.scan_results) == 1
        # Findings from scan result are also added to rg.findings
        assert len(rg.findings) == 1

    def test_get_statistics_empty(self) -> None:
        rg = ReportGenerator()
        stats = rg.get_statistics()
        assert stats["total_findings"] == 0
        assert stats["risk_score"] == 0
        assert stats["scans_performed"] == 0

    def test_get_statistics_with_findings(self) -> None:
        rg = self._make_generator()
        stats = rg.get_statistics()
        assert stats["total_findings"] == 2
        assert stats["severity_breakdown"]["critical"] == 1
        assert stats["severity_breakdown"]["info"] == 1
        assert stats["risk_score"] > 0

    def test_risk_score_max_100(self) -> None:
        rg = ReportGenerator()
        for _ in range(20):
            rg.add_finding(
                Finding(
                    title="crit", severity=FindingSeverity.CRITICAL,
                    description="d", affected_asset="a",
                ),
            )
        stats = rg.get_statistics()
        assert stats["risk_score"] <= 100

    def test_generate_json(self) -> None:
        rg = self._make_generator()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            result_path = rg.generate(ReportFormat.JSON, path)
            assert Path(result_path).exists()
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            assert "findings" in data or "report" in data or isinstance(data, dict)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_generate_markdown(self) -> None:
        rg = self._make_generator()
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, mode="w") as f:
            path = f.name
        try:
            result_path = rg.generate(ReportFormat.MARKDOWN, path)
            assert Path(result_path).exists()
            content = Path(path).read_text(encoding="utf-8")
            assert len(content) > 100
        finally:
            Path(path).unlink(missing_ok=True)

    def test_generate_html(self) -> None:
        rg = self._make_generator()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            path = f.name
        try:
            result_path = rg.generate(ReportFormat.HTML, path)
            assert Path(result_path).exists()
            content = Path(path).read_text(encoding="utf-8")
            assert "<!DOCTYPE html>" in content
            assert "Critical SQLi" in content
        finally:
            Path(path).unlink(missing_ok=True)

    def test_generate_unsupported_format(self) -> None:
        rg = ReportGenerator()
        with pytest.raises(ValueError, match="Unsupported format"):
            rg.generate(MagicMock(value="xlsx"), "/tmp/out.xlsx")

    def test_assessment_duration_na(self) -> None:
        rg = ReportGenerator()
        assert rg._get_duration() == "N/A"

    def test_assessment_duration_computed(self) -> None:
        rg = ReportGenerator()
        rg.start_assessment()
        rg.end_assessment()
        duration = rg._get_duration()
        assert "h" in duration and "m" in duration and "s" in duration
