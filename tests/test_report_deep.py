"""Deep coverage tests for modules/report_generator.py.

Covers: Finding, ScanResult, ReportConfig, ReportGenerator
        (statistics, generate HTML/MD/JSON, executive summary, AI insight).
"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.report_generator import (
    Finding,
    FindingSeverity,
    ReportConfig,
    ReportFormat,
    ReportGenerator,
    ScanResult,
)


# ---------------------------------------------------------------------------
# 1. Finding
# ---------------------------------------------------------------------------
class TestFinding:
    def test_create_basic(self):
        f = Finding(
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            description="Parameter id is vulnerable",
            affected_asset="10.0.0.1:80/login",
        )
        assert f.title == "SQL Injection"
        assert f.severity == FindingSeverity.CRITICAL

    def test_to_dict(self):
        f = Finding(
            title="XSS",
            severity=FindingSeverity.HIGH,
            description="Reflected XSS",
            affected_asset="http://target/search",
            evidence="<script>alert(1)</script>",
            cve_id="CVE-2024-1234",
            cvss_score=7.5,
            references=["https://cve.mitre.org"],
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["cvss_score"] == pytest.approx(7.5)
        assert len(d["references"]) == 1

    def test_defaults(self):
        f = Finding(
            title="Info",
            severity=FindingSeverity.INFO,
            description="Port 80 open",
            affected_asset="10.0.0.1",
        )
        assert f.evidence == ""
        assert f.cve_id is None
        assert f.screenshots == []
        assert f.references == []


# ---------------------------------------------------------------------------
# 2. ScanResult
# ---------------------------------------------------------------------------
class TestScanResult:
    def test_create(self):
        sr = ScanResult(
            target="10.0.0.1",
            scan_type="port_scan",
            timestamp="2024-01-01T00:00:00",
            duration_seconds=60.5,
            tool_used="nmap",
        )
        assert sr.target == "10.0.0.1"
        assert sr.duration_seconds == pytest.approx(60.5)

    def test_to_dict_with_findings(self):
        f = Finding(
            title="Open SSH",
            severity=FindingSeverity.LOW,
            description="SSH on port 22",
            affected_asset="10.0.0.1:22",
        )
        sr = ScanResult(
            target="10.0.0.1",
            scan_type="port_scan",
            timestamp="2024-01-01",
            duration_seconds=30,
            findings=[f],
        )
        d = sr.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["title"] == "Open SSH"


# ---------------------------------------------------------------------------
# 3. ReportConfig
# ---------------------------------------------------------------------------
class TestReportConfig:
    def test_defaults(self):
        cfg = ReportConfig()
        assert cfg.title == "DRAKBEN Penetration Test Report"
        assert cfg.classification == "CONFIDENTIAL"
        assert cfg.include_executive_summary is True
        assert cfg.use_llm_summary is False

    def test_custom(self):
        cfg = ReportConfig(title="Custom Report", author="Tester", company="ACME")
        assert cfg.title == "Custom Report"
        assert cfg.company == "ACME"


# ---------------------------------------------------------------------------
# 4. ReportFormat
# ---------------------------------------------------------------------------
class TestReportFormat:
    def test_values(self):
        assert ReportFormat.HTML.value == "html"
        assert ReportFormat.MARKDOWN.value == "markdown"
        assert ReportFormat.JSON.value == "json"
        assert ReportFormat.PDF.value == "pdf"


# ---------------------------------------------------------------------------
# 5. ReportGenerator — core methods
# ---------------------------------------------------------------------------
class TestReportGeneratorBasics:
    def test_init_defaults(self):
        rg = ReportGenerator()
        assert rg.findings == []
        assert rg.scan_results == []
        assert rg.target == ""

    def test_set_target(self):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        assert rg.target == "10.0.0.1"

    def test_start_end_assessment(self):
        rg = ReportGenerator()
        rg.start_assessment()
        assert rg.start_time is not None
        rg.end_assessment()
        assert rg.end_time is not None

    def test_add_finding(self):
        rg = ReportGenerator()
        f = Finding("Test", FindingSeverity.LOW, "desc", "asset")
        rg.add_finding(f)
        assert len(rg.findings) == 1

    def test_add_scan_result(self):
        rg = ReportGenerator()
        f = Finding("Test", FindingSeverity.MEDIUM, "desc", "asset")
        sr = ScanResult("10.0.0.1", "nmap", "2024-01-01", 10.0, findings=[f])
        rg.add_scan_result(sr)
        assert len(rg.scan_results) == 1
        assert len(rg.findings) == 1  # Finding from scan result also added


# ---------------------------------------------------------------------------
# 6. Statistics
# ---------------------------------------------------------------------------
class TestReportStatistics:
    def test_empty_statistics(self):
        rg = ReportGenerator()
        stats = rg.get_statistics()
        assert stats["total_findings"] == 0
        assert stats["risk_score"] == 0
        assert stats["scans_performed"] == 0

    def test_statistics_with_findings(self):
        rg = ReportGenerator()
        rg.add_finding(Finding("A", FindingSeverity.CRITICAL, "d", "a"))
        rg.add_finding(Finding("B", FindingSeverity.HIGH, "d", "a"))
        rg.add_finding(Finding("C", FindingSeverity.MEDIUM, "d", "a"))
        rg.add_finding(Finding("D", FindingSeverity.LOW, "d", "a"))
        rg.add_finding(Finding("E", FindingSeverity.INFO, "d", "a"))

        stats = rg.get_statistics()
        assert stats["total_findings"] == 5
        assert stats["severity_breakdown"]["critical"] == 1
        assert stats["severity_breakdown"]["high"] == 1
        assert stats["severity_breakdown"]["medium"] == 1
        assert stats["severity_breakdown"]["low"] == 1
        assert stats["severity_breakdown"]["info"] == 1
        assert stats["risk_score"] > 0

    def test_statistics_all_critical(self):
        rg = ReportGenerator()
        for i in range(5):
            rg.add_finding(Finding(f"Crit{i}", FindingSeverity.CRITICAL, "d", "a"))
        stats = rg.get_statistics()
        assert stats["risk_score"] == 100  # Max normalized

    def test_duration_string(self):
        rg = ReportGenerator()
        rg.start_time = datetime(2024, 1, 1, 10, 0, 0)
        rg.end_time = datetime(2024, 1, 1, 12, 30, 45)
        dur = rg._get_duration()
        assert dur == "2h 30m 45s"

    def test_duration_no_times(self):
        rg = ReportGenerator()
        assert rg._get_duration() == "N/A"


# ---------------------------------------------------------------------------
# 7. Generate HTML
# ---------------------------------------------------------------------------
class TestGenerateHTML:
    def test_generate_html_report(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        rg.start_assessment()
        rg.add_finding(Finding(
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            description="id param vulnerable",
            affected_asset="10.0.0.1/login",
            evidence="' OR 1=1--",
            remediation="Use parameterized queries",
            cve_id="CVE-2024-0001",
            cvss_score=9.8,
        ))
        rg.end_assessment()

        output = str(tmp_path / "report.html")
        result = rg.generate(ReportFormat.HTML, output)
        assert Path(result).exists()
        content = Path(result).read_text(encoding="utf-8")
        assert "SQL Injection" in content
        assert "10.0.0.1" in content
        assert "CVE-2024-0001" in content
        assert "chart.js" in content.lower() or "Chart" in content

    def test_html_no_findings(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        output = str(tmp_path / "empty.html")
        result = rg.generate(ReportFormat.HTML, output)
        content = Path(result).read_text(encoding="utf-8")
        assert "No findings" in content


# ---------------------------------------------------------------------------
# 8. Generate Markdown
# ---------------------------------------------------------------------------
class TestGenerateMarkdown:
    def test_generate_md_report(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        rg.add_finding(Finding(
            "XSS", FindingSeverity.HIGH, "Reflected XSS", "10.0.0.1/search",
            evidence="<script>alert(1)</script>",
            remediation="Sanitize user input",
        ))
        output = str(tmp_path / "report.md")
        result = rg.generate(ReportFormat.MARKDOWN, output)
        content = Path(result).read_text(encoding="utf-8")
        assert "# DRAKBEN" in content
        assert "XSS" in content
        assert "HIGH" in content
        assert "Remediation" in content

    def test_md_with_cve(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("target.com")
        rg.add_finding(Finding(
            "CVE Test", FindingSeverity.CRITICAL, "desc", "asset",
            cve_id="CVE-2024-9999", cvss_score=10.0,
        ))
        output = str(tmp_path / "report_cve.md")
        rg.generate(ReportFormat.MARKDOWN, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "CVE-2024-9999" in content


# ---------------------------------------------------------------------------
# 9. Generate JSON
# ---------------------------------------------------------------------------
class TestGenerateJSON:
    def test_generate_json_report(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        rg.add_finding(Finding("SSH Open", FindingSeverity.LOW, "Port 22", "10.0.0.1"))
        output = str(tmp_path / "report.json")
        result = rg.generate(ReportFormat.JSON, output)
        data = json.loads(Path(result).read_text(encoding="utf-8"))
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_json_round_trip(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("target.com")
        rg.add_finding(Finding(
            "Test", FindingSeverity.MEDIUM, "desc", "asset",
            references=["ref1", "ref2"],
        ))
        output = str(tmp_path / "report.json")
        rg.generate(ReportFormat.JSON, output)
        data = json.loads(Path(output).read_text(encoding="utf-8"))
        assert data["findings"][0]["references"] == ["ref1", "ref2"]


# ---------------------------------------------------------------------------
# 10. Executive Summary
# ---------------------------------------------------------------------------
class TestExecutiveSummary:
    def test_summary_html_generated(self, tmp_path):
        cfg = ReportConfig(include_executive_summary=True)
        rg = ReportGenerator(config=cfg)
        rg.set_target("10.0.0.1")
        rg.add_finding(Finding("A", FindingSeverity.CRITICAL, "d", "a"))
        output = str(tmp_path / "exec.html")
        rg.generate(ReportFormat.HTML, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "Executive Summary" in content

    def test_summary_risk_levels(self):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        # Test CRITICAL risk (score >= 70)
        for _ in range(10):
            rg.add_finding(Finding("C", FindingSeverity.CRITICAL, "d", "a"))
        stats = rg.get_statistics()
        summary = rg._generate_executive_summary_html(stats)
        assert "CRITICAL" in summary or "critical" in summary.lower()


# ---------------------------------------------------------------------------
# 11. AI Insight
# ---------------------------------------------------------------------------
class TestAIInsight:
    def test_rule_based_high_risk(self):
        rg = ReportGenerator()
        with patch("llm.openrouter_client.OpenRouterClient", side_effect=Exception("no llm")):
            insight = rg._generate_ai_insight(5, 3, 85)
        assert "imminent threat" in insight

    def test_rule_based_medium_risk(self):
        rg = ReportGenerator()
        with patch("llm.openrouter_client.OpenRouterClient", side_effect=Exception("no llm")):
            insight = rg._generate_ai_insight(1, 3, 55)
        assert "48 hours" in insight

    def test_rule_based_low_risk(self):
        rg = ReportGenerator()
        with patch("llm.openrouter_client.OpenRouterClient", side_effect=Exception("no llm")):
            insight = rg._generate_ai_insight(0, 0, 15)
        assert "robust" in insight

    def test_llm_insight_fallback(self):
        """When LLM import fails, should fall back to rules."""
        rg = ReportGenerator()
        with patch("llm.openrouter_client.OpenRouterClient", side_effect=ImportError):
            insight = rg._generate_ai_insight(2, 5, 60)
        assert "AI Strategic Analysis" in insight

    def test_llm_insight_success(self):
        """When LLM returns valid text, use it."""
        rg = ReportGenerator()
        mock_client = MagicMock()
        mock_client.query.return_value = "This is a real AI strategic recommendation for C-level executives."
        with patch("llm.openrouter_client.OpenRouterClient", return_value=mock_client):
            insight = rg._generate_ai_insight(3, 5, 70)
        assert "AI Strategic Analysis" in insight
        assert "C-level" in insight or "strategic" in insight.lower()


# ---------------------------------------------------------------------------
# 12. Multiple findings sorting
# ---------------------------------------------------------------------------
class TestFindingSorting:
    def test_html_sorts_by_severity(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        rg.add_finding(Finding("Low1", FindingSeverity.LOW, "d", "a"))
        rg.add_finding(Finding("Crit1", FindingSeverity.CRITICAL, "d", "a"))
        rg.add_finding(Finding("Med1", FindingSeverity.MEDIUM, "d", "a"))
        output = str(tmp_path / "sorted.html")
        rg.generate(ReportFormat.HTML, output)
        content = Path(output).read_text(encoding="utf-8")
        # Critical should appear before Low
        crit_pos = content.index("Crit1")
        low_pos = content.index("Low1")
        assert crit_pos < low_pos


# ---------------------------------------------------------------------------
# 13. Screenshot handling in HTML
# ---------------------------------------------------------------------------
class TestScreenshots:
    def test_screenshot_embedded(self, tmp_path):
        # Create a tiny PNG
        img_path = tmp_path / "screenshot.png"
        # Minimal 1x1 red PNG
        import base64
        png_data = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg=="
        )
        img_path.write_bytes(png_data)

        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        rg.add_finding(Finding(
            "With Screenshot",
            FindingSeverity.HIGH,
            "desc",
            "asset",
            screenshots=[str(img_path)],
        ))
        output = str(tmp_path / "screenshot.html")
        rg.generate(ReportFormat.HTML, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "data:image/png;base64," in content

    def test_missing_screenshot_graceful(self, tmp_path):
        rg = ReportGenerator()
        rg.set_target("10.0.0.1")
        rg.add_finding(Finding(
            "Missing SS",
            FindingSeverity.LOW,
            "desc",
            "asset",
            screenshots=["/nonexistent/path.png"],
        ))
        output = str(tmp_path / "no_ss.html")
        rg.generate(ReportFormat.HTML, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "Screenshot" in content or "nonexistent" in content


# ---------------------------------------------------------------------------
# 14. FindingSeverity enum
# ---------------------------------------------------------------------------
class TestFindingSeverity:
    def test_all_values(self):
        assert FindingSeverity.INFO.value == "info"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.CRITICAL.value == "critical"
