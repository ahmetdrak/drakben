# modules/report_generator.py
# DRAKBEN Report Generator - PDF/HTML/Markdown/JSON Export
# Professional penetration test report generation

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

# Third-party for PDF (Optional)
try:
    import os
    from contextlib import redirect_stderr, redirect_stdout

    # Silence WeasyPrint noise on import (especially on Windows)
    with open(os.devnull, "w") as fnull:
        with redirect_stderr(fnull), redirect_stdout(fnull):
            from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False

from core.agent.state import AgentState

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats."""

    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    PDF = "pdf"


class FindingSeverity(Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Security finding data structure."""

    title: str
    severity: FindingSeverity
    description: str
    affected_asset: str
    evidence: str = ""
    remediation: str = ""
    cve_id: str | None = None
    cvss_score: float | None = None
    references: list[str] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)  # Paths to screenshot files

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "affected_asset": self.affected_asset,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "references": self.references,
            "screenshots": self.screenshots,
        }


@dataclass
class ScanResult:
    """Scan result data structure."""

    target: str
    scan_type: str
    timestamp: str
    duration_seconds: float
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    tool_used: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output": self.raw_output,
            "tool_used": self.tool_used,
        }


@dataclass
class ReportConfig:
    """Report configuration."""

    title: str = "DRAKBEN Penetration Test Report"
    author: str = "DRAKBEN AI Framework"
    company: str = ""
    logo_path: str | None = None
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_raw_output: bool = False
    include_statistics: bool = True
    use_llm_summary: bool = False
    classification: str = "CONFIDENTIAL"


class ReportGenerator:
    """Professional penetration test report generator.

    Features:
    - Multiple output formats (HTML, Markdown, JSON, PDF)
    - Executive summary generation
    - Finding categorization and statistics
    - Evidence and remediation sections
    - Professional styling
    """

    def __init__(self, config: ReportConfig | None = None) -> None:
        """Initialize report generator.

        Args:
            config: Report configuration

        """
        self.config = config or ReportConfig()
        self.findings: list[Finding] = []
        self.scan_results: list[ScanResult] = []
        self.target: str = ""
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        logger.info("ReportGenerator initialized")

    def set_target(self, target: str) -> None:
        """Set target for the report."""
        self.target = target
        logger.info("Report target set: %s", target)

    def start_assessment(self) -> None:
        """Mark assessment start time."""
        self.start_time = datetime.now()
        logger.info("Assessment started")

    def end_assessment(self) -> None:
        """Mark assessment end time."""
        self.end_time = datetime.now()
        logger.info("Assessment ended")

    def add_finding(self, finding: Finding) -> None:
        """Add a security finding."""
        self.findings.append(finding)
        logger.info("Finding added: %s (%s)", finding.title, finding.severity.value)

    def add_scan_result(self, result: ScanResult) -> None:
        """Add a scan result."""
        self.scan_results.append(result)
        self.findings.extend(result.findings)
        logger.info("Scan result added: %s", result.scan_type)

    def get_statistics(self) -> dict[str, Any]:
        """Calculate finding statistics."""
        severity_counts = {s.value: 0 for s in FindingSeverity}
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1

        total = len(self.findings)
        risk_score = (
            severity_counts["critical"] * 10
            + severity_counts["high"] * 7
            + severity_counts["medium"] * 4
            + severity_counts["low"] * 1
        )

        # Normalize risk score (0-100)
        max_possible = total * 10 if total > 0 else 1
        normalized_risk = min(100, int((risk_score / max_possible) * 100))

        return {
            "total_findings": total,
            "severity_breakdown": severity_counts,
            "risk_score": normalized_risk,
            "scans_performed": len(self.scan_results),
            "assessment_duration": self._get_duration(),
        }

    def _get_duration(self) -> str:
        """Get assessment duration string."""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{hours}h {minutes}m {seconds}s"
        return "N/A"

    def generate(self, format: ReportFormat, output_path: str) -> str:
        """Generate report in specified format.

        Args:
            format: Output format
            output_path: Output file path

        Returns:
            Path to generated report

        """
        logger.info("Generating %s report: %s", format.value, output_path)

        if format == ReportFormat.HTML:
            content = self._generate_html()
        elif format == ReportFormat.MARKDOWN:
            content = self._generate_markdown()
        elif format == ReportFormat.JSON:
            content = self._generate_json()
        elif format == ReportFormat.PDF:
            return self._generate_pdf(output_path)
        else:
            msg = f"Unsupported format: {format}"
            raise ValueError(msg)

        # Text-based formats (HTML, Markdown, JSON)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
            logger.info("Report saved: %s", output_path)
            return output_path
        except PermissionError as e:
            logger.exception("Permission denied writing report to %s: %s", output_path, e)
            raise
        except OSError as e:
            logger.exception("OS error writing report to %s: %s", output_path, e)
            raise

    def _generate_html(self) -> str:
        """Generate HTML report with Chart.js visualization."""
        stats = self.get_statistics()
        findings_html = self._build_findings_list_html()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config.title}</title>
    <!-- Chart.js for Visual Analytics -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500&display=swap');

        :root {{
            --bg-primary: #0f111a;
            --bg-secondary: #1a1e2e;
            --text-primary: #e0e6ed;
            --text-secondary: #94a3b8;
            --accent: #7c3aed; /* Drakben Purple */
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #d97706;
            --low: #22c55e;
            --info: #3b82f6;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid var(--accent);
            margin-bottom: 40px;
        }}

        .header h1 {{
            color: var(--accent);
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .classification {{
            background: var(--critical);
            color: white;
            padding: 5px 20px;
            display: inline-block;
            font-weight: bold;
            margin-top: 10px;
        }}

        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}

        .meta-card {{
            background: var(--bg-secondary);
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid var(--accent);
        }}

        .meta-card h3 {{
            color: var(--accent);
            margin-bottom: 5px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 30px 0;
        }}

        .stat-card {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: var(--bg-secondary);
        }}

        .stat-card.critical {{ border-top: 4px solid var(--critical); }}
        .stat-card.high {{ border-top: 4px solid var(--high); }}
        .stat-card.medium {{ border-top: 4px solid var(--medium); }}
        .stat-card.low {{ border-top: 4px solid var(--low); }}
        .stat-card.info {{ border-top: 4px solid var(--info); }}

        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
        }}

        .stat-card.critical .stat-number {{ color: var(--critical); }}
        .stat-card.high .stat-number {{ color: var(--high); }}
        .stat-card.medium .stat-number {{ color: var(--medium); }}
        .stat-card.low .stat-number {{ color: var(--low); }}
        .stat-card.info .stat-number {{ color: var(--info); }}

        .section {{
            margin: 40px 0;
        }}

        .section h2 {{
            color: var(--accent);
            border-bottom: 1px solid var(--accent);
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}

        .risk-meter {{
            width: 100%;
            height: 30px;
            background: linear-gradient(to right, var(--low), var(--medium), var(--high), var(--critical));
            border-radius: 15px;
            position: relative;
            margin: 20px 0;
        }}

        .risk-indicator {{
            position: absolute;
            top: -5px;
            width: 4px;
            height: 40px;
            background: white;
            border-radius: 2px;
        }}

        .finding {{
            background: var(--bg-secondary);
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
        }}

        .finding-header {{
            padding: 15px 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            cursor: pointer;
        }}

        .finding-number {{
            color: var(--text-secondary);
            font-weight: bold;
        }}

        .finding-title {{
            flex: 1;
            font-weight: bold;
        }}

        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}

        .severity-badge.severity-critical {{ background: var(--critical); }}
        .severity-badge.severity-high {{ background: var(--high); color: #1a1a2e; }}
        .severity-badge.severity-medium {{ background: var(--medium); color: #1a1a2e; }}
        .severity-badge.severity-low {{ background: var(--low); color: #1a1a2e; }}
        .severity-badge.severity-info {{ background: var(--info); color: #1a1a2e; }}

        .finding-body {{
            padding: 20px;
            display: none; /* Hidden by default */
        }}

        .finding.active .finding-body {{ display: block; }}
        .toggle-icon {{ transition: transform 0.3s; }}
        .finding.active .toggle-icon {{ transform: rotate(180deg); }}

        .finding-body p {{
            margin: 10px 0;
        }}

        .evidence {{
            background: #0d1117;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }}

        .evidence pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Consolas', monospace;
            font-size: 0.9em;
            color: var(--info);
        }}

        .footer {{
            text-align: center;
            padding: 40px 0;
            border-top: 1px solid var(--bg-secondary);
            margin-top: 40px;
            color: var(--text-secondary);
        }}

        .executive-summary {{
            background: var(--bg-secondary);
            padding: 30px;
            border-radius: 8px;
            border-left: 4px solid var(--accent);
        }}

        @media print {{
            body {{ background: white; color: black; }}
            .finding {{ break-inside: avoid; }}
            .finding-body {{ display: block !important; }}
            .chart-container {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Section -->
        <div class="header">
            <h1>{self.config.title}</h1>
            <p>{self.config.author}</p>
            <div class="classification">{self.config.classification}</div>
        </div>

        <!-- Meta Info Grid -->
        <div class="meta-info">
            <div class="meta-card">
                <h3>Target</h3>
                <p>{self.target}</p>
            </div>
            <div class="meta-card">
                <h3>Date</h3>
                <p>{self.start_time.strftime("%Y-%m-%d") if self.start_time else "N/A"}</p>
            </div>
            <div class="meta-card">
                <h3>Duration</h3>
                <p>{stats["assessment_duration"]}</p>
            </div>
            <div class="meta-card">
                <h3>Findings</h3>
                <p>{stats["total_findings"]}</p>
            </div>
        </div>

        <!-- Findings Summary & Charts -->
        <div class="section">
            <h2>Findings Summary</h2>
            <div style="display: flex; gap: 40px; align-items: center; justify-content: center; flex-wrap: wrap;">
                <div style="flex: 1; max-width: 400px; min-width: 300px;">
                     <canvas id="severityChart"></canvas>
                </div>
                <div style="flex: 1; min-width: 300px;">
                     <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));">
                        <div class="stat-card critical"><div class="stat-number">{stats["severity_breakdown"]["critical"]}</div><div>Critical</div></div>
                        <div class="stat-card high"><div class="stat-number">{stats["severity_breakdown"]["high"]}</div><div>High</div></div>
                        <div class="stat-card medium"><div class="stat-number">{stats["severity_breakdown"]["medium"]}</div><div>Medium</div></div>
                        <div class="stat-card low"><div class="stat-number">{stats["severity_breakdown"]["low"]}</div><div>Low</div></div>
                        <div class="stat-card info"><div class="stat-number">{stats["severity_breakdown"]["info"]}</div><div>Info</div></div>
                     </div>
                </div>
            </div>

            <h3 style="margin-top:20px;">Overall Risk Score: {stats["risk_score"]}/100</h3>
            <div class="risk-meter">
                <div class="risk-indicator" style="left: {stats["risk_score"]}%;"></div>
            </div>
        </div>

        {self._generate_executive_summary_html(stats) if self.config.include_executive_summary else ""}

        <div class="section">
            <h2>Detailed Findings (Click to Expand)</h2>
            {findings_html if findings_html else "<p>No findings recorded.</p>"}
        </div>

        <div class="footer">
            <p>Generated by DRAKBEN AI Framework</p>
            <p>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>

    <script>
        // Chart.js Configuration
        const ctx = document.getElementById('severityChart').getContext('2d');
        const severityChart = new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [
                        {stats["severity_breakdown"]["critical"]},
                        {stats["severity_breakdown"]["high"]},
                        {stats["severity_breakdown"]["medium"]},
                        {stats["severity_breakdown"]["low"]},
                        {stats["severity_breakdown"]["info"]}
                    ],
                    backgroundColor: [
                        '#ff5555', // Critical
                        '#ff79c6', // High
                        '#ffb86c', // Medium
                        '#50fa7b', // Low
                        '#8be9fd'  // Info
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{ color: '#eee' }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

    def _build_finding_body_html(self, finding: "Finding") -> str:
        """Build the HTML body content for a single finding."""
        body = (
            f"<p><strong>Affected Asset:</strong> {finding.affected_asset}</p>"
            f"<p><strong>Description:</strong> {finding.description}</p>"
        )
        if finding.cve_id:
            body += f"<p><strong>CVE:</strong> {finding.cve_id} (CVSS: {finding.cvss_score})</p>"
        if finding.evidence:
            body += f'<div class="evidence"><strong>Evidence:</strong><pre>{finding.evidence}</pre></div>'
        if finding.screenshots:
            body += self._build_screenshots_html(finding.screenshots)
        if finding.remediation:
            body += f"<p><strong>Remediation:</strong> {finding.remediation}</p>"
        return body

    def _build_screenshots_html(self, screenshots: list[str]) -> str:
        """Build HTML for embedded screenshot images."""
        import base64

        html = '<div class="screenshots"><strong>Screenshots:</strong><br>'
        for ss_path in screenshots:
            try:
                ss_file = Path(ss_path)
                if ss_file.exists():
                    data = base64.b64encode(ss_file.read_bytes()).decode()
                    ext = ss_file.suffix.lower().lstrip(".")
                    mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif"}.get(ext, "image/png")
                    html += f'<img src="data:{mime};base64,{data}" style="max-width:100%;margin:8px 0;border:1px solid #444;border-radius:4px;" alt="{ss_file.name}"><br>'
            except Exception:
                html += f'<p style="color:#666;">[Screenshot: {ss_path}]</p>'
        html += "</div>"
        return html

    def _build_findings_list_html(self) -> str:
        """Build HTML for all findings sorted by severity."""
        sorted_findings = sorted(
            self.findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(
                f.severity.value,
            ),
        )

        findings_html = ""
        for i, finding in enumerate(sorted_findings, 1):
            severity_class = f"severity-{finding.severity.value}"
            finding_body = self._build_finding_body_html(finding)
            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header" onclick="this.parentElement.classList.toggle('active')">
                    <span class="finding-number">#{i}</span>
                    <span class="finding-title">{finding.title}</span>
                    <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                    <span class="toggle-icon">&#9660;</span>
                </div>
                <div class="finding-body">
                    {finding_body}
                </div>
            </div>
            """
        return findings_html

    def _generate_executive_summary_html(self, stats: dict[str, Any]) -> str:
        """Generate executive summary section with Optional AI Insight."""
        total = stats["total_findings"]
        critical = stats["severity_breakdown"]["critical"]
        high = stats["severity_breakdown"]["high"]

        risk_level = "LOW"
        if stats["risk_score"] >= 70:
            risk_level = "CRITICAL"
        elif stats["risk_score"] >= 50:
            risk_level = "HIGH"
        elif stats["risk_score"] >= 30:
            risk_level = "MEDIUM"

        # AI Insight Generation (Simulated for C-Level)
        ai_content = ""
        if self.config.use_llm_summary:
            ai_content = self._generate_ai_insight(critical, high, stats["risk_score"])

        return f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="executive-summary">
                <p>A penetration test was conducted against <strong>{self.target}</strong>
                to identify security vulnerabilities and assess the overall security posture.</p>

                <p>The assessment identified <strong>{total} security findings</strong>,
                including <strong>{critical} critical</strong> and <strong>{high} high</strong> severity issues.</p>

                <p>The overall risk level is assessed as <strong>{risk_level}</strong>
                with a risk score of <strong>{stats["risk_score"]}/100</strong>.</p>

                {ai_content}

                <p><strong>Key Recommendations:</strong></p>
                <ul>
                    <li>Address all critical and high severity findings immediately</li>
                    <li>Implement regular security assessments</li>
                    <li>Review and update security policies</li>
                    <li>Conduct security awareness training</li>
                </ul>
            </div>
        </div>
        """

    def _generate_ai_insight(self, critical: int, high: int, risk: int) -> str:
        """Generate C-Level insight via LLM with rule-based fallback.

        Attempts to use the configured LLM (OpenRouter/Ollama) for a real
        strategic analysis.  Falls back to template text when the LLM is
        unavailable or the call fails.
        """
        # --- Try real LLM first ---
        try:
            from llm.openrouter_client import OpenRouterClient

            client = OpenRouterClient()
            prompt = (
                f"You are a senior cybersecurity consultant writing a 3-sentence "
                f"executive summary for a penetration test report.\n\n"
                f"Stats: {critical} critical, {high} high-severity findings.  "
                f"Overall risk score: {risk}/100.\n\n"
                f"Provide a concise, C-Level friendly strategic recommendation. "
                f"Do NOT use markdown. Plain text only."
            )
            llm_text = client.query(
                prompt=prompt,
                system_prompt="You are a concise security analyst.",
                timeout=15,
            )
            if llm_text and len(llm_text.strip()) > 20:
                insight = (
                    "<div style='margin-top: 15px; padding: 10px; "
                    "background-color: #2a2a40; border-left: 3px solid #bd93f9;'>"
                    "<strong>🤖 AI Strategic Analysis (C-Level):</strong><br>"
                    f"{llm_text.strip()}</div>"
                )
                return insight
        except Exception:
            logger.debug("LLM insight unavailable, using rule-based fallback")

        # --- Rule-based fallback ---
        insight = (
            "<div style='margin-top: 15px; padding: 10px; "
            "background-color: #2a2a40; border-left: 3px solid #bd93f9;'>"
            "<strong>🤖 AI Strategic Analysis (C-Level):</strong><br>"
        )

        if risk > 80:
            insight += (
                "Detected vulnerabilities pose an <em>imminent threat</em> to business continuity. "
                "Immediate resource allocation is required to mitigate potential data breaches and regulatory fines. "
                "<strong>Recommendation:</strong> Freeze feature development and focus engineering teams on remediation."
            )
        elif risk > 50:
            insight += (
                "Security posture is compromised with significant risks reachable from external networks. "
                "Potential for lateral movement is high. "
                "<strong>Recommendation:</strong> Schedule emergency maintenance window within 48 hours."
            )
        else:
            insight += (
                "Security posture is generally robust, though some hygiene issues remain. "
                "<strong>Recommendation:</strong> Incorporate fixes into the next scheduled sprint."
            )

        insight += "</div>"
        return insight

    def _generate_markdown(self) -> str:
        """Generate Markdown report."""
        stats = self.get_statistics()

        md = f"""# {self.config.title}

**Classification:** {self.config.classification}
**Author:** {self.config.author}
**Date:** {self.start_time.strftime("%Y-%m-%d") if self.start_time else "N/A"}

---

## Target Information

- **Target:** {self.target}
- **Assessment Duration:** {stats["assessment_duration"]}
- **Total Findings:** {stats["total_findings"]}

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {stats["severity_breakdown"]["critical"]} |
| High | {stats["severity_breakdown"]["high"]} |
| Medium | {stats["severity_breakdown"]["medium"]} |
| Low | {stats["severity_breakdown"]["low"]} |
| Info | {stats["severity_breakdown"]["info"]} |

**Risk Score:** {stats["risk_score"]}/100

---

## Executive Summary

A penetration test was conducted against **{self.target}** to identify security vulnerabilities.

The assessment identified **{stats["total_findings"]} findings**, including:
- {stats["severity_breakdown"]["critical"]} Critical
- {stats["severity_breakdown"]["high"]} High
- {stats["severity_breakdown"]["medium"]} Medium

---

## Detailed Findings

"""

        sorted_findings = sorted(
            self.findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(
                f.severity.value,
            ),
        )

        for i, finding in enumerate(sorted_findings, 1):
            md += f"""### {i}. {finding.title}

**Severity:** {finding.severity.value.upper()}
**Affected Asset:** {finding.affected_asset}

**Description:**
{finding.description}

"""
            if finding.cve_id:
                md += f"**CVE:** {finding.cve_id} (CVSS: {finding.cvss_score})\n\n"

            if finding.evidence:
                md += f"""**Evidence:**
```
{finding.evidence}
```

"""

            if finding.remediation:
                md += f"**Remediation:**  \n{finding.remediation}\n\n"

            md += "---\n\n"

        md += f"""
## Report Information

- Generated by: DRAKBEN AI Framework
- Generated at: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

        return md

    def _generate_json(self) -> str:
        """Generate JSON report."""
        stats = self.get_statistics()

        report = {
            "metadata": {
                "title": self.config.title,
                "author": self.config.author,
                "classification": self.config.classification,
                "generated_at": datetime.now().isoformat(),
                "target": self.target,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
            },
            "statistics": stats,
            "findings": [f.to_dict() for f in self.findings],
            "scan_results": [r.to_dict() for r in self.scan_results],
        }

        return json.dumps(report, indent=2, ensure_ascii=False)

    def _generate_pdf(self, output_path: str) -> str:
        """Generate PDF report.
        Falls back to HTML if weasyprint is not available.
        """
        html_content = self._generate_html()

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        if WEASYPRINT_AVAILABLE:
            try:
                HTML(string=html_content).write_pdf(output_path)
                logger.info("PDF Report saved: %s", output_path)
                return output_path
            except Exception as e:
                logger.exception("PDF generation error: %s", e)
                # Fallback to HTML
                html_path = output_path.replace(".pdf", ".html")
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                logger.warning("Fallback: Saved as HTML to %s", html_path)
                return html_path
        else:
            logger.warning("WeasyPrint not installed. Saving as HTML.")
            html_path = output_path.replace(".pdf", ".html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            return html_path


@dataclass
class VulnerabilityData:
    """Mock for state vulnerability."""

    vuln_id: str
    severity: str
    description: str = ""
    target: str = ""


# Convenience functions for state integration
def generate_report_from_state(
    state: AgentState,
    output_path: str,
    format: ReportFormat = ReportFormat.HTML,
    config: ReportConfig | None = None,
) -> str:
    """Generate full report from AgentState.

    Args:
        state: AgentState instance
        output_path: Where to save the report
        format: Output format
        config: Optional report configuration

    Returns:
        Path to generated report

    """
    generator = ReportGenerator(config=config)
    generator.set_target(state.target if hasattr(state, "target") else "Unknown")

    # Time tracking
    generator.start_assessment()
    generator.end_assessment()

    # Import vulnerabilities
    if hasattr(state, "vulnerabilities") and state.vulnerabilities:
        for vuln in state.vulnerabilities:
            # Handle both dict and object
            v_data = vuln if isinstance(vuln, dict) else vuln.__dict__

            try:
                finding = Finding(
                    title=v_data.get("title") or v_data.get("vuln_id") or "Finding",
                    severity=FindingSeverity(v_data.get("severity", "info").lower()),
                    description=v_data.get("description", "No description."),
                    affected_asset=v_data.get("target", generator.target),
                    evidence=v_data.get("evidence", ""),
                    remediation=v_data.get("remediation", ""),
                    cve_id=v_data.get("cve_id"),
                    cvss_score=v_data.get("cvss_score"),
                )
                generator.add_finding(finding)
            except Exception as e:
                logger.debug("Skipping invalid finding: %s", e)

    return generator.generate(format, output_path)


def capture_screenshot(url: str, output_dir: str = "logs/screenshots") -> str | None:
    """Capture a screenshot of a web page.

    Tries multiple approaches:
    1. Playwright (headless Chromium)
    2. Selenium (headless Chrome)
    3. External cutycapt/wkhtmltoimage tool

    Args:
        url: URL to capture
        output_dir: Directory to save screenshots

    Returns:
        Path to saved screenshot file, or None on failure
    """
    import os
    import time
    from pathlib import Path

    os.makedirs(output_dir, exist_ok=True)
    timestamp = int(time.time())
    safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
    filename = f"{safe_name}_{timestamp}.png"
    filepath = str(Path(output_dir) / filename)

    # Attempt 1: Playwright
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=15000, wait_until="networkidle")
            page.screenshot(path=filepath, full_page=True)
            browser.close()
            logger.info("Screenshot captured (playwright): %s", filepath)
            return filepath
    except Exception:
        pass

    # Attempt 2: Selenium
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        driver.set_page_load_timeout(15)
        driver.get(url)
        driver.save_screenshot(filepath)
        driver.quit()
        logger.info("Screenshot captured (selenium): %s", filepath)
        return filepath
    except Exception:
        pass

    # Attempt 3: External tool
    try:
        import subprocess
        for tool_cmd in [
            ["cutycapt", f"--url={url}", f"--out={filepath}"],
            ["wkhtmltoimage", "--quiet", url, filepath],
        ]:
            try:
                subprocess.run(tool_cmd, timeout=15, capture_output=True, check=True)
                if Path(filepath).exists():
                    logger.info("Screenshot captured (%s): %s", tool_cmd[0], filepath)
                    return filepath
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
    except Exception:
        pass

    logger.debug("Screenshot capture failed for %s (no available backend)", url)
    return None


def create_report_from_state(state: AgentState, output_dir: str = "reports") -> str:
    """Legacy wrapper for simplified report generation."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"drakben_report_{timestamp}.html"
    filepath = str(Path(output_dir) / filename)
    return generate_report_from_state(state, filepath)
