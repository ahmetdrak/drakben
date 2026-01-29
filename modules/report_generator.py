# modules/report_generator.py
# DRAKBEN Report Generator - PDF/HTML/Markdown/JSON Export
# Professional penetration test report generation

import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum

from core.state import AgentState

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats"""
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    PDF = "pdf"


class FindingSeverity(Enum):
    """Finding severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Security finding data structure"""
    title: str
    severity: FindingSeverity
    description: str
    affected_asset: str
    evidence: str = ""
    remediation: str = ""
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "affected_asset": self.affected_asset,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "references": self.references
        }


@dataclass
class ScanResult:
    """Scan result data structure"""
    target: str
    scan_type: str
    timestamp: str
    duration_seconds: float
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""
    tool_used: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output": self.raw_output,
            "tool_used": self.tool_used
        }


@dataclass
class ReportConfig:
    """Report configuration"""
    title: str = "DRAKBEN Penetration Test Report"
    author: str = "DRAKBEN AI Framework"
    company: str = ""
    logo_path: Optional[str] = None
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_raw_output: bool = False
    include_statistics: bool = True
    use_llm_summary: bool = False
    classification: str = "CONFIDENTIAL"


class ReportGenerator:
    """
    Professional penetration test report generator.
    
    Features:
    - Multiple output formats (HTML, Markdown, JSON, PDF)
    - Executive summary generation
    - Finding categorization and statistics
    - Evidence and remediation sections
    - Professional styling
    """
    
    def __init__(self, config: Optional[ReportConfig] = None):
        """
        Initialize report generator.
        
        Args:
            config: Report configuration
        """
        self.config = config or ReportConfig()
        self.findings: List[Finding] = []
        self.scan_results: List[ScanResult] = []
        self.target: str = ""
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        logger.info("ReportGenerator initialized")
    
    def set_target(self, target: str) -> None:
        """Set target for the report"""
        self.target = target
        logger.info(f"Report target set: {target}")
    
    def start_assessment(self) -> None:
        """Mark assessment start time"""
        self.start_time = datetime.now()
        logger.info("Assessment started")
    
    def end_assessment(self) -> None:
        """Mark assessment end time"""
        self.end_time = datetime.now()
        logger.info("Assessment ended")
    
    def add_finding(self, finding: Finding) -> None:
        """Add a security finding"""
        self.findings.append(finding)
        logger.info(f"Finding added: {finding.title} ({finding.severity.value})")
    
    def add_scan_result(self, result: ScanResult) -> None:
        """Add a scan result"""
        self.scan_results.append(result)
        self.findings.extend(result.findings)
        logger.info(f"Scan result added: {result.scan_type}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Calculate finding statistics"""
        severity_counts = {s.value: 0 for s in FindingSeverity}
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        
        total = len(self.findings)
        risk_score = (
            severity_counts["critical"] * 10 +
            severity_counts["high"] * 7 +
            severity_counts["medium"] * 4 +
            severity_counts["low"] * 1
        )
        
        # Normalize risk score (0-100)
        max_possible = total * 10 if total > 0 else 1
        normalized_risk = min(100, int((risk_score / max_possible) * 100))
        
        return {
            "total_findings": total,
            "severity_breakdown": severity_counts,
            "risk_score": normalized_risk,
            "scans_performed": len(self.scan_results),
            "assessment_duration": self._get_duration()
        }
    
    def _get_duration(self) -> str:
        """Get assessment duration string"""
        if self.start_time and self.end_time:
            delta = self.end_time - self.start_time
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{hours}h {minutes}m {seconds}s"
        return "N/A"
    
    def generate(self, format: ReportFormat, output_path: str) -> str:
        """
        Generate report in specified format.
        
        Args:
            format: Output format
            output_path: Output file path
            
        Returns:
            Path to generated report
        """
        logger.info(f"Generating {format.value} report: {output_path}")
        
        if format == ReportFormat.HTML:
            content = self._generate_html()
        elif format == ReportFormat.MARKDOWN:
            content = self._generate_markdown()
        elif format == ReportFormat.JSON:
            content = self._generate_json()
        elif format == ReportFormat.PDF:
            pdf_content = self._generate_pdf()
            # PDF is binary, handle separately
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(pdf_content)
            logger.info(f"Report saved: {output_path}")
            return output_path
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        # Text-based formats (HTML, Markdown, JSON)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Report saved: {output_path}")
            return output_path
        except PermissionError as e:
            logger.error(f"Permission denied writing report to {output_path}: {e}")
            raise
        except OSError as e:
            logger.error(f"OS error writing report to {output_path}: {e}")
            raise
    
    def _generate_html(self) -> str:
        """Generate HTML report"""
        stats = self.get_statistics()
        
        # Sort findings by severity
        sorted_findings = sorted(
            self.findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
        )
        
        findings_html = ""
        for i, finding in enumerate(sorted_findings, 1):
            severity_class = f"severity-{finding.severity.value}"
            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="finding-number">#{i}</span>
                    <span class="finding-title">{finding.title}</span>
                    <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Affected Asset:</strong> {finding.affected_asset}</p>
                    <p><strong>Description:</strong> {finding.description}</p>
                    {f'<p><strong>CVE:</strong> {finding.cve_id} (CVSS: {finding.cvss_score})</p>' if finding.cve_id else ''}
                    {f'<div class="evidence"><strong>Evidence:</strong><pre>{finding.evidence}</pre></div>' if finding.evidence else ''}
                    {f'<p><strong>Remediation:</strong> {finding.remediation}</p>' if finding.remediation else ''}
                </div>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config.title}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #bd93f9;
            --critical: #ff5555;
            --high: #ff79c6;
            --medium: #ffb86c;
            --low: #50fa7b;
            --info: #8be9fd;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
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
        }}
        
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
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self.config.title}</h1>
            <p>{self.config.author}</p>
            <div class="classification">{self.config.classification}</div>
        </div>
        
        <div class="meta-info">
            <div class="meta-card">
                <h3>Target</h3>
                <p>{self.target}</p>
            </div>
            <div class="meta-card">
                <h3>Assessment Date</h3>
                <p>{self.start_time.strftime('%Y-%m-%d') if self.start_time else 'N/A'}</p>
            </div>
            <div class="meta-card">
                <h3>Duration</h3>
                <p>{stats['assessment_duration']}</p>
            </div>
            <div class="meta-card">
                <h3>Total Findings</h3>
                <p>{stats['total_findings']}</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Findings Summary</h2>
            <div class="stats-grid">
                <div class="stat-card critical">
                    <div class="stat-number">{stats['severity_breakdown']['critical']}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-number">{stats['severity_breakdown']['high']}</div>
                    <div>High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-number">{stats['severity_breakdown']['medium']}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-number">{stats['severity_breakdown']['low']}</div>
                    <div>Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-number">{stats['severity_breakdown']['info']}</div>
                    <div>Info</div>
                </div>
            </div>
            
            <h3>Risk Score: {stats['risk_score']}/100</h3>
            <div class="risk-meter">
                <div class="risk-indicator" style="left: {stats['risk_score']}%;"></div>
            </div>
        </div>
        
        {self._generate_executive_summary_html(stats) if self.config.include_executive_summary else ''}
        
        <div class="section">
            <h2>Detailed Findings</h2>
            {findings_html if findings_html else '<p>No findings recorded.</p>'}
        </div>
        
        <div class="footer">
            <p>Generated by DRAKBEN AI Framework</p>
            <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_executive_summary_html(self, stats: Dict[str, Any]) -> str:
        """Generate executive summary section with Optional AI Insight"""
        total = stats['total_findings']
        critical = stats['severity_breakdown']['critical']
        high = stats['severity_breakdown']['high']
        
        risk_level = "LOW"
        if stats['risk_score'] >= 70:
            risk_level = "CRITICAL"
        elif stats['risk_score'] >= 50:
            risk_level = "HIGH"
        elif stats['risk_score'] >= 30:
            risk_level = "MEDIUM"
            
        # AI Insight Generation (Simulated for C-Level)
        ai_content = ""
        if self.config.use_llm_summary:
            ai_content = self._generate_ai_insight(critical, high, stats['risk_score'])
        
        return f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="executive-summary">
                <p>A penetration test was conducted against <strong>{self.target}</strong> 
                to identify security vulnerabilities and assess the overall security posture.</p>
                
                <p>The assessment identified <strong>{total} security findings</strong>, 
                including <strong>{critical} critical</strong> and <strong>{high} high</strong> severity issues.</p>
                
                <p>The overall risk level is assessed as <strong>{risk_level}</strong> 
                with a risk score of <strong>{stats['risk_score']}/100</strong>.</p>
                
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

    def _generate_ai_insight(self, _critical: int, _high: int, risk: int) -> str:
        """Generate C-Level insight using simulated LLM logic"""
        # In a real scenario, this communicates with UniversalAdapter's LLM
        insight = "<div style='margin-top: 15px; padding: 10px; background-color: #2a2a40; border-left: 3px solid #bd93f9;'>"
        insight += "<strong>🤖 AI Strategic Analysis (C-Level):</strong><br>"
        
        if risk > 80:
             insight += "Detected vulnerabilities pose an <em>imminent threat</em> to business continuity. "
             insight += "Immediate resource allocation is required to mitigate potential data breaches and regulatory fines. "
             insight += "<strong>Recommendation:</strong> Freeze feature development and focus engineering teams on remediation."
        elif risk > 50:
             insight += "Security posture is compromised with significant risks reachable from external networks. "
             insight += "Potential for lateral movement is high. "
             insight += "<strong>Recommendation:</strong> Schedule emergency maintenance window within 48 hours."
        else:
             insight += "Security posture is generally robust, though some hygiene issues remain. "
             insight += "<strong>Recommendation:</strong> Incorporate fixes into the next scheduled sprint."
             
        insight += "</div>"
        return insight
    
    def _generate_markdown(self) -> str:
        """Generate Markdown report"""
        stats = self.get_statistics()
        
        md = f"""# {self.config.title}

**Classification:** {self.config.classification}  
**Author:** {self.config.author}  
**Date:** {self.start_time.strftime('%Y-%m-%d') if self.start_time else 'N/A'}

---

## Target Information

- **Target:** {self.target}
- **Assessment Duration:** {stats['assessment_duration']}
- **Total Findings:** {stats['total_findings']}

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {stats['severity_breakdown']['critical']} |
| High | {stats['severity_breakdown']['high']} |
| Medium | {stats['severity_breakdown']['medium']} |
| Low | {stats['severity_breakdown']['low']} |
| Info | {stats['severity_breakdown']['info']} |

**Risk Score:** {stats['risk_score']}/100

---

## Executive Summary

A penetration test was conducted against **{self.target}** to identify security vulnerabilities.

The assessment identified **{stats['total_findings']} findings**, including:
- {stats['severity_breakdown']['critical']} Critical
- {stats['severity_breakdown']['high']} High
- {stats['severity_breakdown']['medium']} Medium

---

## Detailed Findings

"""
        
        sorted_findings = sorted(
            self.findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
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
- Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return md
    
    def _generate_json(self) -> str:
        """Generate JSON report"""
        stats = self.get_statistics()
        
        report = {
            "metadata": {
                "title": self.config.title,
                "author": self.config.author,
                "classification": self.config.classification,
                "generated_at": datetime.now().isoformat(),
                "target": self.target,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None
            },
            "statistics": stats,
            "findings": [f.to_dict() for f in self.findings],
            "scan_results": [r.to_dict() for r in self.scan_results]
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _generate_pdf(self) -> bytes:
        """
        Generate PDF report.
        
        Falls back to HTML if weasyprint is not available.
        """
        html_content = self._generate_html()
        
        try:
            from weasyprint import HTML
            pdf_bytes = HTML(string=html_content).write_pdf()
            return pdf_bytes
        except ImportError:
            logger.warning("weasyprint not installed, saving HTML instead")
            # Return HTML as bytes if PDF generation not available
            return html_content.encode('utf-8')
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            return html_content.encode('utf-8')


def create_finding_from_vuln(vuln_data: Dict[str, Any]) -> Finding:
    """
    Create Finding from vulnerability data.
    
    Args:
        vuln_data: Vulnerability dictionary
        
    Returns:
        Finding object
    """
    severity_map = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFO
    }
    
    severity_str = vuln_data.get("severity", "info").lower()
    severity = severity_map.get(severity_str, FindingSeverity.INFO)
    
    return Finding(
        title=vuln_data.get("title", vuln_data.get("vuln_id", "Unknown")),
        severity=severity,
        description=vuln_data.get("description", ""),
        affected_asset=vuln_data.get("target", vuln_data.get("affected_asset", "")),
        evidence=vuln_data.get("evidence", vuln_data.get("proof", "")),
        remediation=vuln_data.get("remediation", ""),
        cve_id=vuln_data.get("cve_id"),
        cvss_score=vuln_data.get("cvss_score"),
        references=vuln_data.get("references", [])
    )


# Convenience function for state integration
def generate_report_from_state(
    state: "AgentState",
    output_path: str,
    format: ReportFormat = ReportFormat.HTML,
    config: Optional[ReportConfig] = None
) -> str:
    """
    Generate report from AgentState.
    
    Args:
        state: AgentState instance
        output_path: Output file path
        format: Report format
        config: Report configuration
        
    Returns:
        Path to generated report
    """
    generator = ReportGenerator(config)
    generator.set_target(state.target or "Unknown")
    
    # Convert state vulnerabilities to findings
    # Convert state vulnerabilities to findings
    for vuln in state.vulnerabilities:
        severity_val = FindingSeverity.HIGH if getattr(vuln, 'exploit_success', False) else FindingSeverity.MEDIUM
        
        # Determine strict severity from vuln.severity string if possible
        if hasattr(vuln, 'severity') and isinstance(vuln.severity, str):
             try:
                 severity_val = FindingSeverity(vuln.severity.lower())
             except ValueError:
                 pass

        finding = Finding(
            title=vuln.vuln_id,
            severity=severity_val,
            description=getattr(vuln, 'description', f"Vulnerability detected on service {vuln.service} port {vuln.port}"),
            affected_asset=f"{state.target}:{vuln.port}" if state.target else "unknown",
            evidence=f"Exploitable: {vuln.exploitable}",
            cve_id=getattr(vuln, 'cve_id', None),
            cvss_score=getattr(vuln, 'cvss_score', None)
        )
        generator.add_finding(finding)
    
    return generator.generate(format, output_path)
