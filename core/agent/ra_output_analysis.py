"""Output analysis mixin for RefactoredDrakbenAgent.

Handles both LLM-powered and offline (rule-based) tool output analysis,
feeding discovered steps back into the live planner.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.agent._agent_protocol import AgentProtocol

    _MixinBase = AgentProtocol
else:
    _MixinBase = object

logger: logging.Logger = logging.getLogger(__name__)


class RAOutputAnalysisMixin(_MixinBase):
    """Mixin: tool output analysis (LLM + offline)."""

    # ------------------------------------------------------------------
    # entry point
    # ------------------------------------------------------------------

    def _analyze_and_show_output(self, tool_name: str, execution_result: dict) -> None:
        """Ask the LLM to analyze tool output and show the analysis to the user."""
        stdout = execution_result.get("stdout", "")
        if not stdout or not stdout.strip():
            return

        llm_client = getattr(self.brain, "llm_client", None)

        # LLM-powered analysis
        if llm_client:
            self._analyze_with_llm_transparency(tool_name, stdout, llm_client)
            return

        # Offline: rule-based analysis so user still sees SOMETHING
        self._analyze_offline(tool_name, stdout)

    # ------------------------------------------------------------------
    # LLM path
    # ------------------------------------------------------------------

    def _analyze_with_llm_transparency(self, tool_name: str, stdout: str, llm_client: Any) -> None:
        """LLM-powered output analysis that feeds suggestions back into the planner.

        This is the core "LLM-in-the-loop" mechanism:
        1. Send tool output to LLM for analysis
        2. Parse structured response (findings, severity, suggested next steps)
        3. Inject any suggested next steps into the live plan via planner
        4. Show everything transparently to the user
        """
        try:
            prompt = self._build_analysis_prompt(tool_name, stdout)
            prompt = self._enhance_analysis_prompt(prompt, tool_name)

            t0 = time.time()
            response = llm_client.query(prompt, timeout=25)
            duration = time.time() - t0

            self.transparency.show_llm_thinking(
                prompt_summary=f"Analyze {tool_name} output ({len(stdout)} chars)",
                response=response[:500],
                duration=duration,
            )

            analysis = self._parse_analysis_response(response)
            self.transparency.show_output_analysis(tool_name, analysis)
            self._inject_analysis_steps(analysis)

        except Exception as e:
            logger.debug("LLM analysis failed, falling back to offline: %s", e)
            self._analyze_offline(tool_name, stdout)

    def _build_analysis_prompt(self, tool_name: str, stdout: str) -> str:
        """Build the LLM analysis prompt with current state context."""
        target = self.state.target if self.state else "N/A"
        phase = self.state.phase.value if self.state else "unknown"
        n_services = len(self.state.open_services) if self.state else 0
        n_vulns = len(self.state.vulnerabilities) if self.state else 0

        return (
            f"You are DRAKBEN's analysis engine. Analyze this {tool_name} output "
            f"for target {target} (phase: {phase}, {n_services} services, {n_vulns} vulns).\n\n"
            f"OUTPUT:\n{stdout[:4000]}\n\n"
            f"Respond ONLY in JSON:\n"
            f'{{"findings": ["finding1", ...], '
            f'"summary": "2-3 sentence technical analysis", '
            f'"severity": "info|low|medium|high|critical", '
            f'"next_steps": ['
            f'  {{"action": "action_name", "tool": "tool_name", "reason": "why"}}'
            f']}}\n\n'
            f"next_steps should recommend concrete follow-up scans based on what "
            f"was discovered (e.g., web port open -> nikto, SMB -> enum4linux). "
            f"Return empty list if no further action needed."
        )

    def _enhance_analysis_prompt(self, prompt: str, tool_name: str) -> str:
        """Enhance analysis prompt with few-shot examples and KB context."""
        phase = self.state.phase.value if self.state else "unknown"
        target = self.state.target if self.state else "N/A"

        few_shot = getattr(self.brain, "few_shot", None) if self.brain else None
        if few_shot:
            try:
                prompt = few_shot.enhance_prompt(prompt, phase=phase, task_type="tool_analysis")
            except (AttributeError, TypeError, ValueError):
                logger.debug("Few-shot enhancement failed", exc_info=True)

        kb = getattr(self.brain, "knowledge_base", None) if self.brain else None
        if kb:
            try:
                service_hint = tool_name.split("_")[0] if "_" in tool_name else None
                kb_context = kb.recall_for_context(target=target, service=service_hint)
                if kb_context:
                    prompt = f"{prompt}\n\n### PRIOR KNOWLEDGE\n{kb_context}"
            except (AttributeError, TypeError, sqlite3.Error):
                logger.debug("KB context recall failed", exc_info=True)

        return prompt

    def _parse_analysis_response(self, response: str) -> dict[str, Any]:
        """Parse LLM analysis response using structured parser or fallback."""
        output_parser = getattr(self.brain, "output_parser", None) if self.brain else None
        if output_parser and type(output_parser).__name__ == "StructuredOutputParser":
            try:
                from core.intelligence.structured_output import ToolAnalysis as _TA
                parsed = output_parser.parse(response, _TA)
                if parsed and hasattr(parsed, "to_dict"):
                    return parsed.to_dict()
            except (ImportError, ValueError, TypeError, AttributeError):
                logger.debug("Structured output parsing failed", exc_info=True)
        return self._parse_llm_json(response)

    def _inject_analysis_steps(self, analysis: dict[str, Any]) -> None:
        """Inject LLM-suggested next steps into the live plan."""
        next_steps = analysis.get("next_steps") or []
        if not next_steps and analysis.get("next_action"):
            next_steps = [{"action": analysis["next_action"], "tool": analysis["next_action"]}]

        if not next_steps or not self.state:
            return

        target = self.state.target or "unknown"
        n_injected = self.planner.inject_dynamic_steps(
            new_actions=next_steps, target=target, source="llm",
        )
        if n_injected > 0:
            self.transparency.show_plan_injection(next_steps[:n_injected], source="llm")
            self.console.print(
                f"   \U0001f9e0 LLM injected {n_injected} new step(s) into plan",
                style=self.STYLE_MAGENTA,
            )

    @staticmethod
    def _parse_llm_json(response: str) -> dict[str, Any]:
        """Extract JSON from LLM response, tolerating markdown fences."""
        # Try ```json ... ``` block first (supports nested braces via DOTALL)
        m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", response, re.DOTALL)
        text = m.group(1) if m else response
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find any JSON object in raw text
            m2 = re.search(r"(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", response, re.DOTALL)
            if m2:
                try:
                    return json.loads(m2.group(1))
                except json.JSONDecodeError:
                    pass
            return {"summary": response[:500], "findings": [], "severity": "info"}

    # ------------------------------------------------------------------
    # Offline (rule-based) path
    # ------------------------------------------------------------------

    def _analyze_offline(self, tool_name: str, stdout: str) -> None:
        """Rule-based output analysis when LLM is unavailable."""
        findings: list[str] = []
        output_lower = stdout.lower()

        # Port/service detection
        port_lines = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", stdout)
        for port, svc in port_lines:
            findings.append(f"Port {port}/tcp open \u2014 {svc}")

        # Vulnerability markers
        vuln_findings, severity = self._extract_vuln_findings(stdout, output_lower)
        findings.extend(vuln_findings)

        # Service-specific suggestions → injectable steps
        next_action, offline_next_steps = self._determine_offline_next_steps(port_lines)

        if not findings:
            findings.append(f"{tool_name} tamamland\u0131 \u2014 {len(stdout)} karakter \u00e7\u0131kt\u0131")

        summary = f"{len(findings)} bulgu tespit edildi (offline analiz)"
        analysis = {
            "summary": summary,
            "findings": findings[:10],
            "severity": severity,
            "next_action": next_action,
        }
        self.transparency.show_output_analysis(tool_name, analysis)

        # Offline mode also injects steps into the plan (same as LLM path)
        self._inject_offline_steps(offline_next_steps)

    def _extract_vuln_findings(self, stdout: str, output_lower: str) -> tuple[list[str], str]:
        """Scan output for vulnerability markers and extract matching lines."""
        findings: list[str] = []
        severity = "info"
        vuln_markers = ["vulnerable", "cve-", "exploit", "injection", "xss", "rce"]
        for marker in vuln_markers:
            if marker in output_lower:
                severity = "high" if marker in ("exploit", "rce") else "medium"
                for line in stdout.splitlines():
                    if marker in line.lower() and len(line.strip()) > 5:
                        findings.append(line.strip()[:150])
                        break
        return findings, severity

    def _determine_offline_next_steps(
        self, port_lines: list[tuple[str, str]],
    ) -> tuple[str | None, list[dict[str, str]]]:
        """Determine next actions based on discovered ports."""
        if not port_lines:
            return None, []
        next_action: str | None = None
        steps: list[dict[str, str]] = []
        ports_found = {int(p) for p, _ in port_lines}
        if 80 in ports_found or 443 in ports_found:
            next_action = "nikto_web_scan"
            steps.append({"action": "web_vuln_scan", "tool": "nikto_web_scan", "reason": "HTTP port found"})
        elif 3306 in ports_found:
            next_action = "mysql_enum"
            steps.append({"action": "db_enum", "tool": "db_enum", "reason": "MySQL port 3306 open"})
        elif 445 in ports_found:
            next_action = "enum4linux"
            steps.append({"action": "smb_enum", "tool": "enum4linux", "reason": "SMB port 445 open"})
        return next_action, steps

    def _inject_offline_steps(self, offline_next_steps: list[dict[str, str]]) -> None:
        """Inject offline-discovered steps into the plan."""
        if not offline_next_steps or not self.state:
            return
        n_injected = self.planner.inject_dynamic_steps(
            new_actions=offline_next_steps,
            target=self.state.target or "",
            source="offline",
        )
        if n_injected > 0:
            self.transparency.show_plan_injection(offline_next_steps[:n_injected], source="offline")
            self.console.print(
                f"   \U0001f4dd Offline analysis injected {n_injected} step(s) into plan",
                style="yellow",
            )
