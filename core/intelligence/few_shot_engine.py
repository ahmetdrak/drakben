# core/intelligence/few_shot_engine.py
# DRAKBEN — Few-Shot Prompting + Chain-of-Thought Engine
#
# Problem: All prompts send ZERO examples → LLM guesses the output format
# Solution: Inject 2-3 curated pentest chain examples + "think step by step"
#
# This dramatically improves:
#   - Output format consistency (JSON compliance)
#   - Reasoning quality (CoT forces step-by-step logic)
#   - Tool selection accuracy (examples show winning patterns)
#
# Reference: Wei et al. "Chain-of-Thought Prompting Elicits Reasoning"

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FewShotExample:
    """A single few-shot example with input, reasoning, and output."""

    scenario: str      # Input scenario description
    reasoning: str     # Chain-of-thought reasoning trace
    output: dict       # Expected structured output
    phase: str = ""    # Which pentest phase this example covers
    tags: list[str] = field(default_factory=list)


class FewShotEngine:
    """Manages few-shot examples and injects them into LLM prompts.

    Usage::

        engine = FewShotEngine()
        enhanced_prompt = engine.enhance_prompt(
            original_prompt="Analyze nmap output for 10.0.0.1",
            phase="recon",
            task_type="tool_analysis",
        )

    """

    def __init__(self) -> None:
        self._examples: dict[str, list[FewShotExample]] = {}
        self._cot_prefix = (
            "Let's think step by step before deciding:\n"
            "1. What do I know from the observations so far?\n"
            "2. What is the most valuable next action?\n"
            "3. What risks should I consider?\n\n"
        )
        self._load_builtin_examples()
        self._stats = {"prompts_enhanced": 0, "examples_injected": 0}

    # ─────────────────────── Public API ───────────────────────

    def enhance_prompt(
        self,
        original_prompt: str,
        phase: str = "",
        task_type: str = "general",
        *,
        max_examples: int = 2,
        include_cot: bool = True,
    ) -> str:
        """Enhance a prompt with few-shot examples and CoT instruction.

        Args:
            original_prompt: The original prompt to enhance.
            phase: Pentest phase (recon, enum, exploit, post_exploit).
            task_type: Type of task (tool_analysis, next_step, recovery, etc.).
            max_examples: Maximum number of examples to inject.
            include_cot: Whether to prepend Chain-of-Thought instruction.

        Returns:
            Enhanced prompt with examples prepended.

        """
        parts: list[str] = []

        # 1. CoT instruction
        if include_cot:
            parts.append(self._cot_prefix)

        # 2. Few-shot examples
        examples = self._select_examples(phase, task_type, max_examples)
        if examples:
            parts.append("### EXAMPLES (follow this format):\n")
            for i, ex in enumerate(examples, 1):
                parts.append(f"**Example {i}:** {ex.scenario}")
                parts.append(f"**Reasoning:** {ex.reasoning}")
                parts.append(f"**Output:**\n```json\n{json.dumps(ex.output, indent=2)}\n```\n")
            self._stats["examples_injected"] += len(examples)

        # 3. Original prompt
        parts.append("### YOUR TASK (apply the same reasoning):\n")
        parts.append(original_prompt)

        self._stats["prompts_enhanced"] += 1
        return "\n".join(parts)

    def add_example(self, task_type: str, example: FewShotExample) -> None:
        """Add a custom few-shot example."""
        self._examples.setdefault(task_type, []).append(example)

    def add_learned_example(
        self,
        task_type: str,
        scenario: str,
        reasoning: str,
        output: dict,
        phase: str = "",
    ) -> None:
        """Add an example learned from a successful real execution."""
        ex = FewShotExample(
            scenario=scenario,
            reasoning=reasoning,
            output=output,
            phase=phase,
            tags=["learned", "real_execution"],
        )
        self._examples.setdefault(task_type, []).append(ex)
        # Keep max 10 learned examples per type
        learned = [e for e in self._examples[task_type] if "learned" in e.tags]
        if len(learned) > 10:
            # Remove oldest learned example
            for idx, e in enumerate(self._examples[task_type]):
                if "learned" in e.tags:
                    self._examples[task_type].pop(idx)
                    break

    def get_stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        total_examples = sum(len(v) for v in self._examples.values())
        return {**self._stats, "total_examples": total_examples}

    # ─────────────────── Example Selection ───────────────────

    def _select_examples(
        self, phase: str, task_type: str, max_count: int,
    ) -> list[FewShotExample]:
        """Select the most relevant examples for the current context."""
        candidates = self._collect_candidates(phase, task_type)
        scored = [
            (self._score_example(ex, phase, task_type), ex)
            for ex in candidates
        ]
        scored.sort(key=lambda x: -x[0])
        return [ex for _, ex in scored[:max_count]]

    def _collect_candidates(
        self, phase: str, task_type: str,
    ) -> list[FewShotExample]:
        """Gather candidate examples from task-type, phase, and general pools."""
        candidates: list[FewShotExample] = list(
            self._examples.get(task_type, []),
        )
        if phase:
            for examples in self._examples.values():
                for ex in examples:
                    if ex.phase == phase and ex not in candidates:
                        candidates.append(ex)
        if not candidates:
            candidates.extend(self._examples.get("general", []))
        return candidates

    @staticmethod
    def _score_example(
        ex: FewShotExample, phase: str, task_type: str,
    ) -> int:
        """Score a single example based on relevance."""
        score = 0
        if "learned" in ex.tags:
            score += 3
        if ex.phase == phase:
            score += 2
        if task_type in ex.tags:
            score += 1
        return score

    # ─────────────────── Built-in Examples ───────────────────

    def _load_builtin_examples(self) -> None:
        """Load curated pentest examples for each task type."""
        self._load_tool_analysis_examples()
        self._load_next_step_examples()
        self._load_recovery_examples()
        self._load_general_examples()

    def _load_tool_analysis_examples(self) -> None:
        """Examples for analyzing tool output."""
        self._examples["tool_analysis"] = [
            FewShotExample(
                scenario=(
                    "Nmap scan of 10.0.0.5 returned: "
                    "22/tcp open ssh OpenSSH 7.9, "
                    "80/tcp open http Apache/2.4.49, "
                    "443/tcp open ssl/http Apache/2.4.49, "
                    "3306/tcp open mysql MySQL 5.7.34"
                ),
                reasoning=(
                    "Step 1: 4 open ports found — SSH, HTTP (both 80+443), MySQL. "
                    "Step 2: Apache 2.4.49 is critically vulnerable to CVE-2021-41773 (path traversal + RCE). "
                    "Step 3: MySQL on external interface is unusual and high-risk. "
                    "Step 4: Priority: exploit Apache CVE first, then enumerate MySQL."
                ),
                output={
                    "findings": [
                        "Apache 2.4.49 vulnerable to CVE-2021-41773 (critical path traversal/RCE)",
                        "MySQL 5.7.34 exposed on external interface",
                        "SSH OpenSSH 7.9 (relatively current, low priority)",
                    ],
                    "summary": "Critical Apache 2.4.49 with known RCE (CVE-2021-41773). MySQL externally exposed. Immediate exploitation path available.",
                    "severity": "critical",
                    "next_steps": [
                        {"action": "exploit_cve", "tool": "nuclei", "reason": "Verify CVE-2021-41773 on Apache 2.4.49"},
                        {"action": "mysql_enum", "tool": "nmap_scripts", "reason": "Enumerate MySQL with default creds"},
                        {"action": "web_scan", "tool": "nikto", "reason": "Full web vulnerability scan on 80/443"},
                    ],
                },
                phase="recon",
                tags=["tool_analysis", "nmap", "critical_vuln"],
            ),
            FewShotExample(
                scenario=(
                    "Nikto scan of 10.0.0.5:80 returned: "
                    "+ /server-status accessible (mod_status), "
                    "+ /phpinfo.php found (PHP 7.4.3), "
                    "+ /.git/ directory listing enabled, "
                    "+ X-Frame-Options header missing"
                ),
                reasoning=(
                    "Step 1: server-status exposes internal server metrics — info leak. "
                    "Step 2: phpinfo.php reveals full PHP config including paths and modules — serious info disclosure. "
                    "Step 3: .git directory exposed means source code can be downloaded — high severity. "
                    "Step 4: Priority: download .git repo for source code analysis, check phpinfo for exploitable modules."
                ),
                output={
                    "findings": [
                        "Git repository exposed at /.git/ — source code downloadable",
                        "phpinfo.php reveals PHP 7.4.3 config and server paths",
                        "mod_status accessible — server metrics leak",
                        "Missing X-Frame-Options — clickjacking possible",
                    ],
                    "summary": "Exposed .git directory is the highest priority — full source code can be extracted. phpinfo.php provides valuable server intel for further exploitation.",
                    "severity": "high",
                    "next_steps": [
                        {"action": "git_dump", "tool": "git_dumper", "reason": "Download exposed .git repository for source code analysis"},
                        {"action": "dir_enum", "tool": "gobuster", "reason": "Find more hidden files and directories"},
                    ],
                },
                phase="enum",
                tags=["tool_analysis", "nikto", "info_disclosure"],
            ),
        ]

    def _load_next_step_examples(self) -> None:
        """Examples for deciding next pentest step."""
        self._examples["next_step"] = [
            FewShotExample(
                scenario=(
                    "Current state: target 10.0.0.1, phase=recon. "
                    "Nmap found ports 22,80,445,3389. "
                    "No vulnerabilities found yet. "
                    "Tools already run: nmap_port_scan."
                ),
                reasoning=(
                    "Step 1: Port 445 (SMB) and 3389 (RDP) suggest Windows target. "
                    "Step 2: SMB is historically the richest attack surface on Windows. "
                    "Step 3: Should enumerate SMB shares, check for EternalBlue, then move to web. "
                    "Step 4: RDP brute-force is noisy — save for later."
                ),
                output={
                    "intent": "scan",
                    "confidence": 0.85,
                    "response": "Windows hedef tespit edildi (SMB+RDP). SMB üzerinden enumeration başlatıyorum.",
                    "command": None,
                    "steps": [
                        {"action": "smb_enum", "tool": "enum4linux", "target": "10.0.0.1"},
                        {"action": "vuln_scan", "tool": "nmap_vuln_scan", "target": "10.0.0.1"},
                        {"action": "web_scan", "tool": "nikto", "target": "10.0.0.1:80"},
                    ],
                },
                phase="recon",
                tags=["next_step", "windows", "smb"],
            ),
            FewShotExample(
                scenario=(
                    "Current state: target app.example.com, phase=enum. "
                    "Found: 80/tcp (nginx), 443/tcp (nginx). "
                    "Nikto found: /api/v1/ endpoint, /admin login page. "
                    "gobuster found: /api/v1/users, /api/v1/debug, /uploads/."
                ),
                reasoning=(
                    "Step 1: /api/v1/debug is suspicious — debug endpoints often have auth bypass. "
                    "Step 2: /api/v1/users might allow user enumeration. "
                    "Step 3: /uploads/ could allow file upload → shell upload. "
                    "Step 4: /admin login page → test for default creds and SQLi."
                ),
                output={
                    "intent": "scan",
                    "confidence": 0.90,
                    "response": "API debug endpoint ve upload dizini bulundu. SQLi ve auth bypass testleri başlatıyorum.",
                    "command": None,
                    "steps": [
                        {"action": "api_test", "tool": "ffuf", "target": "app.example.com/api/v1/debug"},
                        {"action": "sqli_test", "tool": "sqlmap", "target": "app.example.com/admin"},
                        {"action": "upload_test", "tool": "file_upload_test", "target": "app.example.com/uploads/"},
                    ],
                },
                phase="enum",
                tags=["next_step", "web", "api"],
            ),
        ]

    def _load_recovery_examples(self) -> None:
        """Examples for recovering from tool failures."""
        self._examples["recovery"] = [
            FewShotExample(
                scenario=(
                    "Tool nmap_port_scan failed with: 'Host seems down'. "
                    "Target: 10.0.0.1. Previous: no scans completed."
                ),
                reasoning=(
                    "Step 1: 'Host seems down' usually means ICMP blocked, not actually down. "
                    "Step 2: Retry with -Pn (no ping) to skip host discovery. "
                    "Step 3: If that fails, try TCP SYN on common ports. "
                    "Step 4: Could also be a firewall — try from different source port."
                ),
                output=[
                    {"action": "nmap_no_ping", "tool": "nmap_port_scan", "reason": "Retry with -Pn to bypass ICMP block", "params": {"extra_args": "-Pn"}},
                    {"action": "tcp_connect", "tool": "nmap_port_scan", "reason": "TCP connect scan as fallback", "params": {"extra_args": "-sT -Pn"}},
                ],
                phase="recon",
                tags=["recovery", "nmap", "host_down"],
            ),
        ]

    def _load_general_examples(self) -> None:
        """General pentest reasoning examples."""
        self._examples["general"] = [
            FewShotExample(
                scenario="User asks: '10.0.0.0/24 ağını tara'",
                reasoning=(
                    "Step 1: User wants a subnet scan — this is recon phase. "
                    "Step 2: Start with fast ping sweep to find live hosts. "
                    "Step 3: Then port scan live hosts with common ports. "
                    "Step 4: /24 = 254 hosts, need aggressive timing."
                ),
                output={
                    "intent": "scan",
                    "target_extracted": "10.0.0.0/24",
                    "confidence": 0.95,
                    "response": "10.0.0.0/24 subnet taraması başlatıyorum. Önce canlı host tespiti, sonra port taraması.",
                    "command": "/scan 10.0.0.0/24",
                    "steps": [
                        {"action": "host_discovery", "description": "Ping sweep for live hosts"},
                        {"action": "port_scan", "description": "Top 1000 ports on live hosts"},
                    ],
                    "risks": ["Large subnet scan may trigger IDS alerts"],
                },
                phase="recon",
                tags=["general", "subnet", "recon"],
            ),
        ]
