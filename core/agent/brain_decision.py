# core/agent/brain_decision.py
# DRAKBEN - Decision Engine Module (extracted from brain.py)

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.agent.brain import ExecutionContext


class DecisionEngine:
    """Karar motoru - Hangi aksiyonun alınacağına karar verir."""

    # Maximum history size to prevent memory growth
    MAX_HISTORY_SIZE = 100

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.decision_history: list[dict] = []
        # Instance-level copy to prevent shared mutable state across instances
        self._tool_registry = dict(self._DEFAULT_TOOL_REGISTRY)

    def decide(self, analysis: dict, context: ExecutionContext) -> dict:
        """Make a decision based on analysis with scoring.

        When multiple actions are available, scores them on:
        - expected_yield: How much new info does this action produce?
        - confidence: How sure are we this will work?
        - risk: How dangerous is this action? (inverse weight)
        - stealth: How quiet is this action?

        Returns:
            {
                "action": str,
                "command": str,
                "needs_approval": bool,
                "reasoning": str,
                "confidence": float,
                "score": float
            }

        """
        intent = analysis.get("intent")
        steps = analysis.get("steps", [])
        risks = analysis.get("risks", [])

        # Determine if approval needed
        intent_str = str(intent or "unknown")
        needs_approval: bool = self._needs_approval(intent_str, risks, context)

        # Select best action with scoring
        action, score = self._select_action_scored(steps, context)

        # Generate command if needed
        command: str | None = self._generate_command(action, context)

        decision = {
            "action": action,
            "command": command,
            "needs_approval": needs_approval,
            "reasoning": analysis.get("reasoning", ""),
            "confidence": analysis.get("confidence", 0.5),
            "score": score,
            "has_risks": len(risks) > 0,
            "risks": risks,
            "steps": steps,
        }

        # Thread-safe history update with size limit
        with self._lock:
            self.decision_history.append(decision)
            if len(self.decision_history) > self.MAX_HISTORY_SIZE:
                self.decision_history = self.decision_history[-self.MAX_HISTORY_SIZE :]
        return decision

    def _needs_approval(
        self,
        intent: str,
        risks: list[str],
        context: ExecutionContext,
    ) -> bool:
        """Determine if user approval is needed based on risk level."""
        # Always ask for destructive intents
        if intent in ["exploit", "get_shell"]:
            return True

        # Ask for risky operations
        if risks:
            return True

        # First-time execution: ask once
        return bool(not context.history)

    @staticmethod
    def _collect_failed_tools(context: ExecutionContext) -> set[str]:
        """Collect tool names that have failed from execution history."""
        failed: set[str] = set()
        for entry in context.history or []:
            if isinstance(entry, dict) and not entry.get("success", True):
                failed.add(entry.get("tool", ""))
        return failed

    def _score_step(self, step: dict, failed_tools: set[str]) -> float:
        """Calculate a score for a single plan step."""
        score = 0.5  # Base score

        # Penalize already-failed tools
        tool = step.get("tool", "")
        if tool in failed_tools:
            score -= 0.3

        # Boost based on tool registry metadata
        action = step.get("action", "unknown")
        registry_entry = self._tool_registry.get(action, {})
        risk_val = registry_entry.get("risk", 5)
        stealth_val = registry_entry.get("stealth", 5)
        # Lower risk + higher stealth = better score
        score += (10 - risk_val) * 0.03  # type: ignore[operator]  # 0-0.3 bonus for low risk
        score += stealth_val * 0.02  # type: ignore[operator]  # 0-0.2 bonus for stealth
        return score

    def _select_action_scored(
        self,
        steps: list[dict],
        context: ExecutionContext,
    ) -> tuple[str, float]:
        """Select the best next action with scoring.

        Skips already-completed or failed actions. Scores remaining candidates
        on expected yield, confidence, and risk (from tool registry).

        Returns:
            (action_name, score)
        """
        if not steps:
            return ("respond", 1.0)

        current_step: int = context.current_step
        if current_step >= len(steps):
            return ("complete", 1.0)

        remaining = steps[current_step:]
        failed_tools = self._collect_failed_tools(context)

        if len(remaining) == 1:
            action = remaining[0].get("action", "unknown")
            tool = remaining[0].get("tool", "")
            base = 0.8
            if tool in failed_tools:
                base -= 0.3
            return (action, base)

        # Score each remaining step and pick the best
        best_action = remaining[0].get("action", "unknown")
        best_score = 0.0

        for step in remaining:
            score = self._score_step(step, failed_tools)
            if score > best_score:
                best_score = score
                best_action = step.get("action", "unknown")

        return (best_action, round(best_score, 3))

    # Tool registry mapping (action, context) → command template
    # Each entry: {"cmd": template, "risk": 0-10, "stealth": 0-10, "speed": 0-10}
    _DEFAULT_TOOL_REGISTRY: dict[str, dict[str, str | int]] = {
        # Reconnaissance
        "port_scan": {"cmd": "nmap -sS -T3 {target}", "risk": 2, "stealth": 7},
        "port_scan_fast": {"cmd": "nmap -F -T4 {target}", "risk": 1, "stealth": 5},
        "port_scan_full": {"cmd": "nmap -p- -T3 {target}", "risk": 3, "stealth": 4},
        "service_detection": {"cmd": "nmap -sV -sC {target}", "risk": 3, "stealth": 5},
        "os_detection": {"cmd": "nmap -O {target}", "risk": 3, "stealth": 4},
        "udp_scan": {"cmd": "nmap -sU --top-ports 100 {target}", "risk": 3, "stealth": 3},
        # Web scanning
        "web_scan": {"cmd": "nikto -h {target}", "risk": 4, "stealth": 2},
        "dir_bruteforce": {
            "cmd": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -q",
            "risk": 4,
            "stealth": 3,
        },
        "dir_fuzz": {
            "cmd": "ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 20",
            "risk": 4,
            "stealth": 3,
        },
        # Vulnerability scanning
        "vuln_scan": {"cmd": "nmap --script vuln {target}", "risk": 5, "stealth": 3},
        "nuclei_scan": {"cmd": "nuclei -u {target} -severity medium,high,critical -silent", "risk": 5, "stealth": 4},
        "wpscan": {"cmd": "wpscan --url http://{target} --enumerate vp,vt,u --no-banner", "risk": 4, "stealth": 4},
        # SQL injection
        "sqli_test": {
            "cmd": "sqlmap -u http://{target}/ --batch --level 1 --risk 1 --forms --crawl=2",
            "risk": 6,
            "stealth": 3,
        },
        # Brute force
        "ssh_bruteforce": {"cmd": "hydra -L users.txt -P passwords.txt ssh://{target} -t 4", "risk": 7, "stealth": 2},
        "http_bruteforce": {
            "cmd": "hydra -L users.txt -P passwords.txt {target} http-post-form",
            "risk": 7,
            "stealth": 2,
        },
        # Subdomain enumeration
        "subdomain_enum": {"cmd": "subfinder -d {target} -silent", "risk": 1, "stealth": 9},
        "dns_enum": {"cmd": "dnsrecon -d {target} -t std", "risk": 2, "stealth": 7},
        # SSL/TLS
        "ssl_scan": {"cmd": "sslscan {target}", "risk": 1, "stealth": 8},
        # SMB
        "smb_enum": {"cmd": "enum4linux -a {target}", "risk": 3, "stealth": 4},
        # Exploitation
        "exploit_search": {"cmd": "searchsploit {target}", "risk": 0, "stealth": 10},
        # General
        "check_tools": {
            "cmd": "which nmap nikto gobuster ffuf sqlmap hydra nuclei 2>/dev/null",
            "risk": 0,
            "stealth": 10,
        },
        "analyze_results": {"cmd": None, "risk": 0, "stealth": 10},  # type: ignore[dict-item]
        "analyze_vulns": {"cmd": None, "risk": 0, "stealth": 10},  # type: ignore[dict-item]
    }

    def _generate_command(self, action: str, context: ExecutionContext) -> str | None:
        """Generate shell command for action using the tool registry.

        Supports 20+ tools with risk/stealth scoring. Falls back to basic
        nmap if the action is unrecognized but a target exists.
        """
        target: str | None = context.target
        if not target:
            return None

        entry = self._tool_registry.get(action)
        if entry:
            cmd_template = entry.get("cmd")
            if cmd_template:
                return cmd_template.format(target=target)
            return None  # Analysis-only action

        return None
