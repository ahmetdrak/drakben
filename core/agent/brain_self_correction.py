# core/agent/brain_self_correction.py
# DRAKBEN - Self Correction Module (extracted from brain.py)


class SelfCorrection:
    """Kendi kendine düzeltme - Hataları tespit edip düzeltir."""

    def __init__(self) -> None:
        self.correction_history: list[dict[str, str]] = []

    def review(self, decision: dict) -> dict:
        """Review a decision and correct if needed.

        Args:
            decision: Decision to review

        Returns:
            Corrected decision

        """
        corrected = decision.copy()
        corrections = []

        # Check for dangerous commands
        if self._is_dangerous(decision):
            corrections.append("Added safety check")
            corrected["needs_approval"] = True
            corrected["safety_warning"] = "Potentially destructive operation"

        # Check for missing prerequisites
        prereqs: list[str] = self._check_prerequisites(decision)
        if prereqs:
            corrections.append(f"Added prerequisites: {', '.join(prereqs)}")
            corrected["prerequisites"] = prereqs

        # Check for optimization opportunities
        optimizations: list[str] = self._suggest_optimizations(decision)
        if optimizations:
            corrections.append("Suggested optimizations")
            corrected["optimizations"] = optimizations

        if corrections:
            corrected["corrected"] = True
            corrected["corrections"] = corrections
            self.correction_history.append(
                {
                    "original": decision,
                    "corrected": corrected,
                    "corrections": corrections,
                },
            )

        return corrected

    def _is_dangerous(self, decision: dict) -> bool:
        """Check if decision involves dangerous operations.

        Two-layer check:
        1. Literal substring match for simple patterns
        2. Regex match for complex/piped command patterns

        Also analyzes piped commands (cmd1 | cmd2) and chained
        commands (cmd1 && cmd2 ; cmd3) segment by segment.
        """
        command = decision.get("command", "")
        if not command:
            return False

        # Split on pipes, semicolons, && to check each segment
        segments = self._re.split(r"\s*[|;&]+\s*", command)
        full_check = command  # Also check the full command for cross-segment patterns

        # Layer 1: Literal substring match on each segment and full command
        for check_str in [*segments, full_check]:
            if any(pattern in check_str for pattern in self._DANGEROUS_PATTERNS):
                return True

        # Layer 2: Regex match on full command (catches piped patterns)
        return any(regex.search(full_check) for regex in self._DANGEROUS_REGEX)

    # Expanded dangerous pattern list — configurable via subclass override
    # NOTE: These are LITERAL substring matches. Regex patterns use _DANGEROUS_REGEX.
    _DANGEROUS_PATTERNS: frozenset[str] = frozenset({
        # Destructive filesystem operations
        "rm -rf /",
        "rm -rf /*",
        "dd if=",
        "mkfs",
        "format c:",
        "> /dev/sda",
        "shred ",
        "wipefs",
        # Permission escalation
        "chmod 777",
        "chmod -R 777",
        "chown root",
        # Fork-bomb / resource exhaustion
        ":(){ :|:& };:",
        "%0|%0",
        # Direct exfiltration
        "nc -e",
        "ncat -e",
        # Credential dumping / shadow access
        "cat /etc/shadow",
        "cat /etc/passwd",
        # Kernel / boot manipulation
        "insmod ",
        "modprobe ",
        "grub-install",
        # Windows destructive
        "del /f /s /q",
        "rd /s /q",
        "format d:",
    })

    # Regex patterns for complex dangerous command detection
    import re as _re
    _DANGEROUS_REGEX: tuple = (
        _re.compile(r"curl\s+.*\|\s*(ba)?sh"),       # curl ... | bash/sh
        _re.compile(r"wget\s+.*\|\s*(ba)?sh"),       # wget ... | sh
        _re.compile(r"curl\s+.*-o\s+/tmp/.*&&.*sh"),  # curl -o /tmp/x && sh /tmp/x
        _re.compile(r"> /dev/sd[a-z]"),               # overwrite disk device
        _re.compile(r"python[23]?\s+-c\s+.*import\s+os"),  # python -c 'import os'
        _re.compile(r"base64\s+-d.*\|\s*(ba)?sh"),    # base64 -d | sh (obfuscation)
    )

    def _check_prerequisites(self, decision: dict) -> list[str]:
        """Check for missing prerequisites by inspecting tool availability."""
        import shutil

        prereqs: list[str] = []

        # Strategy 1: Check explicitly listed required_tools (if caller sets them)
        required_tools = decision.get("required_tools", [])
        tools_available = decision.get("tools_available", {})
        if required_tools and tools_available:
            prereqs.extend(
                tool for tool in required_tools
                if not tools_available.get(tool)
            )

        # Strategy 2: Extract tool names from steps and verify they exist on the system
        steps = decision.get("steps", [])
        for step in steps:
            if isinstance(step, dict):
                tool_name = step.get("tool")
                if tool_name and isinstance(tool_name, str):
                    # Check if the tool binary exists on PATH
                    if not shutil.which(tool_name):
                        prereqs.append(f"{tool_name} (not found on PATH)")

        return prereqs

    def _suggest_optimizations(self, decision: dict) -> list[str]:
        """Suggest optimizations based on step analysis."""
        optimizations: list[str] = []
        steps = decision.get("steps", [])
        if not steps:
            return optimizations

        if len(steps) > 3:
            optimizations.append("Consider parallel execution for independent steps")

        self._check_nmap_combinations(steps, optimizations)
        self._check_redundant_steps(steps, optimizations)
        self._check_cache_opportunity(decision, optimizations)

        return optimizations

    @staticmethod
    def _check_nmap_combinations(steps: list, optimizations: list[str]) -> None:
        """Detect combinable nmap commands."""
        nmap_steps = [s for s in steps if isinstance(s, dict) and s.get("tool") == "nmap"]
        if len(nmap_steps) < 2:
            return
        actions = [s.get("action", "") for s in nmap_steps]
        if "port_scan" in actions and "service_detection" in actions:
            optimizations.append(
                "Combine port_scan + service_detection into single 'nmap -sV -sS' call",
            )
        if "vuln_scan" in actions and "service_detection" in actions:
            optimizations.append(
                "Combine service_detection + vuln_scan into 'nmap -sV --script vuln'",
            )

    @staticmethod
    def _check_redundant_steps(steps: list, optimizations: list[str]) -> None:
        """Detect redundant steps."""
        seen_actions: set[str] = set()
        for step in steps:
            if not isinstance(step, dict):
                continue
            action = step.get("action", "")
            if action in seen_actions:
                optimizations.append(f"Redundant step detected: '{action}' — remove duplicate")
            seen_actions.add(action)

    @staticmethod
    def _check_cache_opportunity(decision: dict, optimizations: list[str]) -> None:
        """Suggest caching scan results."""
        command = decision.get("command", "")
        if command and any(tool in command for tool in ["nmap", "nikto", "nuclei"]):
            optimizations.append("Cache scan results to avoid re-scanning if target unchanged")

    def get_correction_stats(self) -> dict:
        """Get statistics about corrections made."""
        return {
            "total_corrections": len(self.correction_history),
            "recent_corrections": self.correction_history[-5:],
        }
