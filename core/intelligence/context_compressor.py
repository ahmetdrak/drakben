# core/intelligence/context_compressor.py
# DRAKBEN — Smart Context Compressor
# Instead of just truncating old messages (losing information),
# this module summarizes them to preserve key facts while saving tokens.
#
# Key insight: A 500-line nmap output can be summarized to 5 lines
# without losing any actionable information.

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class ContextCompressor:
    """Compress conversation/observation history to fit context windows.

    Three strategies:
    1. Pre-summarized observations (via ToolOutputAnalyzer)
    2. LLM-based compression of old conversation turns
    3. Sliding window with importance scoring

    Usage::

        compressor = ContextCompressor(llm_client=client_or_none)
        compressed = compressor.compress_messages(messages, max_tokens=4000)

    """

    # Keep the last N messages intact (uncompressed)
    KEEP_RECENT = 4
    # Minimum number of messages before compression kicks in
    MIN_MESSAGES_FOR_COMPRESSION = 8
    # Maximum characters for a single compressed block
    MAX_SUMMARY_CHARS = 800

    def __init__(
        self,
        llm_client: Any = None,
        *,
        keep_recent: int = 4,
        max_summary_chars: int = 800,
    ) -> None:
        self._llm = llm_client
        self._keep_recent = max(keep_recent, 2)
        self._max_summary_chars = max_summary_chars
        self._cache: dict[str, str] = {}  # Hash → summary cache
        self._stats = {
            "compressions": 0,
            "llm_summaries": 0,
            "rule_summaries": 0,
            "chars_saved": 0,
        }

    def compress_messages(
        self,
        messages: list[dict[str, str]],
        *,
        max_total_chars: int = 12000,
    ) -> list[dict[str, str]]:
        """Compress message history while preserving recent messages.

        Args:
            messages: List of {"role": "...", "content": "..."} dicts
            max_total_chars: Target max total characters

        Returns:
            Compressed message list with a summary message replacing old ones

        """
        if not messages:
            return messages

        # Check if compression is needed
        total_chars = sum(len(m.get("content", "")) for m in messages)
        if total_chars <= max_total_chars or len(messages) <= self.MIN_MESSAGES_FOR_COMPRESSION:
            return messages

        self._stats["compressions"] += 1

        # Split: system prompt + old messages + recent messages
        system_msgs = [m for m in messages if m.get("role") == "system"]
        non_system = [m for m in messages if m.get("role") != "system"]

        if len(non_system) <= self._keep_recent:
            return messages

        old_messages = non_system[: -self._keep_recent]
        recent_messages = non_system[-self._keep_recent :]

        # Compress old messages
        summary = self._summarize_messages(old_messages)
        original_chars = sum(len(m.get("content", "")) for m in old_messages)
        self._stats["chars_saved"] += original_chars - len(summary)

        # Build compressed message list
        compressed: list[dict[str, str]] = []
        compressed.extend(system_msgs)
        compressed.append(
            {
                "role": "system",
                "content": f"[Context Summary - {len(old_messages)} previous messages compressed]\n{summary}",
            }
        )
        compressed.extend(recent_messages)

        return compressed

    def compress_observations(
        self,
        observations: list[dict[str, Any]],
        *,
        max_total_chars: int = 6000,
    ) -> str:
        """Compress a list of tool observations into a compact summary.

        Each observation is expected to have: tool, output, success, (optional) structured.

        Returns:
            Compact string summarizing all observations

        """
        if not observations:
            return ""

        total_chars = sum(len(str(obs.get("output", ""))) for obs in observations)

        # If already fits, just format normally
        if total_chars <= max_total_chars:
            return self._format_observations(observations)

        # Compress: use structured data if available, otherwise extract key facts
        parts: list[str] = []
        for obs in observations:
            tool = obs.get("tool", "unknown")
            success = "✓" if obs.get("success") else "✗"
            output = str(obs.get("output", ""))

            # Use pre-parsed structured data if available
            structured = obs.get("structured")
            if structured and isinstance(structured, dict):
                compact = self._format_structured(tool, structured)
                parts.append(f"[{success}] {compact}")
            else:
                # Extract key facts from raw output
                key_facts = self._extract_key_facts(tool, output)
                parts.append(f"[{success}] {tool}: {key_facts}")

        result = "\n".join(parts)
        return result[:max_total_chars]

    def _summarize_messages(self, messages: list[dict[str, str]]) -> str:
        """Summarize a list of messages."""
        # Try LLM summarization first
        if self._llm:
            summary = self._llm_summarize(messages)
            if summary:
                return summary

        # Rule-based summarization
        return self._rule_summarize(messages)

    def _llm_summarize(self, messages: list[dict[str, str]]) -> str | None:
        """Use LLM to create an intelligent summary."""
        try:
            # Build compact representation of messages
            msg_text = "\n".join(f"[{m['role']}]: {m['content'][:300]}" for m in messages)

            prompt = (
                "Summarize this conversation history in 200 words or less. "
                "Keep ALL technical details: IP addresses, ports, services, "
                "vulnerabilities found, credentials, and tool results. "
                "Drop conversational fluff.\n\n"
                f"{msg_text[:3000]}"
            )

            t0 = time.time()
            summary = self._llm.query(prompt, timeout=15)
            duration = time.time() - t0

            if summary and not summary.startswith("["):
                self._stats["llm_summaries"] += 1
                logger.debug("LLM summary generated in %.1fs", duration)
                return summary[: self._max_summary_chars]

        except Exception as e:
            logger.debug("LLM summarization failed: %s", e)

        return None

    def _rule_summarize(self, messages: list[dict[str, str]]) -> str:
        """Rule-based summarization — extract key facts without LLM."""
        self._stats["rule_summaries"] += 1

        facts: list[str] = []
        for msg in messages:
            content = msg.get("content", "")
            role = msg.get("role", "")

            if role == "user":
                # Keep short user requests
                if len(content) < 100:
                    facts.append(f"User: {content}")
                else:
                    facts.append(f"User: {content[:80]}...")
            elif role == "assistant":
                # Extract key info from assistant responses
                key_info = self._extract_assistant_facts(content)
                if key_info:
                    facts.append(f"Assistant: {key_info}")

        result = "\n".join(facts)
        return result[: self._max_summary_chars]

    def _extract_assistant_facts(self, content: str) -> str:
        """Extract key technical facts from assistant response."""
        import re

        facts: list[str] = []

        # Port/service info
        ports = re.findall(r"\d+/(tcp|udp)\s+open\s+\S+", content)
        if ports:
            facts.append(f"{len(ports)} ports found")

        # CVEs
        cves = re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)
        if cves:
            facts.append(f"CVEs: {', '.join(list(set(cves))[:3])}")  # type: ignore[arg-type]

        # Tool results
        tools_mentioned = re.findall(
            r"(nmap|nikto|sqlmap|gobuster|hydra|nuclei)\s+(?:found|detected|completed)",
            content,
            re.IGNORECASE,
        )
        if tools_mentioned:
            facts.append(f"Tools used: {', '.join(set(tools_mentioned))}")

        # Severity markers
        if any(kw in content.lower() for kw in ("critical", "high severity", "vulnerable")):
            facts.append("High-severity findings detected")

        if not facts:
            # Fallback: first meaningful line
            for line in content.split("\n"):
                line = line.strip()
                if len(line) > 20 and not line.startswith(("#", "```")):
                    return line[:120]

        return "; ".join(facts)

    def _format_observations(self, observations: list[dict[str, Any]]) -> str:
        """Format observations without compression."""
        parts: list[str] = []
        for obs in observations:
            tool = obs.get("tool", "unknown")
            success = "✓" if obs.get("success") else "✗"
            output = str(obs.get("output", ""))[:500]
            parts.append(f"[{success}] {tool}:\n{output}")
        return "\n".join(parts)

    def _format_structured(self, tool: str, structured: dict) -> str:
        """Format structured data compactly."""
        parts: list[str] = [tool]

        if structured.get("ports"):
            n = len(structured["ports"])
            parts.append(f"{n} ports")
        if structured.get("vulnerabilities"):
            n = len(structured["vulnerabilities"])
            parts.append(f"{n} vulns")
        if structured.get("findings"):
            n = len(structured["findings"])
            parts.append(f"{n} findings")
        if structured.get("severity") and structured["severity"] != "info":
            parts.append(f"[{structured['severity']}]")

        return " | ".join(parts)

    def _extract_key_facts(self, tool: str, output: str) -> str:
        """Extract key facts from raw tool output without LLM."""
        import re

        facts: list[str] = []

        # Count open ports
        port_count = len(re.findall(r"\d+/(tcp|udp)\s+open", output))
        if port_count:
            facts.append(f"{port_count} open ports")

        # CVEs
        cves = list(set(re.findall(r"CVE-\d{4}-\d+", output, re.IGNORECASE)))
        if cves:
            facts.append(f"CVEs: {', '.join(cves[:3])}")

        # Vulnerability indicators
        vuln_count = output.lower().count("vulnerable")
        if vuln_count:
            facts.append(f"{vuln_count} vulnerabilities")

        # Found directories
        dir_count = len(re.findall(r"Status:\s*200", output))
        if dir_count:
            facts.append(f"{dir_count} directories")

        if not facts:
            # Fallback: line count
            line_count = len(output.strip().split("\n"))
            facts.append(f"{line_count} lines of output")

        return "; ".join(facts)

    def get_stats(self) -> dict[str, int]:
        """Get compression statistics."""
        return dict(self._stats)
