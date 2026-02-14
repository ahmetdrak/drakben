# core/agent/cognitive/reflect.py
"""Reflect Module - Stanford Cognitive Architecture.

The Reflect module is the third stage of the cognitive cycle:
Memories -> Higher-Level Insights

This module:
1. Periodically reviews recent memories
2. Identifies patterns and connections
3. Generates reflection nodes (insights)
4. Updates poignancy scores based on new understanding

Stanford Reference:
"The reflection process generates higher-level insights by examining
recent memories and identifying patterns, lessons, and strategic implications."

Pentest-Specific Reflections:
- Attack path identification
- Vulnerability correlation
- Credential chain discovery
- Defense pattern detection
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from core.agent.memory.concept_node import (
    ConceptNode,
    NodeType,
    PentestRelevance,
    SPOTriple,
    create_reflection_node,
)

if TYPE_CHECKING:
    from core.agent.memory.memory_stream import MemoryStream

logger = logging.getLogger(__name__)


# Reflection triggers - when to generate reflections
REFLECTION_TRIGGERS = {
    "node_count": 10,  # After every N new nodes
    "finding_count": 3,  # After N new findings
    "time_elapsed": 300,  # After N seconds
}


class ReflectModule:
    """Generates higher-level insights from memories.

    This module implements Stanford's reflection mechanism:
    - Periodic review of recent memories
    - Pattern identification
    - Insight generation
    - Poignancy updates

    Reflections are crucial for:
    - Connecting disparate findings
    - Identifying attack paths
    - Learning from failures
    - Maintaining strategic focus
    """

    def __init__(
        self,
        memory_stream: MemoryStream,
        llm_client: Any | None = None,
        reflection_threshold: int = 10,
    ) -> None:
        """Initialize the reflect module.

        Args:
            memory_stream: MemoryStream to reflect on
            llm_client: Optional LLM for generating insights
            reflection_threshold: Nodes before reflection
        """
        self._memory_stream = memory_stream
        self._llm_client = llm_client
        self._reflection_threshold = reflection_threshold
        self._nodes_since_reflection = 0
        self._last_reflection_time = time.time()

    def should_reflect(self) -> bool:
        """Check if it's time to generate reflections.

        Returns:
            True if reflection should be triggered
        """
        # Node count trigger
        if self._nodes_since_reflection >= self._reflection_threshold:
            return True

        # Time trigger
        elapsed = time.time() - self._last_reflection_time
        if elapsed >= REFLECTION_TRIGGERS["time_elapsed"]:
            return True

        # Finding count trigger
        recent_findings = self._memory_stream.get_by_type(
            NodeType.FINDING, n=10,
        )
        high_poignancy_findings = [
            f for f in recent_findings if f.poignancy >= 7.0
        ]
        return len(high_poignancy_findings) >= REFLECTION_TRIGGERS["finding_count"]

    def reflect(
        self,
        target: str | None = None,
        force: bool = False,
    ) -> list[ConceptNode]:
        """Generate reflections based on recent memories.

        Args:
            target: Target to reflect on
            force: Force reflection even if threshold not met

        Returns:
            List of generated reflection nodes
        """
        if not force and not self.should_reflect():
            return []

        reflections: list[ConceptNode] = []

        # 1. Attack Path Reflection
        attack_path = self._reflect_on_attack_path(target)
        if attack_path:
            reflections.append(attack_path)

        # 2. Vulnerability Correlation
        vuln_correlation = self._reflect_on_vulnerabilities(target)
        if vuln_correlation:
            reflections.append(vuln_correlation)

        # 3. Credential Chain
        cred_chain = self._reflect_on_credentials(target)
        if cred_chain:
            reflections.append(cred_chain)

        # 4. Failure Patterns
        failure_insight = self._reflect_on_failures(target)
        if failure_insight:
            reflections.append(failure_insight)

        # 5. Strategic Insight (uses LLM if available)
        if self._llm_client and len(reflections) > 0:
            strategic = self._generate_strategic_insight(reflections, target)
            if strategic:
                reflections.append(strategic)

        # Store reflections
        for reflection in reflections:
            self._memory_stream.add(reflection)
            logger.info(
                "Generated reflection: %s (poignancy=%.1f)",
                reflection.description[:50],
                reflection.poignancy,
            )

        # Reset counters
        self._nodes_since_reflection = 0
        self._last_reflection_time = time.time()

        return reflections

    def _reflect_on_attack_path(
        self,
        target: str | None,
    ) -> ConceptNode | None:
        """Identify potential attack paths from findings."""
        findings = self._memory_stream.get_critical_findings(target=target)

        if len(findings) < 2:
            return None

        # Look for chain: recon -> vuln -> exploit opportunity
        services = [
            f for f in findings
            if f.pentest_relevance == PentestRelevance.SERVICE_INFO
        ]
        vulns = [
            f for f in findings
            if f.pentest_relevance in [
                PentestRelevance.CRITICAL_VULN,
                PentestRelevance.HIGH_VULN,
            ]
        ]

        if not vulns:
            return None

        # Generate attack path insight
        source_ids = [f.node_id for f in (services + vulns)[:5]]
        description = self._format_attack_path(services, vulns)

        return create_reflection_node(
            description=description,
            source_node_ids=source_ids,
            insight_type="attack_path",
            target=target,
        )

    def _format_attack_path(
        self,
        services: list[ConceptNode],
        vulns: list[ConceptNode],
    ) -> str:
        """Format attack path description."""
        parts = ["ATTACK PATH IDENTIFIED:"]

        if services:
            svc_list = [s.description[:30] for s in services[:3]]
            parts.append(f"Services: {', '.join(svc_list)}")

        if vulns:
            vuln_list = [v.description[:30] for v in vulns[:3]]
            parts.append(f"Vulnerabilities: {', '.join(vuln_list)}")

        parts.append("Consider exploitation via discovered weaknesses.")

        return " ".join(parts)

    def _reflect_on_vulnerabilities(
        self,
        target: str | None,
    ) -> ConceptNode | None:
        """Correlate related vulnerabilities."""
        vulns = self._memory_stream.get_by_relevance(
            PentestRelevance.CRITICAL_VULN, n=10, target=target,
        )
        vulns += self._memory_stream.get_by_relevance(
            PentestRelevance.HIGH_VULN, n=10, target=target,
        )

        if len(vulns) < 2:
            return None

        # Check for related vulnerabilities (same service, same type)
        descriptions = [v.description.lower() for v in vulns]

        # Look for patterns
        patterns_found = []
        if any("sql" in d for d in descriptions):
            patterns_found.append("SQL-related vulnerabilities")
        if any("auth" in d or "login" in d for d in descriptions):
            patterns_found.append("Authentication weaknesses")
        if any("file" in d or "upload" in d for d in descriptions):
            patterns_found.append("File handling issues")

        if not patterns_found:
            return None

        description = (
            f"VULNERABILITY CORRELATION: Multiple {', '.join(patterns_found)} "
            "detected. Consider combined exploitation."
        )

        return create_reflection_node(
            description=description,
            source_node_ids=[v.node_id for v in vulns[:5]],
            insight_type="correlation",
            target=target,
        )

    def _reflect_on_credentials(
        self,
        target: str | None,
    ) -> ConceptNode | None:
        """Identify credential chains and reuse opportunities."""
        creds = self._memory_stream.get_by_relevance(
            PentestRelevance.CREDENTIAL, n=10, target=target,
        )

        if len(creds) < 1:
            return None

        # Look for reuse opportunities
        services = self._memory_stream.get_by_relevance(
            PentestRelevance.SERVICE_INFO, n=20, target=target,
        )

        auth_services = [
            s for s in services
            if any(x in s.description.lower() for x in ["ssh", "ftp", "smb", "rdp", "mysql"])
        ]

        if auth_services:
            description = (
                f"CREDENTIAL OPPORTUNITY: {len(creds)} credential(s) discovered. "
                f"Potential targets: {len(auth_services)} authentication services. "
                "Consider credential spraying or lateral movement."
            )

            return create_reflection_node(
                description=description,
                source_node_ids=[c.node_id for c in creds] + [s.node_id for s in auth_services[:3]],
                insight_type="credential_chain",
                target=target,
            )

        return None

    def _reflect_on_failures(
        self,
        target: str | None,
    ) -> ConceptNode | None:
        """Learn from failed attempts."""
        events = self._memory_stream.get_by_type(
            NodeType.EVENT, n=30, target=target,
        )

        # Find failures
        failures = [
            e for e in events
            if "fail" in e.description.lower() or "error" in e.description.lower()
        ]

        if len(failures) < 3:
            return None

        # Analyze failure patterns
        tools_failed: dict[str, int] = {}
        for f in failures:
            tool = f.metadata.get("tool", "unknown")
            tools_failed[tool] = tools_failed.get(tool, 0) + 1

        # Find most failed tool
        if not tools_failed:
            return None

        most_failed = max(tools_failed.items(), key=lambda x: x[1])

        description = (
            f"FAILURE PATTERN: {most_failed[0]} failed {most_failed[1]} times. "
            "Consider: 1) Different approach, 2) Alternative tool, 3) Target hardening."
        )

        return ConceptNode(
            description=description,
            poignancy=6.0,
            node_type=NodeType.REFLECTION,
            pentest_relevance=PentestRelevance.GENERIC,
            spo_triple=SPOTriple(
                subject="agent",
                predicate="learned_from",
                obj=f"failures with {most_failed[0]}",
            ),
            parent_node_ids=[f.node_id for f in failures[:5]],
            target=target,
        )

    def _generate_strategic_insight(
        self,
        recent_reflections: list[ConceptNode],
        target: str | None,
    ) -> ConceptNode | None:
        """Generate strategic insight using LLM (if available)."""
        if not self._llm_client:
            return None

        # Build context from recent reflections
        context = "\n".join(r.description for r in recent_reflections)

        # Generate insight using LLM
        prompt = f"""Based on these pentest observations, provide ONE strategic insight (max 100 words):

{context}

Target: {target or 'unknown'}

Respond with a single actionable strategic recommendation."""

        try:
            response = self._llm_client.query(
                prompt,
                system_prompt="You are a strategic pentest advisor. Provide concise actionable insights.",
                timeout=15,
            )

            insight_text = response.strip() if isinstance(response, str) else ""
            if not insight_text:
                return None

            return ConceptNode(
                description=f"STRATEGIC INSIGHT: {insight_text}",
                poignancy=8.0,  # High importance
                node_type=NodeType.REFLECTION,
                pentest_relevance=PentestRelevance.ATTACK_PATH,
                spo_triple=SPOTriple(
                    subject="agent",
                    predicate="strategizes",
                    obj=insight_text[:50],
                ),
                parent_node_ids=[r.node_id for r in recent_reflections],
                target=target,
            )
        except Exception as e:
            logger.debug("LLM insight generation failed: %s", e)
            return None

    def notify_new_node(self, node: ConceptNode) -> None:
        """Notify the reflect module of a new node.

        Call this after adding nodes to memory to track reflection triggers.

        Args:
            node: The newly added node
        """
        self._nodes_since_reflection += 1

        # Critical findings trigger immediate reflection
        if node.pentest_relevance in [
            PentestRelevance.CRITICAL_VULN,
            PentestRelevance.CREDENTIAL,
        ]:
            self._nodes_since_reflection += 2  # Count as more significant


def create_reflect_module(
    memory_stream: MemoryStream,
    llm_client: Any | None = None,
) -> ReflectModule:
    """Factory function to create a ReflectModule.

    Args:
        memory_stream: MemoryStream instance
        llm_client: Optional LLM client

    Returns:
        Configured ReflectModule
    """
    return ReflectModule(
        memory_stream=memory_stream,
        llm_client=llm_client,
    )
