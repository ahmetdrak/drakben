# core/agent/memory/concept_node.py
"""ConceptNode - Stanford Generative Agents Style Memory Unit.

This implements the foundational memory structure inspired by:
"Generative Agents: Interactive Simulacra of Human Behavior" (Stanford, 2023)

Each ConceptNode represents a discrete unit of memory:
- Events: Tool executions, observations, scan results
- Thoughts: Agent reasoning, decisions, hypotheses
- Findings: Vulnerabilities, credentials, attack paths
- Reflections: High-level insights derived from other memories

Key features:
- Poignancy scoring (1-10) for importance weighting
- SPO triple for graph-based retrieval
- Embedding support for semantic search
- Access tracking for recency calculations
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Types of memory nodes in the stream."""

    EVENT = "event"  # Tool output, scan result, observation
    THOUGHT = "thought"  # Reasoning, decision, hypothesis
    FINDING = "finding"  # Vulnerability, credential, weakness
    REFLECTION = "reflection"  # High-level insight from memories
    PLAN = "plan"  # Strategic plan or step


class PentestRelevance(Enum):
    """Pentest-specific relevance categories for boosted retrieval."""

    CRITICAL_VULN = "critical_vuln"  # RCE, SQLi, Auth bypass
    HIGH_VULN = "high_vuln"  # XSS, IDOR, Info disclosure
    CREDENTIAL = "credential"  # Any discovered credential
    ATTACK_PATH = "attack_path"  # Confirmed exploitation route
    SERVICE_INFO = "service_info"  # Port, version, banner
    RECON_DATA = "recon_data"  # General reconnaissance
    GENERIC = "generic"  # Non-pentest specific


# Pentest relevance boost factors
PENTEST_BOOST_FACTORS: dict[PentestRelevance, float] = {
    PentestRelevance.CRITICAL_VULN: 3.0,
    PentestRelevance.HIGH_VULN: 2.0,
    PentestRelevance.CREDENTIAL: 2.5,
    PentestRelevance.ATTACK_PATH: 2.0,
    PentestRelevance.SERVICE_INFO: 1.2,
    PentestRelevance.RECON_DATA: 1.0,
    PentestRelevance.GENERIC: 1.0,
}


@dataclass
class SPOTriple:
    """Subject-Predicate-Object triple for graph-based retrieval.

    Examples:
    - ("nmap", "discovered", "port 22 SSH")
    - ("sqlmap", "found", "SQL injection in /login")
    - ("agent", "hypothesizes", "RCE via file upload")
    """

    subject: str
    predicate: str
    obj: str  # 'object' is reserved in Python

    def to_sentence(self) -> str:
        """Convert SPO triple to natural language sentence."""
        return f"{self.subject} {self.predicate} {self.obj}"

    def matches(self, query_subject: str | None = None,
                query_predicate: str | None = None,
                query_obj: str | None = None) -> bool:
        """Check if triple matches a query pattern (None = wildcard)."""
        if query_subject and query_subject.lower() not in self.subject.lower():
            return False
        if query_predicate and query_predicate.lower() not in self.predicate.lower():
            return False
        return not (query_obj and query_obj.lower() not in self.obj.lower())


@dataclass
class ConceptNode:
    """A single unit of memory in the associative memory stream.

    Inspired by Stanford Generative Agents' memory architecture.
    Each node has:
    - Unique ID and timestamp
    - Description (natural language)
    - Poignancy score (1-10, importance)
    - Type (event, thought, finding, reflection)
    - SPO triple for graph queries
    - Embedding vector for semantic search
    - Access tracking for recency decay
    """

    # Core identification
    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""

    # Stanford-style poignancy (importance score 1-10)
    # Higher = more important to remember
    # Criteria: Does this affect the pentest outcome significantly?
    poignancy: float = 5.0

    # Timestamps
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)

    # Access tracking for recency calculations
    access_count: int = 0

    # Type classification
    node_type: NodeType = NodeType.EVENT

    # Pentest-specific relevance category
    pentest_relevance: PentestRelevance = PentestRelevance.GENERIC

    # SPO triple for graph-based retrieval
    spo_triple: SPOTriple | None = None

    # Embedding vector (populated by VectorStore)
    # None = not yet embedded, list[float] = embedded
    embedding: list[float] | None = None

    # Metadata for filtering and context
    metadata: dict = field(default_factory=dict)

    # Link to parent node (for reflections derived from other nodes)
    parent_node_ids: list[str] = field(default_factory=list)

    # Target context (for multi-target scenarios)
    target: str | None = None

    def touch(self) -> None:
        """Update access time and count (for recency tracking)."""
        self.last_accessed = time.time()
        self.access_count += 1

    def age_hours(self) -> float:
        """Calculate age of node in hours."""
        return (time.time() - self.created_at) / 3600.0

    def recency_score(self, decay_factor: float = 0.99) -> float:
        """Calculate recency score with exponential decay.

        Args:
            decay_factor: Decay rate per hour (0.99 = 1% decay per hour)

        Returns:
            Recency score between 0 and 1

        Stanford formula: recency = decay_factor ^ hours_since_access
        """
        hours_since_access = (time.time() - self.last_accessed) / 3600.0
        return decay_factor ** hours_since_access

    def get_pentest_boost(self) -> float:
        """Get pentest-specific boost factor for this node."""
        return PENTEST_BOOST_FACTORS.get(self.pentest_relevance, 1.0)

    def to_context_string(self, include_meta: bool = False) -> str:
        """Convert node to a string for LLM context.

        Args:
            include_meta: Include metadata in output

        Returns:
            Formatted string representation
        """
        parts = [f"[{self.node_type.value.upper()}]"]

        if self.poignancy >= 8:
            parts.append("⚠️ CRITICAL:")
        elif self.poignancy >= 6:
            parts.append("📌 IMPORTANT:")

        parts.append(self.description)

        if self.spo_triple:
            parts.append(f"({self.spo_triple.to_sentence()})")

        if include_meta and self.metadata:
            meta_str = ", ".join(f"{k}={v}" for k, v in self.metadata.items())
            parts.append(f"[{meta_str}]")

        return " ".join(parts)

    def to_dict(self) -> dict:
        """Serialize node to dictionary for persistence."""
        return {
            "node_id": self.node_id,
            "description": self.description,
            "poignancy": self.poignancy,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "access_count": self.access_count,
            "node_type": self.node_type.value,
            "pentest_relevance": self.pentest_relevance.value,
            "spo_triple": {
                "subject": self.spo_triple.subject,
                "predicate": self.spo_triple.predicate,
                "obj": self.spo_triple.obj,
            } if self.spo_triple else None,
            "embedding": self.embedding,
            "metadata": self.metadata,
            "parent_node_ids": self.parent_node_ids,
            "target": self.target,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ConceptNode:
        """Deserialize node from dictionary."""
        spo_data = data.get("spo_triple")
        spo_triple = None
        if spo_data:
            spo_triple = SPOTriple(
                subject=spo_data["subject"],
                predicate=spo_data["predicate"],
                obj=spo_data["obj"],
            )

        return cls(
            node_id=data.get("node_id", str(uuid.uuid4())),
            description=data.get("description", ""),
            poignancy=data.get("poignancy", 5.0),
            created_at=data.get("created_at", time.time()),
            last_accessed=data.get("last_accessed", time.time()),
            access_count=data.get("access_count", 0),
            node_type=NodeType(data.get("node_type", "event")),
            pentest_relevance=PentestRelevance(
                data.get("pentest_relevance", "generic"),
            ),
            spo_triple=spo_triple,
            embedding=data.get("embedding"),
            metadata=data.get("metadata", {}),
            parent_node_ids=data.get("parent_node_ids", []),
            target=data.get("target"),
        )


def create_event_node(
    description: str,
    tool: str,
    result: str,
    poignancy: float = 5.0,
    target: str | None = None,
    pentest_relevance: PentestRelevance = PentestRelevance.GENERIC,
) -> ConceptNode:
    """Factory function to create an event node from tool execution.

    Args:
        description: What happened
        tool: Tool that was executed
        result: Outcome (success/failure/finding)
        poignancy: Importance score (1-10)
        target: Target IP/domain
        pentest_relevance: Pentest-specific category

    Returns:
        Configured ConceptNode
    """
    return ConceptNode(
        description=description,
        poignancy=poignancy,
        node_type=NodeType.EVENT,
        pentest_relevance=pentest_relevance,
        spo_triple=SPOTriple(subject=tool, predicate="executed", obj=result),
        metadata={"tool": tool, "result_type": result},
        target=target,
    )


def create_finding_node(
    description: str,
    finding_type: str,
    severity: str,
    target: str | None = None,
) -> ConceptNode:
    """Factory function to create a finding node (vulnerability, credential, etc.).

    Args:
        description: Description of the finding
        finding_type: Type (vulnerability, credential, misconfig, etc.)
        severity: Severity level (critical, high, medium, low)
        target: Target IP/domain

    Returns:
        Configured ConceptNode with appropriate poignancy
    """
    # Map severity to poignancy
    severity_map = {
        "critical": (10.0, PentestRelevance.CRITICAL_VULN),
        "high": (8.0, PentestRelevance.HIGH_VULN),
        "medium": (6.0, PentestRelevance.HIGH_VULN),
        "low": (4.0, PentestRelevance.RECON_DATA),
    }
    poignancy, relevance = severity_map.get(
        severity.lower(),
        (5.0, PentestRelevance.GENERIC),
    )

    # Credentials always high importance
    if finding_type.lower() == "credential":
        poignancy = 9.0
        relevance = PentestRelevance.CREDENTIAL

    return ConceptNode(
        description=description,
        poignancy=poignancy,
        node_type=NodeType.FINDING,
        pentest_relevance=relevance,
        spo_triple=SPOTriple(
            subject="scan",
            predicate="discovered",
            obj=f"{finding_type}: {description[:50]}",
        ),
        metadata={"finding_type": finding_type, "severity": severity},
        target=target,
    )


def create_thought_node(
    description: str,
    reasoning_type: str = "hypothesis",
    confidence: float = 0.5,
    target: str | None = None,
) -> ConceptNode:
    """Factory function to create a thought/reasoning node.

    Args:
        description: The thought or reasoning
        reasoning_type: Type (hypothesis, decision, observation)
        confidence: Confidence level (0-1)
        target: Target IP/domain

    Returns:
        Configured ConceptNode
    """
    # Higher confidence = higher poignancy
    poignancy = 4.0 + (confidence * 4.0)  # Range: 4-8

    return ConceptNode(
        description=description,
        poignancy=poignancy,
        node_type=NodeType.THOUGHT,
        pentest_relevance=PentestRelevance.GENERIC,
        spo_triple=SPOTriple(
            subject="agent",
            predicate=reasoning_type,
            obj=description[:50],
        ),
        metadata={"reasoning_type": reasoning_type, "confidence": confidence},
        target=target,
    )


def create_reflection_node(
    description: str,
    source_node_ids: list[str],
    insight_type: str = "pattern",
    target: str | None = None,
) -> ConceptNode:
    """Factory function to create a reflection node (insight from memories).

    Args:
        description: The insight or reflection
        source_node_ids: IDs of nodes that led to this reflection
        insight_type: Type (pattern, strategy, lesson)
        target: Target IP/domain

    Returns:
        Configured ConceptNode
    """
    return ConceptNode(
        description=description,
        poignancy=7.0,  # Reflections are generally important
        node_type=NodeType.REFLECTION,
        pentest_relevance=PentestRelevance.ATTACK_PATH,
        spo_triple=SPOTriple(
            subject="agent",
            predicate="reflects",
            obj=description[:50],
        ),
        metadata={"insight_type": insight_type},
        parent_node_ids=source_node_ids,
        target=target,
    )
