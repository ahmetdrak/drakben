# core/agent/memory/retrieval.py
"""RetrievalEngine - Stanford Generative Agents Style Selective Retrieval.

This implements the core retrieval algorithm from Stanford's Generative Agents paper:
"Generative Agents: Interactive Simulacra of Human Behavior"

The retrieval formula combines four factors:
1. Recency: How recently was the memory accessed? (exponential decay)
2. Relevance: How semantically similar to the query? (embedding similarity)
3. Importance: How poignant/significant is the memory? (poignancy score)
4. Pentest Weight: How relevant to pentesting? (custom boost factor)

Stanford Formula:
    final_score = recency_w * recency * 0.5 +
                  relevance_w * relevance * 3.0 +
                  importance_w * importance * 2.0

DRAKBEN Extension (Pentest-specific):
    final_score += pentest_w * pentest_boost * 1.5

This selective retrieval is KEY to token efficiency:
- Instead of passing 100+ history entries, we retrieve 10-20 relevant nodes
- Estimated 10-12x token reduction vs linear history approaches
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.agent.memory.concept_node import (
    ConceptNode,
    NodeType,
    PentestRelevance,
)

if TYPE_CHECKING:
    from core.agent.memory.memory_stream import MemoryStream
    from core.storage.vector_store import VectorStore

logger = logging.getLogger(__name__)


@dataclass
class RetrievalWeights:
    """Configurable weights for the retrieval formula.

    These weights determine the relative importance of each factor.
    Tuned for pentesting scenarios where:
    - Recent actions matter most (what just happened)
    - Critical findings should always surface
    - Semantic relevance helps connect related concepts
    """

    recency: float = 1.0  # Weight for recency factor
    relevance: float = 1.0  # Weight for semantic relevance
    importance: float = 1.0  # Weight for poignancy/importance
    pentest_boost: float = 1.0  # Weight for pentest-specific boost

    # Stanford-style scaling factors (from the paper)
    # These scale the raw scores before weighting
    recency_scale: float = 0.5  # Recency contributes less (temporal decay)
    relevance_scale: float = 3.0  # Relevance is most important
    importance_scale: float = 2.0  # Importance matters significantly
    pentest_scale: float = 1.5  # Pentest boost is additive


@dataclass
class ScoredNode:
    """A ConceptNode with its retrieval score breakdown."""

    node: ConceptNode
    total_score: float = 0.0
    recency_score: float = 0.0
    relevance_score: float = 0.0
    importance_score: float = 0.0
    pentest_score: float = 0.0


@dataclass
class RetrievalResult:
    """Result of a retrieval operation."""

    nodes: list[ScoredNode] = field(default_factory=list)
    query: str = ""
    focal_point: str = ""
    retrieval_time_ms: float = 0.0
    total_candidates: int = 0
    returned_count: int = 0


class RetrievalEngine:
    """Stanford-style retrieval engine for associative memory.

    Implements the 4-factor retrieval formula:
    - Recency: Exponential decay based on last access time
    - Relevance: Semantic similarity via embeddings
    - Importance: Poignancy score (1-10)
    - Pentest: Domain-specific boost factors

    Usage:
        engine = RetrievalEngine(memory_stream, vector_store)
        results = engine.retrieve("SQL injection", n=10)
        for scored in results.nodes:
            print(f"{scored.node.description}: {scored.total_score:.2f}")
    """

    # Decay factor for recency calculation (per hour)
    # 0.99^24 ≈ 0.79 (21% decay per day)
    DEFAULT_DECAY_FACTOR = 0.99

    def __init__(
        self,
        memory_stream: MemoryStream,
        vector_store: VectorStore | None = None,
        weights: RetrievalWeights | None = None,
        decay_factor: float = DEFAULT_DECAY_FACTOR,
    ) -> None:
        """Initialize the retrieval engine.

        Args:
            memory_stream: MemoryStream to retrieve from
            vector_store: Optional VectorStore for semantic search
            weights: Custom weights (None = defaults)
            decay_factor: Recency decay factor per hour
        """
        self._memory_stream = memory_stream
        self._vector_store = vector_store
        self._weights = weights or RetrievalWeights()
        self._decay_factor = decay_factor

    def retrieve(
        self,
        query: str,
        n: int = 10,
        target: str | None = None,
        include_types: list[NodeType] | None = None,
        min_score: float = 0.0,
    ) -> RetrievalResult:
        """Retrieve the most relevant memories for a query.

        This is the CORE RETRIEVAL FUNCTION implementing Stanford's formula.

        Args:
            query: Natural language query (focal point)
            n: Number of nodes to retrieve
            target: Optional target filter
            include_types: Node types to consider (None = all)
            min_score: Minimum score threshold

        Returns:
            RetrievalResult with scored nodes
        """
        start_time = time.time()

        # Step 1: Get semantic relevance scores from vector store
        relevance_scores: dict[str, float] = {}
        if self._vector_store:
            relevance_scores = self._compute_relevance_scores(query, n * 3)

        # Step 2: Get candidate nodes from memory stream
        candidates = self._get_candidates(target, include_types)

        # Step 3: Score each candidate
        scored_nodes: list[ScoredNode] = []
        for node in candidates:
            scored = self._score_node(node, relevance_scores)
            if scored.total_score >= min_score:
                scored_nodes.append(scored)

        # Step 4: Sort by total score (descending)
        scored_nodes.sort(key=lambda x: x.total_score, reverse=True)

        # Step 5: Return top N
        top_nodes = scored_nodes[:n]

        # Touch accessed nodes to update recency
        for scored in top_nodes:
            scored.node.touch()

        elapsed_ms = (time.time() - start_time) * 1000

        return RetrievalResult(
            nodes=top_nodes,
            query=query,
            focal_point=query,
            retrieval_time_ms=elapsed_ms,
            total_candidates=len(candidates),
            returned_count=len(top_nodes),
        )

    def _compute_relevance_scores(
        self,
        query: str,
        n: int,
    ) -> dict[str, float]:
        """Compute semantic relevance scores using vector store.

        Args:
            query: The query string
            n: Number of results to fetch

        Returns:
            Dict mapping node_id to relevance score (0-1)
        """
        scores: dict[str, float] = {}

        if not self._vector_store:
            return scores

        try:
            results = self._vector_store.search(query, n_results=n)

            for result in results:
                metadata = result.get("metadata", {})
                node_id = metadata.get("node_id")
                if node_id:
                    # Convert distance to similarity (lower distance = higher similarity)
                    distance = result.get("distance", 0.5)
                    similarity = max(0.0, 1.0 - distance)
                    scores[node_id] = similarity

        except Exception as e:
            logger.debug("Vector search failed: %s", e)

        return scores

    def _get_candidates(
        self,
        target: str | None,
        include_types: list[NodeType] | None,
    ) -> list[ConceptNode]:
        """Get candidate nodes for scoring.

        Args:
            target: Optional target filter
            include_types: Optional type filter

        Returns:
            List of candidate ConceptNodes
        """
        # Get recent nodes as base candidates
        candidates = self._memory_stream.get_recent(n=200, target=target)

        # Filter by type if specified
        if include_types:
            candidates = [n for n in candidates if n.node_type in include_types]

        return candidates

    def _score_node(
        self,
        node: ConceptNode,
        relevance_scores: dict[str, float],
    ) -> ScoredNode:
        """Score a single node using the Stanford formula.

        Stanford Formula (adapted):
            score = w_r * recency * 0.5 +
                    w_v * relevance * 3.0 +
                    w_i * importance * 2.0 +
                    w_p * pentest * 1.5

        Args:
            node: The node to score
            relevance_scores: Pre-computed relevance scores

        Returns:
            ScoredNode with score breakdown
        """
        w = self._weights

        # 1. Recency score (exponential decay)
        recency = node.recency_score(self._decay_factor)
        recency_component = w.recency * recency * w.recency_scale

        # 2. Relevance score (semantic similarity)
        relevance = relevance_scores.get(node.node_id, 0.5)  # Default to 0.5 if no embedding
        relevance_component = w.relevance * relevance * w.relevance_scale

        # 3. Importance score (poignancy normalized to 0-1)
        importance = node.poignancy / 10.0  # Normalize from 1-10 to 0-1
        importance_component = w.importance * importance * w.importance_scale

        # 4. Pentest boost (domain-specific)
        pentest_boost = node.get_pentest_boost()
        # Normalize boost (1.0-3.0 range to 0-1 range)
        normalized_boost = (pentest_boost - 1.0) / 2.0
        pentest_component = w.pentest_boost * normalized_boost * w.pentest_scale

        # Total score
        total = recency_component + relevance_component + importance_component + pentest_component

        return ScoredNode(
            node=node,
            total_score=total,
            recency_score=recency_component,
            relevance_score=relevance_component,
            importance_score=importance_component,
            pentest_score=pentest_component,
        )

    def retrieve_for_planning(
        self,
        current_phase: str,
        target: str | None = None,
        n: int = 15,
    ) -> RetrievalResult:
        """Specialized retrieval for planning context.

        Retrieves memories most relevant to the current attack phase.

        Args:
            current_phase: Current attack phase (recon, vuln_scan, exploit, etc.)
            target: Target IP/domain
            n: Number of nodes to retrieve

        Returns:
            RetrievalResult optimized for planning
        """
        # Build phase-specific query
        phase_queries = {
            "recon": "port scan service discovery reconnaissance target information",
            "vuln_scan": "vulnerability CVE exploit weakness security flaw",
            "exploit": "attack payload exploit RCE shell access",
            "foothold": "shell access reverse connection persistence",
            "post_exploit": "privilege escalation lateral movement data exfiltration",
        }

        query = phase_queries.get(current_phase, current_phase)

        # Boost importance for planning
        planning_weights = RetrievalWeights(
            recency=0.8,  # Recent matters
            relevance=1.2,  # Phase relevance boosted
            importance=1.5,  # Critical findings boosted
            pentest_boost=1.3,  # Pentest-specific boost
        )

        # Temporarily use planning weights
        original_weights = self._weights
        self._weights = planning_weights

        result = self.retrieve(
            query=query,
            n=n,
            target=target,
            include_types=[NodeType.EVENT, NodeType.FINDING, NodeType.REFLECTION],
        )

        # Restore original weights
        self._weights = original_weights

        return result

    def retrieve_for_context(
        self,
        user_input: str,
        target: str | None = None,
        max_tokens: int = 2000,
    ) -> str:
        """Retrieve and format memories as LLM context.

        This is the KEY FUNCTION for token efficiency.
        Instead of passing raw history, we retrieve relevant memories
        and format them efficiently.

        Args:
            user_input: User's input/query
            target: Target IP/domain
            max_tokens: Maximum tokens for context

        Returns:
            Formatted context string for LLM
        """
        # Estimate nodes based on tokens (avg ~100 tokens per node)
        estimated_nodes = max(5, max_tokens // 100)

        # Retrieve relevant memories
        result = self.retrieve(
            query=user_input,
            n=estimated_nodes,
            target=target,
        )

        if not result.nodes:
            return ""

        # Group nodes by type
        by_type = self._group_nodes_by_type(result.nodes)

        # Format as context string
        return self._format_context_sections(by_type)

    def _group_nodes_by_type(
        self,
        nodes: list[ScoredNode],
    ) -> dict[NodeType, list[ScoredNode]]:
        """Group scored nodes by their node type."""
        by_type: dict[NodeType, list[ScoredNode]] = {}
        for scored in nodes:
            ntype = scored.node.node_type
            if ntype not in by_type:
                by_type[ntype] = []
            by_type[ntype].append(scored)
        return by_type

    def _format_context_sections(
        self,
        by_type: dict[NodeType, list[ScoredNode]],
    ) -> str:
        """Format grouped nodes into context sections."""
        lines = ["=== RELEVANT CONTEXT (from memory) ==="]

        # Section configurations: (type, header, limit, use_context_string)
        sections = [
            (NodeType.FINDING, "\n📌 Key Findings:", 5, False),
            (NodeType.EVENT, "\n📋 Recent Actions:", 5, True),
            (NodeType.THOUGHT, "\n💭 Current Reasoning:", 3, False),
            (NodeType.REFLECTION, "\n💡 Insights:", 2, False),
        ]

        for node_type, header, limit, use_context in sections:
            if node_type in by_type:
                lines.append(header)
                for scored in by_type[node_type][:limit]:
                    if use_context:
                        lines.append(f"  - {scored.node.to_context_string()}")
                    else:
                        lines.append(f"  - {scored.node.description}")

        return "\n".join(lines)

    def get_attack_path_context(
        self,
        target: str,
        n: int = 10,
    ) -> list[ConceptNode]:
        """Get nodes forming a potential attack path.

        Specialized retrieval that traces the chain of:
        recon → vulnerability → exploit → foothold

        Args:
            target: Target IP/domain
            n: Maximum nodes to return

        Returns:
            List of nodes forming attack path
        """
        # Query for attack path related memories
        result = self.retrieve(
            query="vulnerability exploit attack foothold shell access credential",
            n=n * 2,
            target=target,
            include_types=[NodeType.FINDING, NodeType.EVENT, NodeType.REFLECTION],
        )

        # Filter for high-poignancy attack-related nodes
        attack_nodes = [
            scored.node for scored in result.nodes
            if scored.node.poignancy >= 6.0
            or scored.node.pentest_relevance in [
                PentestRelevance.CRITICAL_VULN,
                PentestRelevance.HIGH_VULN,
                PentestRelevance.CREDENTIAL,
                PentestRelevance.ATTACK_PATH,
            ]
        ]

        # Sort by creation time to show progression
        attack_nodes.sort(key=lambda x: x.created_at)

        return attack_nodes[:n]


def create_retrieval_engine(
    memory_stream: MemoryStream,
    vector_store: VectorStore | None = None,
    weights: RetrievalWeights | None = None,
) -> RetrievalEngine:
    """Factory function to create a configured RetrievalEngine.

    Args:
        memory_stream: MemoryStream instance
        vector_store: Optional VectorStore for embeddings
        weights: Optional custom weights

    Returns:
        Configured RetrievalEngine
    """
    return RetrievalEngine(
        memory_stream=memory_stream,
        vector_store=vector_store,
        weights=weights,
    )
