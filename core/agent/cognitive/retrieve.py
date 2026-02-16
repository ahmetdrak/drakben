# core/agent/cognitive/retrieve.py
"""Retrieve Module - Stanford Cognitive Architecture.

The Retrieve module is the second stage of the cognitive cycle:
Focal Point → Relevant Memories

This module:
1. Takes a focal point (current situation/query)
2. Uses the RetrievalEngine to find relevant memories
3. Formats memories for LLM context
4. Manages context window budget

Stanford Reference:
"Given a focal point, the agent retrieves relevant memories using
a scoring function that combines recency, relevance, and importance."

Token Efficiency:
This is where the 10-12x token savings happen:
- Instead of 100+ history entries → retrieve 10-20 relevant nodes
- Context stays constant (~6k tokens) regardless of session length
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from core.agent.memory.concept_node import ConceptNode, NodeType
from core.agent.memory.retrieval import (
    RetrievalEngine,
    RetrievalResult,
    ScoredNode,
)

if TYPE_CHECKING:
    from core.agent.memory.memory_stream import MemoryStream
    from core.storage.vector_store import VectorStore

logger = logging.getLogger(__name__)


@dataclass
class ContextBudget:
    """Token budget allocation for context sections."""

    total_tokens: int = 4000  # Total budget
    critical_findings: int = 800  # For vulnerabilities, credentials
    recent_events: int = 1000  # For recent actions
    reasoning: int = 600  # For thoughts
    insights: int = 400  # For reflections
    reserved: int = 1200  # For system prompt + user input

    def validate(self) -> bool:
        """Validate budget doesn't exceed total."""
        allocated = self.critical_findings + self.recent_events + self.reasoning + self.insights + self.reserved
        return allocated <= self.total_tokens


@dataclass
class RetrievedContext:
    """Retrieved context ready for LLM consumption."""

    # Formatted context string
    context_string: str = ""

    # Raw nodes by category
    critical_findings: list[ConceptNode] = field(default_factory=list)
    recent_events: list[ConceptNode] = field(default_factory=list)
    reasoning: list[ConceptNode] = field(default_factory=list)
    insights: list[ConceptNode] = field(default_factory=list)

    # Metrics
    total_nodes: int = 0
    estimated_tokens: int = 0
    retrieval_time_ms: float = 0.0

    def get_summary(self) -> str:
        """Get a summary of retrieved context."""
        return (
            f"Context: {self.total_nodes} nodes, ~{self.estimated_tokens} tokens "
            f"(findings={len(self.critical_findings)}, events={len(self.recent_events)}, "
            f"thoughts={len(self.reasoning)}, insights={len(self.insights)})"
        )


class RetrieveModule:
    """Retrieves relevant memories for the current cognitive state.

    This module acts as the bridge between raw memory storage and
    the LLM's context window. It intelligently selects which memories
    to include based on the current focal point.
    """

    # Approximate chars per token for budget calculation
    CHARS_PER_TOKEN = 4

    def __init__(
        self,
        memory_stream: MemoryStream,
        vector_store: VectorStore | None = None,
        budget: ContextBudget | None = None,
    ) -> None:
        """Initialize the retrieve module.

        Args:
            memory_stream: MemoryStream to retrieve from
            vector_store: Optional VectorStore for semantic search
            budget: Token budget allocation
        """
        self._memory_stream = memory_stream
        self._vector_store = vector_store
        self._budget = budget or ContextBudget()
        self._retrieval_engine = RetrievalEngine(
            memory_stream=memory_stream,
            vector_store=vector_store,
        )

    def retrieve_for_decision(
        self,
        focal_point: str,
        target: str | None = None,
        phase: str | None = None,
        budget: ContextBudget | None = None,
    ) -> RetrievedContext:
        """Retrieve context for decision making.

        This is the main entry point for the cognitive cycle.
        Given a focal point (current situation), it retrieves
        the most relevant memories within the token budget.

        Args:
            focal_point: Current situation/query (what to focus on)
            target: Target IP/domain
            phase: Current attack phase
            budget: Optional budget override (defaults to self._budget)

        Returns:
            RetrievedContext ready for LLM
        """
        import time

        start_time = time.time()

        # Use phase-specific retrieval if phase provided
        if phase:
            result = self._retrieval_engine.retrieve_for_planning(
                current_phase=phase,
                target=target,
                n=30,  # Get more candidates for filtering
            )
        else:
            result = self._retrieval_engine.retrieve(
                query=focal_point,
                n=30,
                target=target,
            )

        # Categorize retrieved nodes
        context = self._categorize_and_budget(result, focal_point, budget=budget)

        # Build context string
        context.context_string = self._format_context_string(context)
        context.estimated_tokens = len(context.context_string) // self.CHARS_PER_TOKEN
        context.retrieval_time_ms = (time.time() - start_time) * 1000

        logger.debug(context.get_summary())

        return context

    def _categorize_and_budget(
        self,
        result: RetrievalResult,
        focal_point: str,
        budget: ContextBudget | None = None,
    ) -> RetrievedContext:
        """Categorize nodes and apply budget constraints.

        Args:
            result: Retrieval result with scored nodes
            focal_point: Current focal point (reserved for future use)
            budget: Optional budget override (defaults to self._budget)
        """
        # Note: focal_point kept for future weighting/prioritization
        _ = focal_point  # Acknowledge parameter for SonarQube
        active_budget = budget if budget is not None else self._budget
        context = RetrievedContext()

        # Separate by node type
        findings: list[ScoredNode] = []
        events: list[ScoredNode] = []
        thoughts: list[ScoredNode] = []
        reflections: list[ScoredNode] = []

        for scored in result.nodes:
            node_type = scored.node.node_type
            if node_type == NodeType.FINDING:
                findings.append(scored)
            elif node_type == NodeType.EVENT:
                events.append(scored)
            elif node_type == NodeType.THOUGHT:
                thoughts.append(scored)
            elif node_type == NodeType.REFLECTION:
                reflections.append(scored)

        # Apply budget to each category
        context.critical_findings = self._apply_budget(
            findings,
            active_budget.critical_findings,
        )
        context.recent_events = self._apply_budget(
            events,
            active_budget.recent_events,
        )
        context.reasoning = self._apply_budget(
            thoughts,
            active_budget.reasoning,
        )
        context.insights = self._apply_budget(
            reflections,
            active_budget.insights,
        )

        context.total_nodes = (
            len(context.critical_findings) + len(context.recent_events) + len(context.reasoning) + len(context.insights)
        )

        return context

    def _apply_budget(
        self,
        scored_nodes: list[ScoredNode],
        token_budget: int,
    ) -> list[ConceptNode]:
        """Select nodes within token budget.

        Args:
            scored_nodes: Sorted by score (highest first)
            token_budget: Maximum tokens for this category

        Returns:
            List of nodes fitting within budget
        """
        selected: list[ConceptNode] = []
        current_tokens = 0
        char_budget = token_budget * self.CHARS_PER_TOKEN

        for scored in scored_nodes:
            node = scored.node
            node_chars = len(node.to_context_string())

            if current_tokens + node_chars > char_budget:
                break

            selected.append(node)
            current_tokens += node_chars

        return selected

    def _format_context_string(self, context: RetrievedContext) -> str:
        """Format categorized nodes into a context string."""
        sections = []

        # Critical findings (always first)
        if context.critical_findings:
            section = "=== 🔴 CRITICAL FINDINGS ===\n"
            for node in context.critical_findings:
                section += f"• {node.to_context_string()}\n"
            sections.append(section)

        # Recent events
        if context.recent_events:
            section = "\n=== 📋 RECENT ACTIONS ===\n"
            for node in context.recent_events:
                section += f"• {node.to_context_string()}\n"
            sections.append(section)

        # Current reasoning
        if context.reasoning:
            section = "\n=== 💭 REASONING ===\n"
            for node in context.reasoning:
                section += f"• {node.description}\n"
            sections.append(section)

        # Insights
        if context.insights:
            section = "\n=== 💡 INSIGHTS ===\n"
            for node in context.insights:
                section += f"• {node.description}\n"
            sections.append(section)

        return "".join(sections)

    def get_context_for_llm(
        self,
        user_input: str,
        target: str | None = None,
        phase: str | None = None,
        max_tokens: int = 3000,
    ) -> str:
        """High-level API to get formatted context for LLM.

        This is the KEY FUNCTION for integration with brain.py.
        It returns a ready-to-use context string.

        Args:
            user_input: User's input/query
            target: Target IP/domain
            phase: Current attack phase
            max_tokens: Maximum tokens for context

        Returns:
            Formatted context string
        """
        # Adjust budget based on max_tokens
        adjusted_budget = ContextBudget(
            total_tokens=max_tokens,
            critical_findings=int(max_tokens * 0.2),
            recent_events=int(max_tokens * 0.25),
            reasoning=int(max_tokens * 0.15),
            insights=int(max_tokens * 0.1),
            reserved=int(max_tokens * 0.3),
        )

        # Thread-safe: pass budget directly instead of swapping self._budget
        context = self.retrieve_for_decision(
            focal_point=user_input,
            target=target,
            phase=phase,
            budget=adjusted_budget,
        )

        return context.context_string


def create_retrieve_module(
    memory_stream: MemoryStream,
    vector_store: VectorStore | None = None,
) -> RetrieveModule:
    """Factory function to create a RetrieveModule.

    Args:
        memory_stream: MemoryStream instance
        vector_store: Optional VectorStore

    Returns:
        Configured RetrieveModule
    """
    return RetrieveModule(
        memory_stream=memory_stream,
        vector_store=vector_store,
    )
