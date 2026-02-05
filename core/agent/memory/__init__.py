# core/agent/memory/__init__.py
"""DRAKBEN Memory System - Stanford Generative Agents Style.

This package implements a sophisticated memory system inspired by:
"Generative Agents: Interactive Simulacra of Human Behavior" (Stanford, 2023)

Key Components:
- ConceptNode: Individual memory units with poignancy scoring
- MemoryStream: Associative memory storage with multi-index retrieval
- RetrievalEngine: 4-factor retrieval (recency, relevance, importance, pentest)

Token Efficiency:
Instead of passing entire history to LLM (linear growth = 70k tokens at 100 steps),
this system selectively retrieves only relevant memories (constant ~6k tokens).
Estimated 10-12x token reduction vs PentestGPT approach.

Usage:
    from core.agent.memory import (
        ConceptNode,
        MemoryStream,
        RetrievalEngine,
        create_event_node,
        create_finding_node,
        get_memory_stream,
    )

    # Create and store a finding
    finding = create_finding_node(
        description="SQL injection in /login endpoint",
        finding_type="vulnerability",
        severity="critical",
        target="192.168.1.100",
    )
    memory = get_memory_stream()
    memory.add(finding)

    # Retrieve relevant context for LLM
    engine = RetrievalEngine(memory)
    context = engine.retrieve_for_context("exploit SQL injection")
"""

from core.agent.memory.concept_node import (
    PENTEST_BOOST_FACTORS,
    ConceptNode,
    NodeType,
    PentestRelevance,
    SPOTriple,
    create_event_node,
    create_finding_node,
    create_reflection_node,
    create_thought_node,
)
from core.agent.memory.memory_stream import (
    MemoryStream,
    get_memory_stream,
    reset_memory_stream,
)
from core.agent.memory.retrieval import (
    RetrievalEngine,
    RetrievalResult,
    RetrievalWeights,
    ScoredNode,
    create_retrieval_engine,
)

__all__ = [
    # Core classes
    "ConceptNode",
    "MemoryStream",
    "RetrievalEngine",
    # Enums
    "NodeType",
    "PentestRelevance",
    # Data classes
    "SPOTriple",
    "RetrievalResult",
    "RetrievalWeights",
    "ScoredNode",
    # Factory functions
    "create_event_node",
    "create_finding_node",
    "create_thought_node",
    "create_reflection_node",
    "create_retrieval_engine",
    # Singleton accessors
    "get_memory_stream",
    "reset_memory_stream",
    # Constants
    "PENTEST_BOOST_FACTORS",
]
