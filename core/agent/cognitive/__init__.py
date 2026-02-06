# core/agent/cognitive/__init__.py
"""DRAKBEN Cognitive Architecture - Stanford Generative Agents Style.

This package implements the cognitive cycle inspired by:
"Generative Agents: Interactive Simulacra of Human Behavior" (Stanford, 2023)

Cognitive Cycle:
1. PERCEIVE: Tool output -> ConceptNodes (sensory input)
2. RETRIEVE: Focal point -> Relevant memories (selective attention)
3. REFLECT: Memories -> Insights (higher-level thinking)

Integration Flow:
    tool_output -> PerceiveModule -> MemoryStream
                                          |
    LLM context <- RetrieveModule <-------+
                                          |
    insights <--- ReflectModule <---------+

Token Efficiency:
Instead of passing entire history to LLM:
- PentestGPT: ~70k tokens at 100 steps (linear growth)
- DRAKBEN: ~6k tokens constant (selective retrieval)
- 10-12x token reduction

Usage:
    from core.agent.cognitive import (
        PerceiveModule,
        RetrieveModule,
        ReflectModule,
        perceive_tool_output,
    )

    # Create modules with shared memory stream
    from core.agent.memory import get_memory_stream
    memory = get_memory_stream()

    perceive = PerceiveModule(memory)
    retrieve = RetrieveModule(memory)
    reflect = ReflectModule(memory)

    # Cognitive cycle
    nodes = perceive.perceive("nmap", nmap_output, target="192.168.1.100")
    context = retrieve.get_context_for_llm("exploit SSH", target="192.168.1.100")
    insights = reflect.reflect(target="192.168.1.100")
"""

from core.agent.cognitive.perceive import (
    PerceiveModule,
    perceive_tool_output,
)
from core.agent.cognitive.reflect import (
    ReflectModule,
    create_reflect_module,
)
from core.agent.cognitive.retrieve import (
    ContextBudget,
    RetrievedContext,
    RetrieveModule,
    create_retrieve_module,
)

__all__ = [
    # Data classes
    "ContextBudget",
    # Core modules
    "PerceiveModule",
    "ReflectModule",
    "RetrieveModule",
    "RetrievedContext",
    "create_reflect_module",
    # Factory functions
    "create_retrieve_module",
    # Convenience functions
    "perceive_tool_output",
]
