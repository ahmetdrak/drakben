# core/agent/brain_cognitive_memory.py
# DRAKBEN - Cognitive Memory Manager (extracted from brain.py)
# Stanford Generative Agents Memory Integration

import logging
from typing import Any

logger: logging.Logger = logging.getLogger(__name__)


class CognitiveMemoryManager:
    """Stanford-style Cognitive Memory System manager.

    Integrates:
    - MemoryStream: Persistent storage with importance scoring
    - RetrievalEngine: 4-factor retrieval (recency, importance, relevance, context)
    - PerceiveModule: Tool output → ConceptNode conversion
    - RetrieveModule: Token-efficient context retrieval
    - ReflectModule: Insight generation from patterns

    Reference: Park et al. "Generative Agents" (2023)
    """

    def __init__(self, llm_client: Any = None, db_path: str | None = None) -> None:
        """Initialize the Cognitive Memory System.

        Args:
            llm_client: LLM client for importance scoring and reflection
            db_path: Optional path for SQLite persistence

        """
        self.llm_client = llm_client
        self._initialized = False
        self._memory_stream: Any = None
        self._retrieval_engine: Any = None
        self._perceive: Any = None
        self._retrieve: Any = None
        self._reflect: Any = None

        try:
            # Import memory modules
            from core.agent.cognitive import PerceiveModule, ReflectModule, RetrieveModule
            from core.agent.memory import MemoryStream, RetrievalEngine

            # Try to initialize VectorStore for semantic embeddings
            vector_store = None
            try:
                from core.storage.vector_store import VectorStore
                vector_store = VectorStore()
                logger.debug("VectorStore initialized for semantic embeddings")
            except (ImportError, RuntimeError, OSError) as vs_err:
                logger.debug("VectorStore not available (optional): %s", vs_err)

            # Initialize core components with optional VectorStore
            self._memory_stream = MemoryStream(
                persist_path=db_path,
                vector_store=vector_store,
            )
            self._retrieval_engine = RetrievalEngine(memory_stream=self._memory_stream)

            # Initialize cognitive modules
            self._perceive = PerceiveModule(memory_stream=self._memory_stream)
            self._retrieve = RetrieveModule(memory_stream=self._memory_stream)
            self._reflect = ReflectModule(
                memory_stream=self._memory_stream,
                llm_client=llm_client,
            )

            self._initialized = True
            logger.debug("CognitiveMemoryManager initialized successfully")

        except ImportError as e:
            logger.warning("Memory modules not available: %s", e)
        except (RuntimeError, OSError, ValueError) as e:
            logger.warning("Failed to initialize CognitiveMemoryManager: %s", e)

    @property
    def is_initialized(self) -> bool:
        """Check if the memory system is properly initialized."""
        return self._initialized

    def perceive_tool_output(
        self,
        tool_name: str,
        tool_output: str,
        target: str | None = None,
        success: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> list[Any]:
        """Convert tool output to ConceptNodes and store in memory.

        Args:
            tool_name: Name of the tool that produced output
            tool_output: Raw output string from the tool
            target: Target IP/domain being tested
            success: Whether the tool execution was successful
            metadata: Additional metadata to attach

        Returns:
            List of created ConceptNode objects

        """
        if not self._initialized or not self._perceive:
            return []

        try:
            # PerceiveModule.perceive(tool_name, tool_output, target, metadata)
            meta = metadata or {}
            meta["success"] = success
            nodes = self._perceive.perceive(
                tool_name=tool_name,
                tool_output=tool_output,
                target=target,
                metadata=meta,
            )
            return nodes
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning("Failed to perceive tool output: %s", e, exc_info=True)
            return []

    def get_context_for_llm(
        self,
        query: str,
        target: str | None = None,
        _max_tokens: int = 2000,
        phase: str | None = None,
    ) -> str:
        """Retrieve relevant context for LLM prompt (token-efficient).

        Uses Stanford-style 4-factor retrieval:
        - Recency: Recent observations weighted higher
        - Importance: High-impact findings prioritized
        - Relevance: Semantic similarity to query
        - Context: Current phase/target relevance

        Args:
            query: Current task/question
            target: Target being tested
            _max_tokens: Token budget for context (managed by RetrieveModule)
            phase: Current pentest phase (recon, exploit, etc.)

        Returns:
            Formatted context string within token budget

        """
        if not self._initialized or not self._retrieve:
            return ""

        try:
            # RetrieveModule.retrieve_for_decision returns RetrievedContext
            retrieved_ctx = self._retrieve.retrieve_for_decision(
                focal_point=query,
                target=target,
                phase=phase,
            )
            return retrieved_ctx.context_string
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning("Failed to retrieve context: %s", e, exc_info=True)
            return ""

    def generate_reflections(
        self,
        target: str | None = None,
        _min_observations: int = 5,
        force: bool = False,
    ) -> list[Any]:
        """Generate high-level insights from accumulated observations.

        Follows Stanford pattern: After sufficient observations,
        synthesize patterns into higher-level "reflection" nodes.

        Args:
            target: Target to focus reflections on
            _min_observations: Reserved for future threshold configuration
            force: Force reflection even if threshold not met

        Returns:
            List of reflection ConceptNodes

        """
        if not self._initialized or not self._reflect:
            return []

        try:
            # ReflectModule.reflect(target, force)
            reflections = self._reflect.reflect(target=target, force=force)
            return reflections
        except (ValueError, TypeError, RuntimeError) as e:
            logger.warning("Failed to generate reflections: %s", e, exc_info=True)
            return []

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the memory system.

        Returns:
            Dictionary with memory statistics

        """
        if not self._initialized:
            return {"initialized": False}

        stats: dict[str, Any] = {
            "initialized": True,
            "total_nodes": 0,
            "observations": 0,
            "reflections": 0,
            "avg_importance": 0.0,
        }

        try:
            if self._memory_stream:
                stream_stats = self._memory_stream.get_stats()
                stats.update({
                    "total_nodes": stream_stats.get("total_nodes", 0),
                    "observations": stream_stats.get("observations", 0),
                    "reflections": stream_stats.get("reflections", 0),
                    "avg_importance": stream_stats.get("avg_importance", 0.0),
                })
        except (AttributeError, ValueError, TypeError) as e:
            logger.debug("Failed to get memory stats: %s", e)

        return stats
