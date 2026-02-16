# core/llm/rag_pipeline.py
# DRAKBEN — RAG (Retrieval-Augmented Generation) Pipeline
# Enriches LLM prompts with relevant CVE/exploit data from VectorStore.
# Eliminates reliance on LLM's training data for vulnerability knowledge.

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class RAGPipeline:
    """Retrieval-Augmented Generation pipeline for DRAKBEN.

    Queries the existing VectorStore (ChromaDB) for relevant CVE/exploit
    data and injects it into LLM prompts as context.

    Usage::

        rag = RAGPipeline(vector_store=vs)
        enriched_prompt = rag.enrich_prompt(
            user_query="Apache 2.4.49 vulnerabilities",
            system_prompt="You are DRAKBEN...",
        )
        # enriched_prompt now includes relevant CVE data from vector DB

    """

    # Maximum context characters to inject from RAG results
    MAX_RAG_CONTEXT_CHARS = 3000

    # Relevance threshold (cosine distance — lower is more similar)
    RELEVANCE_THRESHOLD = 1.5

    def __init__(
        self,
        vector_store: Any = None,
        *,
        n_results: int = 5,
    ) -> None:
        """Initialize RAG pipeline.

        Args:
            vector_store: VectorStore instance for semantic search.
            n_results: Number of search results to retrieve.

        """
        self._vector_store = vector_store
        self._n_results = n_results
        self._stats = {"queries": 0, "hits": 0, "enrichments": 0}

        if vector_store is None:
            self._try_auto_init()

    def _try_auto_init(self) -> None:
        """Try to auto-initialize VectorStore if available."""
        try:
            from core.storage.vector_store import VectorStore

            self._vector_store = VectorStore()
            if self._vector_store.collection:
                logger.info("RAG pipeline auto-initialized with VectorStore")
            else:
                self._vector_store = None
                logger.debug("VectorStore has no collection — RAG disabled")
        except ImportError:
            logger.debug("VectorStore not available — RAG pipeline disabled")
        except (RuntimeError, OSError, ValueError) as exc:
            logger.debug("VectorStore init failed: %s", exc)
            self._vector_store = None

    @property
    def available(self) -> bool:
        """Check if RAG pipeline is operational."""
        return self._vector_store is not None and hasattr(self._vector_store, "search")

    def retrieve(self, query: str, *, n_results: int | None = None) -> list[dict[str, Any]]:
        """Retrieve relevant documents from vector store.

        Args:
            query: Search query text.
            n_results: Number of results (overrides default).

        Returns:
            List of relevant documents with text, metadata, and distance.

        """
        if not self.available:
            return []

        self._stats["queries"] += 1
        count = n_results or self._n_results

        try:
            results = self._vector_store.search(query, n_results=count)

            # Filter by relevance threshold
            relevant = [r for r in results if r.get("distance", 999) < self.RELEVANCE_THRESHOLD]

            if relevant:
                self._stats["hits"] += 1

            return relevant

        except (ValueError, RuntimeError) as exc:
            logger.debug("RAG retrieval failed: %s", exc)
            return []

    def enrich_prompt(
        self,
        user_query: str,
        system_prompt: str,
        *,
        section_header: str = "### RELEVANT KNOWLEDGE (from exploit/CVE database)",
    ) -> str:
        """Enrich a system prompt with RAG-retrieved context.

        Args:
            user_query: The user's query to search for.
            system_prompt: The original system prompt to enrich.
            section_header: Header text for the injected section.

        Returns:
            Enriched system prompt with relevant knowledge injected.

        """
        results = self.retrieve(user_query)

        if not results:
            return system_prompt

        # Build context from results
        context_parts: list[str] = []
        total_chars = 0

        for result in results:
            entry = self._format_rag_entry(result)
            if total_chars + len(entry) > self.MAX_RAG_CONTEXT_CHARS:
                break
            context_parts.append(entry)
            total_chars += len(entry)

        if not context_parts:
            return system_prompt

        self._stats["enrichments"] += 1
        rag_context = "\n---\n".join(context_parts)
        return f"{system_prompt}\n\n{section_header}\n{rag_context}"

    @staticmethod
    def _format_rag_entry(result: dict) -> str:
        """Format a single RAG retrieval result into a context entry."""
        text = result.get("text", "")
        metadata = result.get("metadata", {})
        distance = result.get("distance", 0)

        entry_parts: list[str] = []
        if "cve_id" in metadata:
            entry_parts.append(f"CVE: {metadata['cve_id']}")
        if "tool" in metadata:
            entry_parts.append(f"Source: {metadata['tool']}")
        if "severity" in metadata:
            entry_parts.append(f"Severity: {metadata['severity']}")
        entry_parts.append(f"Relevance: {1 - distance:.2f}")
        entry_parts.append(text[:500])

        if len(entry_parts) > 1:
            metadata_line = " | ".join(entry_parts[:-1])
            return metadata_line + "\n" + entry_parts[-1]
        return entry_parts[0] if entry_parts else text[:500]

    def ingest_cve(
        self,
        cve_id: str,
        description: str,
        *,
        severity: str = "unknown",
        cvss_score: float = 0.0,
        references: list[str] | None = None,
    ) -> bool:
        """Ingest a CVE entry into the vector store for future retrieval.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234).
            description: Vulnerability description.
            severity: CVSS severity level.
            cvss_score: CVSS numerical score.
            references: Reference URLs.

        Returns:
            True if successfully ingested.

        """
        if not self.available:
            return False

        try:
            metadata = {
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "type": "cve",
            }
            if references:
                metadata["references"] = ",".join(references[:5])

            text = f"{cve_id}: {description}"
            return self._vector_store.add_memory(text, metadata)
        except (ValueError, TypeError, RuntimeError) as exc:
            logger.debug("CVE ingestion failed: %s", exc)
            return False

    def ingest_exploit(
        self,
        name: str,
        description: str,
        *,
        target_service: str = "",
        exploit_type: str = "",
    ) -> bool:
        """Ingest an exploit/technique into the vector store.

        Args:
            name: Exploit name or identifier.
            description: Exploit description and usage.
            target_service: Targeted service (e.g., "Apache 2.4").
            exploit_type: Type (e.g., "RCE", "SQLi", "XSS").

        Returns:
            True if successfully ingested.

        """
        if not self.available:
            return False

        try:
            metadata = {
                "name": name,
                "target_service": target_service,
                "exploit_type": exploit_type,
                "type": "exploit",
            }
            text = f"{name}: {description}"
            return self._vector_store.add_memory(text, metadata)
        except (ValueError, TypeError, RuntimeError) as exc:
            logger.debug("Exploit ingestion failed: %s", exc)
            return False

    def ingest_tool_output(
        self,
        tool_name: str,
        output: str,
        *,
        target: str = "",
    ) -> bool:
        """Ingest tool execution output for future reference.

        Args:
            tool_name: Name of the tool that produced the output.
            output: Tool's raw output.
            target: Target that was scanned.

        Returns:
            True if successfully ingested.

        """
        if not self.available:
            return False

        try:
            metadata = {
                "tool": tool_name,
                "target": target,
                "type": "tool_output",
            }
            # Truncate very long outputs
            text = f"[{tool_name}] {output[:2000]}"
            return self._vector_store.add_memory(text, metadata)
        except (ValueError, TypeError, RuntimeError) as exc:
            logger.debug("Tool output ingestion failed: %s", exc)
            return False

    def get_stats(self) -> dict[str, Any]:
        """Return RAG pipeline statistics."""
        stats = dict(self._stats)
        stats["available"] = self.available
        if self.available:
            stats["vector_count"] = self._vector_store.count()
        return stats
