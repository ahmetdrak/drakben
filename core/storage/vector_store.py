# core/vector_store.py
# Semantic Vector Memory for DRAKBEN (RAG System)

import logging
import uuid
from typing import Any

# Configure logger
logger = logging.getLogger(__name__)

# Try to import ChromaDB gracefully
DEPENDENCIES_AVAILABLE = False
try:
    import chromadb

    DEPENDENCIES_AVAILABLE = True
except ImportError:
    logger.warning(
        "ChromaDB not found. Vector memory disabled (falling back to exact match).",
    )
except Exception as e:
    logger.warning("ChromaDB initialization error: %s", e)


class VectorStore:
    """Implements Semantic Search/Memory using ChromaDB.
    Equivalent to PentAGI's pgvector + RAG.
    """

    def __init__(self, persist_dir: str = "drakben_vectors") -> None:
        self.persist_dir = persist_dir
        self.client = None
        self.collection = None

        if DEPENDENCIES_AVAILABLE:
            try:
                # Initialize persistent client
                self.client = chromadb.PersistentClient(path=persist_dir)

                # Get or create collection
                self.collection = self.client.get_or_create_collection(
                    name="drakben_memory",
                    metadata={"hnsw:space": "cosine"},
                )
                logger.info("Vector Store initialized at %s", persist_dir)
            except Exception as e:
                logger.exception("Failed to initialize Vector Store: %s", e)
                self.client = None

    def add_memory(self, text: str, metadata: dict[str, Any] | None = None) -> bool:
        """Add a text memory to the vector store."""
        if not self.collection:
            return False

        try:
            doc_id = str(uuid.uuid4())
            if metadata is None:
                metadata = {}

            # Add timestamp
            import time

            metadata["timestamp"] = time.time()

            self.collection.add(documents=[text], metadatas=[metadata], ids=[doc_id])
            return True
        except Exception as e:
            logger.exception("Failed to add memory: %s", e)
            return False

    def search(self, query: str, n_results: int = 5) -> list[dict]:
        """Semantic search for similar memories.

        Returns:
            List of dicts with 'text', 'metadata', 'distance'

        """
        if not self.collection:
            return []

        try:
            results = self.collection.query(query_texts=[query], n_results=n_results)

            output: list[dict] = []
            documents = results.get("documents")
            metadatas = results.get("metadatas")
            distances = results.get("distances")

            if documents and documents[0]:
                output.extend(
                    {
                        "text": documents[0][i],
                        "metadata": metadatas[0][i] if metadatas else {},
                        "distance": distances[0][i] if distances else 0.0,
                    }
                    for i in range(len(documents[0]))
                )
            return output
        except Exception as e:
            logger.exception("Search failed: %s", e)
            return []

    def count(self) -> int:
        """Return total memories."""
        if self.collection:
            return self.collection.count()
        return 0



