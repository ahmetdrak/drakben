# core/llm/ — LLM Infrastructure Package
# Token counting, output validation, multi-turn, RAG, streaming, function calling, async

from __future__ import annotations

__all__ = [
    "AsyncLLMClient",
    "FallbackChain",
    "LLMCache",
    "LLMEngine",
    "LLMOutputValidator",
    "MessageHistory",
    "PromptRegistry",
    "RAGPipeline",
    "TokenCounter",
    "get_prompt",
]

# Lazy imports to avoid circular dependencies
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TokenCounter": ("core.llm.token_counter", "TokenCounter"),
    "LLMOutputValidator": ("core.llm.output_models", "LLMOutputValidator"),
    "MessageHistory": ("core.llm.multi_turn", "MessageHistory"),
    "RAGPipeline": ("core.llm.rag_pipeline", "RAGPipeline"),
    "AsyncLLMClient": ("core.llm.async_client", "AsyncLLMClient"),
    "LLMEngine": ("core.llm.llm_engine", "LLMEngine"),
    "LLMCache": ("core.llm.llm_cache", "LLMCache"),
    "FallbackChain": ("core.llm.fallback_chain", "FallbackChain"),
    "PromptRegistry": ("core.llm.prompt_registry", "PromptRegistry"),
    "get_prompt": ("core.llm.prompt_registry", "get_prompt"),
}


def __getattr__(name: str):
    """Lazy import for package attributes."""
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path)
        return getattr(module, attr_name)
    msg = f"module 'core.llm' has no attribute {name!r}"
    raise AttributeError(msg)
