# core/llm/llm_engine.py
# DRAKBEN — Unified LLM Engine
# Integrates ALL LLM capabilities into a single coherent interface:
# - Streaming (token-by-token)
# - Function Calling (guaranteed schema)
# - Token Counting (auto context window trim)
# - Multi-Turn (conversation memory)
# - Output Validation (auto-retry on bad JSON)
# - RAG Pipeline (CVE/exploit enrichment)
# - Async (ainvoke, abatch, astream)
#
# This replaces raw OpenRouterClient.query() calls with a smart engine
# that automatically manages context, validates output, and enriches prompts.

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

logger = logging.getLogger(__name__)

# Error message constants (SonarCloud: avoid duplicate literals)
_MSG_OFFLINE = "[Offline] No LLM client configured."


class LLMEngine:
    """Unified LLM engine combining all DRAKBEN intelligence layers.

    Usage::

        engine = LLMEngine()

        # Simple query (auto token-trimmed, validated)
        result = engine.query("Scan 10.0.0.1 for open ports")

        # Streaming (token by token)
        for chunk in engine.stream("Explain SQL injection"):
            print(chunk, end="", flush=True)

        # Function calling (guaranteed tool selection)
        tools = engine.get_tool_schemas(["nmap", "nikto", "sqlmap"])
        result = engine.call_with_tools("Scan target", tools)

        # Multi-turn (LLM sees its own history)
        engine.add_user_message("Scan 10.0.0.1")
        result = engine.query_with_history()
        engine.add_assistant_message(result)

        # RAG-enriched (inject CVE/exploit knowledge)
        result = engine.query_with_rag("Apache 2.4.49 vulnerabilities")

    """

    def __init__(
        self,
        llm_client: Any = None,
        *,
        model: str = "",
        system_prompt: str = "",
        enable_rag: bool = True,
        enable_validation: bool = True,
        enable_token_management: bool = True,
        enable_cache: bool = True,
        cache_ttl: float = 300.0,
        max_history: int = 50,
    ) -> None:
        self._client = llm_client
        self._model = model
        self._default_timeout = 30

        # ── Multi-Turn History ──
        self._history = None
        self._init_history(system_prompt, max_history)

        # ── Token Counter ──
        self._token_counter = None
        if enable_token_management:
            self._init_token_counter(model)

        # ── Output Validator ──
        self._validator = None
        if enable_validation:
            self._init_validator()

        # ── RAG Pipeline ──
        self._rag = None
        if enable_rag:
            self._init_rag()

        # ── Response Cache ──
        self._cache = None
        if enable_cache:
            self._init_cache(cache_ttl)

        # ── Context Compressor (Intelligence v2) ──
        self._context_compressor: Any = None
        self._init_context_compressor()

        # ── Model Router (Intelligence v3) ──
        self._model_router: Any = None
        self._init_model_router()

        # ── Stats ──
        self._stats = {
            "queries": 0,
            "streams": 0,
            "tool_calls": 0,
            "rag_enrichments": 0,
            "validation_repairs": 0,
            "tokens_saved_by_trim": 0,
            "cache_hits": 0,
        }

        # Auto-init LLM client if needed
        if self._client is None:
            self._auto_init_client()

    # ─────────────────────── Initialization ───────────────────────

    def _auto_init_client(self) -> None:
        """Auto-initialize LLM client from environment."""
        try:
            from llm.openrouter_client import OpenRouterClient
            self._client = OpenRouterClient()
            if not self._model:
                self._model = self._client.model
        except (ImportError, OSError) as exc:
            logger.debug("Could not auto-init LLM client: %s", exc)

    def _init_history(self, system_prompt: str, max_messages: int) -> None:
        try:
            from core.llm.multi_turn import MessageHistory
            self._history = MessageHistory(  # type: ignore[assignment]
                system_prompt=system_prompt,
                max_messages=max_messages,
            )
        except ImportError:
            logger.debug("MessageHistory unavailable — multi-turn disabled.")

    def _init_token_counter(self, model: str) -> None:
        try:
            from core.llm.token_counter import TokenCounter
            self._token_counter = TokenCounter(model=model or "gpt-4o")  # type: ignore[assignment]
        except ImportError:
            logger.debug("TokenCounter unavailable — token management disabled.")

    def _init_validator(self) -> None:
        try:
            from core.llm.output_models import LLMOutputValidator
            self._validator = LLMOutputValidator(  # type: ignore[assignment]
                llm_client=self._client, max_retries=2,
            )
        except ImportError:
            logger.debug("LLMOutputValidator unavailable — validation disabled.")

    def _init_rag(self) -> None:
        try:
            from core.llm.rag_pipeline import RAGPipeline
            self._rag = RAGPipeline()  # type: ignore[assignment]
            if not self._rag.available:
                self._rag = None
        except ImportError:
            logger.debug("RAGPipeline unavailable — RAG disabled.")

    def _init_cache(self, ttl: float) -> None:
        """Initialize LLM response cache."""
        try:
            from core.llm.llm_cache import LLMCache
            self._cache = LLMCache(default_ttl=ttl, max_size=512)
        except ImportError:
            logger.debug("LLMCache unavailable — caching disabled.")

    def _init_context_compressor(self) -> None:
        """Initialize ContextCompressor for intelligent message summarization."""
        try:
            from core.intelligence.context_compressor import ContextCompressor
            self._context_compressor = ContextCompressor(llm_client=self._client)
        except ImportError:
            logger.debug("ContextCompressor unavailable — compression disabled.")

    def _init_model_router(self) -> None:
        """Initialize ModelRouter for intelligent model selection."""
        try:
            from core.intelligence.model_router import ModelRouter
            self._model_router = ModelRouter()
            # Auto-detect model capabilities from client
            if self._client and hasattr(self._client, "model"):
                self._model_router.auto_detect_models([self._client.model])
            # Try to discover available models from client
            if self._client and hasattr(self._client, "available_models"):
                try:
                    models = self._client.available_models
                    if isinstance(models, list) and models:
                        self._model_router.auto_detect_models(models)
                except (AttributeError, TypeError):
                    pass
        except ImportError:
            logger.debug("ModelRouter unavailable — routing disabled.")

    # ─────────────────────── Core Query Methods ───────────────────────

    def query(
        self,
        prompt: str,
        system_prompt: str | None = None,
        *,
        timeout: int = 30,
        validate: bool = False,
        model_class: type | None = None,
    ) -> str | dict[str, Any]:
        """Smart query with auto token-trim, optional RAG and validation.

        Args:
            prompt: User prompt.
            system_prompt: Override system prompt.
            timeout: Request timeout.
            validate: If True, parse and validate JSON output.
            model_class: Pydantic model for validation.

        Returns:
            Response string, or validated dict if validate=True.

        """
        if not self._client:
            return _MSG_OFFLINE

        self._stats["queries"] += 1

        routed_model = self._route_model(prompt)
        effective_system = self._enrich_system_prompt(prompt, system_prompt)

        # ── Cache lookup ──
        cache_key = None
        if self._cache and not validate:
            from core.llm.llm_cache import LLMCache
            cache_key = LLMCache.make_key(prompt, effective_system, routed_model or "")
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._stats["cache_hits"] += 1
                return cached

        result = self._query_client(prompt, effective_system, timeout, routed_model)

        # ── Cache store ──
        if cache_key is not None and self._cache and isinstance(result, str):
            self._cache.put(cache_key, result)

        if validate and self._validator:
            return self._validate_result(result, model_class)

        return result

    def _route_model(self, prompt: str) -> str | None:
        """Get routed model ID from ModelRouter if available."""
        if not self._model_router:
            return None
        try:
            decision = self._model_router.route(prompt)
            if decision and decision.model_id:
                return decision.model_id
        except (AttributeError, TypeError, ValueError):
            pass
        return None

    def _enrich_system_prompt(self, prompt: str, system_prompt: str | None) -> str:
        """Enrich system prompt with RAG context if available."""
        effective = system_prompt or (
            self._history.system_prompt if self._history else ""
        )
        if not self._rag:
            return effective
        enriched = self._rag.enrich_prompt(prompt, effective)
        if enriched != effective:
            self._stats["rag_enrichments"] += 1
            return enriched
        return effective

    def _query_client(
        self, prompt: str, system: str, timeout: int, routed_model: str | None,
    ) -> str:
        """Execute query against LLM client with optional model routing."""
        if not routed_model or not hasattr(self._client, "query"):
            return self._client.query(prompt, system, timeout=timeout)
        try:
            import inspect
            sig = inspect.signature(self._client.query)
            if "model" in sig.parameters:
                return self._client.query(prompt, system, timeout=timeout, model=routed_model)
        except (TypeError, ValueError):
            pass
        return self._client.query(prompt, system, timeout=timeout)

    def _validate_result(self, result: str, model_class: type | None) -> str | dict[str, Any]:
        """Validate and optionally repair LLM response."""
        if not self._validator:
            return result
        validated = self._validator.validate_response(result, model_class)
        if validated is not None:
            if self._validator.get_stats().get("repairs", 0) > 0:
                self._stats["validation_repairs"] += 1
            return validated
        return result

    def stream(
        self,
        prompt: str,
        system_prompt: str | None = None,
        *,
        timeout: int = 30,
    ) -> Generator[str, None, None]:
        """Stream response token-by-token.

        Args:
            prompt: User prompt.
            system_prompt: Override system prompt.
            timeout: Request timeout.

        Yields:
            Text chunks as they arrive.

        """
        if not self._client:
            yield _MSG_OFFLINE
            return

        self._stats["streams"] += 1

        effective_system = system_prompt or (
            self._history.system_prompt if self._history else ""
        )

        # RAG enrichment
        if self._rag:
            enriched = self._rag.enrich_prompt(prompt, effective_system)
            if enriched != effective_system:
                effective_system = enriched
                self._stats["rag_enrichments"] += 1

        # Use client's stream method
        if hasattr(self._client, "stream"):
            yield from self._client.stream(prompt, effective_system, timeout)
        else:
            # Fallback to non-streaming
            yield self._client.query(prompt, effective_system, timeout=timeout)

    def call_with_tools(
        self,
        prompt: str,
        tools: list[dict[str, Any]],
        system_prompt: str | None = None,
        *,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Function calling — LLM selects tools with guaranteed schema.

        Args:
            prompt: User prompt.
            tools: OpenAI-format tool definitions.
            system_prompt: Override system prompt.
            timeout: Request timeout.

        Returns:
            Dict with content and tool_calls.

        """
        if not self._client:
            return {"content": _MSG_OFFLINE, "tool_calls": []}

        self._stats["tool_calls"] += 1

        effective_system = system_prompt or (
            self._history.system_prompt if self._history else ""
        )

        if hasattr(self._client, "query_with_tools"):
            return self._client.query_with_tools(
                prompt, tools, effective_system, timeout,
            )

        # Fallback: query normally and try to parse tool calls from JSON
        result = self._client.query(prompt, effective_system, timeout=timeout)
        return {"content": result, "tool_calls": []}

    # ─────────────────────── Multi-Turn Methods ───────────────────────

    def add_user_message(self, content: str) -> None:
        """Add a user message to conversation history."""
        if self._history:
            self._history.add_user(content)

    def add_assistant_message(self, content: str) -> None:
        """Add an assistant response to conversation history."""
        if self._history:
            self._history.add_assistant(content)

    def add_tool_result(self, tool_name: str, output: str, *, success: bool = True) -> None:
        """Add a tool execution result to history."""
        if self._history:
            self._history.add_tool_result(tool_name, output, success=success)

    def query_with_history(
        self,
        user_message: str | None = None,
        *,
        timeout: int = 30,
        stream: bool = False,
        tools: list[dict[str, Any]] | None = None,
    ) -> str | Generator[str, None, None] | dict[str, Any]:
        """Query LLM with full conversation history (multi-turn).

        The LLM sees all previous messages, automatically trimmed to fit
        the context window via TokenCounter.

        Args:
            user_message: New user message (added to history first).
            timeout: Request timeout.
            stream: If True, returns streaming generator.
            tools: Optional tool definitions for function calling.

        Returns:
            Response string, streaming generator, or tool-call dict.

        """
        if not self._client:
            return _MSG_OFFLINE

        if not self._history:
            if user_message:
                return self.query(user_message, timeout=timeout)
            return "[Error] No message and no history available."

        if user_message:
            self._history.add_user(user_message)

        messages = self._history.get_trimmed_messages()
        if not messages:
            return "[Error] Empty conversation history."

        messages = self._compress_messages(messages)
        messages = self._enrich_history_system(messages, user_message)
        self._track_token_savings(messages)

        self._stats["queries"] += 1

        if hasattr(self._client, "query_with_messages"):
            return self._client.query_with_messages(
                messages, timeout, tools=tools, stream=stream,
            )
        return self._fallback_multi_turn(messages, timeout)

    def _compress_messages(
        self, messages: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        """Compress conversation history if compressor is available."""
        if not self._context_compressor or len(messages) <= 6:
            return messages
        try:
            return self._context_compressor.compress_messages(messages)
        except (RuntimeError, TypeError, ValueError) as exc:
            logger.debug("Context compression failed: %s", exc)
            return messages

    def _enrich_history_system(
        self, messages: list[dict[str, str]], user_message: str | None,
    ) -> list[dict[str, str]]:
        """Enrich system prompt in history with RAG context."""
        if not self._rag or not messages:
            return messages
        if messages[0].get("role") != "system":
            return messages
        query_text = user_message or ""
        enriched = self._rag.enrich_prompt(query_text, messages[0]["content"])
        if enriched != messages[0]["content"]:
            messages[0] = {"role": "system", "content": enriched}
            self._stats["rag_enrichments"] += 1
        return messages

    def _track_token_savings(self, messages: list[dict[str, str]]) -> None:
        """Track tokens saved by context trimming."""
        if not self._token_counter:
            return
        full_tokens = self._token_counter.count_messages_tokens(
            self._history.get_messages(),
        )
        trimmed_tokens = self._token_counter.count_messages_tokens(messages)
        saved = full_tokens - trimmed_tokens
        if saved > 0:
            self._stats["tokens_saved_by_trim"] += saved

    def _fallback_multi_turn(self, messages: list[dict[str, str]], timeout: int) -> str:
        """Fallback for clients without query_with_messages."""
        system_parts = []
        user_parts = []
        for msg in messages:
            if msg["role"] == "system":
                system_parts.append(msg["content"])
            else:
                prefix = "User" if msg["role"] == "user" else "Assistant"
                user_parts.append(f"{prefix}: {msg['content']}")

        system = "\n".join(system_parts)
        conversation = "\n".join(user_parts[-10:])  # Last 10 exchanges
        return self._client.query(conversation, system, timeout=timeout)

    def clear_history(self) -> None:
        """Clear conversation history."""
        if self._history:
            self._history.clear()

    @property
    def history_count(self) -> int:
        """Number of messages in history."""
        return self._history.count() if self._history else 0

    @property
    def system_prompt(self) -> str:
        """Get current system prompt."""
        return self._history.system_prompt if self._history else ""

    @system_prompt.setter
    def system_prompt(self, value: str) -> None:
        """Update system prompt."""
        if self._history:
            self._history.system_prompt = value

    # ─────────────────────── Token Management ───────────────────────

    def count_tokens(self, text: str) -> int:
        """Count tokens in text."""
        if self._token_counter:
            return self._token_counter.count_tokens(text)
        return len(text.split())  # rough fallback

    def fits_context(self, text: str, *, reserve: int = 1024) -> bool:
        """Check if text fits in the model's context window."""
        if self._token_counter:
            return self._token_counter.fits_context(text, reserve=reserve)
        return True  # Optimistic fallback

    def get_context_window(self) -> int:
        """Get model's context window size."""
        if self._token_counter:
            return self._token_counter.get_context_window()
        return 8192  # Conservative default

    def estimate_cost(self, input_tokens: int = 0, output_tokens: int = 0) -> dict[str, Any]:
        """Estimate API cost."""
        if self._token_counter:
            return self._token_counter.estimate_cost(input_tokens, output_tokens)
        return {"total_cost": 0.0, "note": "TokenCounter unavailable"}

    # ─────────────────────── RAG Methods ───────────────────────

    def ingest_cve(self, cve_id: str, description: str, **kwargs: Any) -> bool:
        """Ingest CVE data into RAG pipeline."""
        if self._rag:
            return self._rag.ingest_cve(cve_id, description, **kwargs)
        return False

    def ingest_tool_output(self, tool_name: str, output: str, **kwargs: Any) -> bool:
        """Ingest tool output for future RAG retrieval."""
        if self._rag:
            return self._rag.ingest_tool_output(tool_name, output, **kwargs)
        return False

    @property
    def rag_available(self) -> bool:
        """Check if RAG pipeline is operational."""
        return self._rag is not None and self._rag.available

    # ─────────────────────── Validation Methods ───────────────────────

    def validate_json(
        self, raw_response: str, model_class: type | None = None,
    ) -> dict[str, Any] | None:
        """Validate and repair LLM JSON output.

        Uses Pydantic models with auto-retry via LLM if validation fails.
        """
        if self._validator:
            return self._validator.validate_response(raw_response, model_class)

        # Fallback: raw JSON parse
        try:
            import json as _json
            return _json.loads(raw_response)
        except (json.JSONDecodeError, TypeError):
            return None

    # ─────────────────────── Tool Schema Builder ───────────────────────

    @staticmethod
    def build_tool_schema(
        name: str,
        description: str,
        parameters: dict[str, Any],
        *,
        required: list[str] | None = None,
    ) -> dict[str, Any]:
        """Build an OpenAI-format tool schema for function calling.

        Args:
            name: Tool name (e.g., "nmap_scan").
            description: What the tool does.
            parameters: Property definitions.
            required: Required parameter names.

        Returns:
            OpenAI-format tool definition.

        Example::

            schema = LLMEngine.build_tool_schema(
                "nmap_scan",
                "Run nmap port scan on target",
                {"target": {"type": "string", "description": "IP or domain"}},
                required=["target"],
            )

        """
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": {
                    "type": "object",
                    "properties": parameters,
                    "required": required or [],
                },
            },
        }

    @staticmethod
    def build_tool_schemas_from_registry(
        tool_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Build OpenAI tool schemas from DRAKBEN's ToolRegistry.

        Args:
            tool_names: Specific tool names. If None, includes all tools.

        Returns:
            List of OpenAI-format tool definitions.

        """
        try:
            from core.tools.tool_registry import ToolRegistry
            registry = ToolRegistry()
        except ImportError:
            return []

        schemas: list[dict[str, Any]] = []

        for name, tool in registry._tools.items():
            if tool_names and name not in tool_names:
                continue

            params: dict[str, Any] = {
                "target": {
                    "type": "string",
                    "description": "Target IP, domain, or URL",
                },
            }

            schemas.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool.description,
                    "parameters": {
                        "type": "object",
                        "properties": params,
                        "required": ["target"],
                    },
                },
            })

        return schemas

    # ─────────────────────── Async Methods ───────────────────────

    async def ainvoke(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> str:
        """Async single query."""
        import asyncio
        try:
            from core.llm.async_client import AsyncLLMClient
            async with asyncio.timeout(self._default_timeout), AsyncLLMClient() as client:
                return await client.ainvoke(prompt, system_prompt)
        except ImportError:
            return self.query(prompt, system_prompt)  # type: ignore[return-value]

    async def abatch(
        self,
        prompts: list[str],
        system_prompt: str = "",
    ) -> list[str]:
        """Async batch — execute multiple queries in parallel."""
        import asyncio
        try:
            from core.llm.async_client import AsyncLLMClient
            async with asyncio.timeout(self._default_timeout), AsyncLLMClient() as client:
                return await client.abatch(prompts, system_prompt)
        except ImportError:
            return [self.query(p, system_prompt) for p in prompts]

    async def astream(self, prompt: str, system_prompt: str = "") -> AsyncGenerator[str, None]:
        """Async streaming query."""
        try:
            from core.llm.async_client import AsyncLLMClient
            async with AsyncLLMClient() as client:
                async for chunk in client.astream(prompt, system_prompt):
                    yield chunk
        except ImportError:
            yield self.query(prompt, system_prompt)

    # ─────────────────────── Stats / Info ───────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Get comprehensive engine statistics."""
        stats = dict(self._stats)
        stats["components"] = {  # type: ignore[assignment]
            "llm_client": self._client is not None,
            "multi_turn": self._history is not None,
            "token_counter": self._token_counter is not None,
            "output_validator": self._validator is not None,
            "rag_pipeline": self._rag is not None and self._rag.available,
        }

        if self._history:
            stats["conversation"] = self._history.get_summary()
        if self._token_counter:
            stats["token_counter"] = self._token_counter.get_stats()
        if self._validator:
            stats["validator"] = self._validator.get_stats()
        if self._rag:
            stats["rag"] = self._rag.get_stats()
        if self._client and hasattr(self._client, "get_provider_info"):
            stats["provider"] = self._client.get_provider_info()

        return stats

    @property
    def client(self) -> Any:
        """Access the underlying LLM client."""
        return self._client
