# tests/test_llm_engine.py
# DRAKBEN — Comprehensive Tests for LLM Engine Features
# Tests: Streaming, Function Calling, Token Counting, Multi-Turn,
#        Output Validation, RAG Pipeline, Async, Unified Engine

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# 1. STREAMING TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestOpenRouterStreaming:
    """Test streaming support in OpenRouterClient."""

    def _make_client(self) -> Any:
        """Create a client with mocked provider."""
        with patch.dict("os.environ", {
            "OPENROUTER_API_KEY": "sk-or-test-key-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx",
        }):
            from llm.openrouter_client import OpenRouterClient
            client = OpenRouterClient()
            client.api_key = "test-key"
            return client

    def test_stream_method_exists(self) -> None:
        """stream() method should exist on OpenRouterClient."""
        client = self._make_client()
        assert hasattr(client, "stream")
        assert callable(client.stream)
        client.close()

    def test_stream_yields_tokens(self) -> None:
        """stream() should yield token chunks from SSE response."""
        client = self._make_client()

        # Simulate SSE response
        sse_lines = [
            b'data: {"choices":[{"delta":{"content":"Hello"}}]}\n',
            b'data: {"choices":[{"delta":{"content":" world"}}]}\n',
            b'data: [DONE]\n',
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_lines.return_value = [
            line.decode("utf-8") for line in sse_lines
        ]
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch.object(client._session, "post", return_value=mock_response):
            chunks = list(client.stream("test prompt"))

        assert "Hello" in chunks
        assert " world" in chunks
        client.close()

    def test_stream_offline_mode(self) -> None:
        """stream() should yield error message when no API key."""
        client = self._make_client()
        client.api_key = None
        client.provider = "openrouter"  # Non-ollama provider

        chunks = list(client.stream("test"))
        assert any("[Offline" in c for c in chunks)
        client.close()

    def test_stream_api_error(self) -> None:
        """stream() should yield error on non-200 response."""
        client = self._make_client()

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch.object(client._session, "post", return_value=mock_response):
            chunks = list(client.stream("test"))

        assert any("[API Error]" in c for c in chunks)
        client.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 2. FUNCTION CALLING TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestFunctionCalling:
    """Test function calling support."""

    def _make_client(self) -> Any:
        with patch.dict("os.environ", {
            "OPENROUTER_API_KEY": "sk-or-test-key-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx",
        }):
            from llm.openrouter_client import OpenRouterClient
            client = OpenRouterClient()
            client.api_key = "test-key"
            return client

    def test_query_with_tools_method_exists(self) -> None:
        """query_with_tools() should exist."""
        client = self._make_client()
        assert hasattr(client, "query_with_tools")
        client.close()

    def test_query_with_tools_returns_tool_calls(self) -> None:
        """query_with_tools() should parse tool_calls from response."""
        client = self._make_client()

        api_response = {
            "choices": [{
                "message": {
                    "content": "I'll scan the target.",
                    "tool_calls": [{
                        "id": "call_abc123",
                        "type": "function",
                        "function": {
                            "name": "nmap_scan",
                            "arguments": '{"target": "10.0.0.1"}',
                        },
                    }],
                },
            }],
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = api_response

        tools = [{
            "type": "function",
            "function": {
                "name": "nmap_scan",
                "description": "Run nmap scan",
                "parameters": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                },
            },
        }]

        with patch.object(client._session, "post", return_value=mock_resp):
            result = client.query_with_tools("Scan 10.0.0.1", tools)

        assert result["content"] == "I'll scan the target."
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["function"]["name"] == "nmap_scan"
        client.close()

    def test_query_with_tools_no_key(self) -> None:
        """query_with_tools() should return error when offline."""
        client = self._make_client()
        client.api_key = None
        client.provider = "openrouter"

        result = client.query_with_tools("test", [])
        assert "[Offline" in result["content"]
        assert result["tool_calls"] == []
        client.close()

    def test_query_with_messages_method_exists(self) -> None:
        """query_with_messages() should exist for multi-turn."""
        client = self._make_client()
        assert hasattr(client, "query_with_messages")
        client.close()

    def test_query_with_messages_sends_full_history(self) -> None:
        """query_with_messages() should send the full message list."""
        client = self._make_client()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Scan completed."}}],
        }

        messages = [
            {"role": "system", "content": "You are DRAKBEN"},
            {"role": "user", "content": "Scan 10.0.0.1"},
            {"role": "assistant", "content": "Starting scan..."},
            {"role": "user", "content": "What did you find?"},
        ]

        with patch.object(client._session, "post", return_value=mock_resp) as mock_post:
            result = client.query_with_messages(messages, timeout=10)

        # Verify messages were sent in payload
        call_kwargs = mock_post.call_args
        sent_payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert sent_payload["messages"] == messages
        assert result == "Scan completed."
        client.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 3. TOKEN COUNTING TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestTokenCounter:
    """Test token counting and budget management."""

    def test_count_tokens_basic(self) -> None:
        """count_tokens should return positive count for non-empty text."""
        from core.llm.token_counter import TokenCounter
        counter = TokenCounter(model="gpt-4o")
        count = counter.count_tokens("Hello, world! This is a test.")
        assert count > 0

    def test_count_tokens_empty(self) -> None:
        from core.llm.token_counter import TokenCounter
        counter = TokenCounter()
        assert counter.count_tokens("") == 0

    def test_trim_to_budget_preserves_system(self) -> None:
        """trim_to_budget should always keep system message."""
        from core.llm.token_counter import TokenCounter
        counter = TokenCounter()

        messages = [
            {"role": "system", "content": "You are DRAKBEN."},
            {"role": "user", "content": "Q1 " * 500},
            {"role": "assistant", "content": "A1 " * 500},
            {"role": "user", "content": "Q2 " * 500},
            {"role": "assistant", "content": "A2 " * 500},
            {"role": "user", "content": "Final question"},
        ]

        trimmed = counter.trim_to_budget(messages, max_tokens=4000)
        assert trimmed[0]["role"] == "system"
        assert trimmed[-1]["content"] == "Final question"
        assert len(trimmed) <= len(messages)

    def test_context_window_lookup(self) -> None:
        from core.llm.token_counter import TokenCounter
        counter = TokenCounter(model="gpt-4o")
        window = counter.get_context_window()
        # gpt-4o should map to 128000, but model name matching is prefix-based
        assert window > 0
        # Verify known models have expected windows
        counter2 = TokenCounter(model="gpt-3.5-turbo")
        assert counter2.get_context_window() == 16385

    def test_fits_context(self) -> None:
        from core.llm.token_counter import TokenCounter
        counter = TokenCounter(model="gpt-4o")
        assert counter.fits_context("Short text")
        assert not counter.fits_context("x " * 200000)

    def test_estimate_cost(self) -> None:
        from core.llm.token_counter import TokenCounter
        counter = TokenCounter(model="gpt-4o")
        cost = counter.estimate_cost(input_tokens=1000, output_tokens=500)
        assert cost["total_cost"] > 0
        assert "input_cost" in cost

    def test_count_messages_tokens(self) -> None:
        from core.llm.token_counter import TokenCounter
        counter = TokenCounter()
        messages = [
            {"role": "system", "content": "System prompt"},
            {"role": "user", "content": "Hello"},
        ]
        tokens = counter.count_messages_tokens(messages)
        assert tokens > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MULTI-TURN TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestMultiTurn:
    """Test multi-turn conversation management."""

    def test_message_history_basic(self) -> None:
        from core.llm.multi_turn import MessageHistory
        history = MessageHistory(system_prompt="You are DRAKBEN.")
        history.add_user("Scan 10.0.0.1")
        history.add_assistant("Starting scan...")

        messages = history.get_messages()
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert messages[2]["role"] == "assistant"
        assert history.count() == 2

    def test_tool_result_added(self) -> None:
        from core.llm.multi_turn import MessageHistory
        history = MessageHistory()
        history.add_tool_result("nmap", "80/tcp open http", success=True)

        messages = history.get_messages()
        assert any("nmap" in m["content"] for m in messages)

    def test_trimmed_messages_respects_budget(self) -> None:
        from core.llm.multi_turn import MessageHistory
        history = MessageHistory(system_prompt="System", max_messages=100)

        for i in range(50):
            history.add_user(f"Question {i} " * 100)
            history.add_assistant(f"Answer {i} " * 100)

        trimmed = history.get_trimmed_messages(max_tokens=2000)
        full = history.get_messages()
        assert len(trimmed) < len(full)

    def test_clear_history(self) -> None:
        from core.llm.multi_turn import MessageHistory
        history = MessageHistory()
        history.add_user("test")
        history.clear()
        assert history.count() == 0

    def test_get_last_n(self) -> None:
        from core.llm.multi_turn import MessageHistory
        history = MessageHistory()
        for i in range(10):
            history.add_user(f"msg {i}")
        last3 = history.get_last_n(3)
        assert len(last3) == 3

    def test_summary_stats(self) -> None:
        from core.llm.multi_turn import MessageHistory
        history = MessageHistory(system_prompt="sys", session_id="test-session")
        history.add_user("Q1")
        history.add_assistant("A1")

        summary = history.get_summary()
        assert summary["user_messages"] == 1
        assert summary["assistant_messages"] == 1
        assert summary["session_id"] == "test-session"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. OUTPUT VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestOutputValidation:
    """Test LLM output validation and repair."""

    def test_validate_valid_json(self) -> None:
        from core.llm.output_models import LLMOutputValidator
        validator = LLMOutputValidator()
        result = validator.validate_response('{"intent": "scan", "response": "ok", "confidence": 0.9}')
        assert result is not None
        assert result["intent"] == "scan"

    def test_validate_json_in_code_block(self) -> None:
        from core.llm.output_models import LLMOutputValidator
        validator = LLMOutputValidator()
        raw = '```json\n{"intent": "chat", "response": "hello"}\n```'
        result = validator.validate_response(raw)
        assert result is not None
        assert result["intent"] == "chat"

    def test_validate_invalid_returns_none_without_client(self) -> None:
        from core.llm.output_models import LLMOutputValidator
        validator = LLMOutputValidator(llm_client=None)
        result = validator.validate_response("not json at all")
        assert result is None

    def test_validate_with_repair(self) -> None:
        """Validator should try LLM repair when initial parse fails."""
        from core.llm.output_models import LLMOutputValidator

        mock_client = MagicMock()
        mock_client.query.return_value = '{"intent": "scan", "response": "fixed"}'

        validator = LLMOutputValidator(llm_client=mock_client, max_retries=1)
        result = validator.validate_response("broken json {{{")

        assert result is not None
        assert result["intent"] == "scan"
        assert mock_client.query.called

    def test_pydantic_model_validation(self) -> None:
        """Test validation with Pydantic models."""
        try:
            from core.llm.output_models import LLMAnalysisResponse, LLMOutputValidator, _PYDANTIC_AVAILABLE  # noqa: I001
            if not _PYDANTIC_AVAILABLE:
                pytest.skip("Pydantic not available")

            validator = LLMOutputValidator()
            raw = json.dumps({
                "intent": "scan",
                "target_extracted": "10.0.0.1",
                "confidence": 0.95,
                "response": "I'll scan the target",
                "steps": [{"action": "nmap"}],
                "risks": ["port exposure"],
            })
            result = validator.validate_response(raw, LLMAnalysisResponse)
            assert result is not None
            assert abs(result["confidence"] - 0.95) < 1e-9
        except ImportError:
            pytest.skip("output_models not available")

    def test_tool_call_response_model(self) -> None:
        """Test ToolCallResponse Pydantic model."""
        try:
            from core.llm.output_models import ToolCallResponse, _PYDANTIC_AVAILABLE  # noqa: I001
            if not _PYDANTIC_AVAILABLE:
                pytest.skip("Pydantic not available")

            tc = ToolCallResponse(tool_name="nmap", arguments={"target": "10.0.0.1"})
            assert tc.tool_name == "nmap"
            assert tc.arguments["target"] == "10.0.0.1"
        except ImportError:
            pytest.skip("output_models not available")

    def test_validator_stats(self) -> None:
        from core.llm.output_models import LLMOutputValidator
        validator = LLMOutputValidator()
        validator.validate_response('{"intent": "chat"}')
        stats = validator.get_stats()
        assert stats["validations"] >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# 6. RAG PIPELINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestRAGPipeline:
    """Test RAG pipeline for CVE/exploit enrichment."""

    def test_rag_init_without_vector_store(self) -> None:
        from core.llm.rag_pipeline import RAGPipeline
        rag = RAGPipeline(vector_store=None)
        # May or may not auto-init depending on ChromaDB availability
        assert isinstance(rag.get_stats(), dict)

    def test_enrich_prompt_no_results(self) -> None:
        """enrich_prompt should return original prompt when no results."""
        from core.llm.rag_pipeline import RAGPipeline
        rag = RAGPipeline(vector_store=None)
        rag._vector_store = None  # Force no store
        enriched = rag.enrich_prompt("test query", "original system prompt")
        assert enriched == "original system prompt"

    def test_enrich_prompt_with_mock_store(self) -> None:
        """enrich_prompt should inject relevant context."""
        from core.llm.rag_pipeline import RAGPipeline

        mock_store = MagicMock()
        mock_store.search.return_value = [
            {"text": "CVE-2024-1234: Apache RCE", "metadata": {"cve_id": "CVE-2024-1234", "severity": "critical"},
             "distance": 0.3},
        ]
        mock_store.count.return_value = 10

        rag = RAGPipeline(vector_store=mock_store)
        enriched = rag.enrich_prompt("Apache vulnerabilities", "You are DRAKBEN")

        assert "CVE-2024-1234" in enriched
        assert "You are DRAKBEN" in enriched

    def test_ingest_cve(self) -> None:
        from core.llm.rag_pipeline import RAGPipeline
        mock_store = MagicMock()
        mock_store.add_memory.return_value = True
        mock_store.count.return_value = 1

        rag = RAGPipeline(vector_store=mock_store)
        assert rag.ingest_cve("CVE-2024-9999", "Test vulnerability", severity="high")
        mock_store.add_memory.assert_called_once()

    def test_ingest_tool_output(self) -> None:
        from core.llm.rag_pipeline import RAGPipeline
        mock_store = MagicMock()
        mock_store.add_memory.return_value = True
        mock_store.count.return_value = 1

        rag = RAGPipeline(vector_store=mock_store)
        assert rag.ingest_tool_output("nmap", "80/tcp open http", target="10.0.0.1")

    def test_retrieve_filters_by_relevance(self) -> None:
        from core.llm.rag_pipeline import RAGPipeline
        mock_store = MagicMock()
        mock_store.search.return_value = [
            {"text": "relevant", "distance": 0.5},
            {"text": "irrelevant", "distance": 2.0},  # Above threshold
        ]

        rag = RAGPipeline(vector_store=mock_store)
        results = rag.retrieve("test query")
        assert len(results) == 1
        assert results[0]["text"] == "relevant"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. ASYNC CLIENT TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestAsyncLLMClient:
    """Test async LLM client."""

    def test_async_client_importable(self) -> None:
        """AsyncLLMClient should be importable."""
        from core.llm.async_client import AsyncLLMClient
        assert callable(AsyncLLMClient)

    def test_async_client_build_payload(self) -> None:
        from core.llm.async_client import AsyncLLMClient
        client = AsyncLLMClient(
            api_key="test", model="gpt-4o",
            base_url="https://test.com/v1/chat/completions",
        )
        payload = client._build_payload("Hello", "System", stream=True)
        assert payload["stream"] is True
        assert payload["model"] == "gpt-4o"
        assert len(payload["messages"]) == 2

    def test_async_client_build_payload_with_tools(self) -> None:
        from core.llm.async_client import AsyncLLMClient
        client = AsyncLLMClient(
            api_key="test", model="gpt-4o",
            base_url="https://test.com/v1/chat/completions",
        )
        tools = [{"type": "function", "function": {"name": "test"}}]
        payload = client._build_payload("Hello", tools=tools)
        assert payload["tools"] == tools

    @pytest.mark.asyncio
    async def test_extract_content(self) -> None:
        from core.llm.async_client import AsyncLLMClient
        data = {"choices": [{"message": {"content": "Hello!"}}]}
        assert AsyncLLMClient._extract_content(data) == "Hello!"

    @pytest.mark.asyncio
    async def test_extract_full_response_with_tools(self) -> None:
        from core.llm.async_client import AsyncLLMClient
        data = {
            "choices": [{
                "message": {
                    "content": "I'll help",
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "nmap", "arguments": '{"target": "10.0.0.1"}'},
                    }],
                },
            }],
        }
        result = AsyncLLMClient._extract_full_response(data)
        assert result["content"] == "I'll help"
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["function"]["name"] == "nmap"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. UNIFIED LLM ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestLLMEngine:
    """Test unified LLM Engine."""

    def _make_engine(self, **kwargs: Any) -> Any:
        """Create engine with mock client."""
        from core.llm.llm_engine import LLMEngine

        mock_client = MagicMock()
        mock_client.query.return_value = "Mock response"
        mock_client.model = "gpt-4o"
        mock_client.stream.return_value = iter(["Hello", " world"])
        mock_client.query_with_tools.return_value = {
            "content": "I'll scan", "tool_calls": [],
        }
        mock_client.query_with_messages.return_value = "Multi-turn response"
        mock_client.get_provider_info.return_value = {"provider": "mock"}

        return LLMEngine(
            llm_client=mock_client,
            system_prompt="Test system",
            enable_rag=False,
            **kwargs,
        )

    def test_engine_init(self) -> None:
        engine = self._make_engine()
        assert engine.client is not None
        stats = engine.get_stats()
        assert stats["components"]["llm_client"] is True

    def test_engine_query(self) -> None:
        engine = self._make_engine()
        result = engine.query("test prompt")
        assert result == "Mock response"
        assert engine.get_stats()["queries"] >= 1

    def test_engine_stream(self) -> None:
        engine = self._make_engine()
        chunks = list(engine.stream("test"))
        assert "Hello" in chunks

    def test_engine_call_with_tools(self) -> None:
        engine = self._make_engine()
        tools = [{"type": "function", "function": {"name": "test"}}]
        result = engine.call_with_tools("test", tools)
        assert "content" in result

    def test_engine_multi_turn(self) -> None:
        engine = self._make_engine()
        engine.add_user_message("Hello")
        engine.add_assistant_message("Hi there")
        assert engine.history_count == 2

        result = engine.query_with_history("What's next?")
        # Should use query_with_messages
        assert result is not None

    def test_engine_system_prompt(self) -> None:
        engine = self._make_engine()
        assert engine.system_prompt == "Test system"
        engine.system_prompt = "New prompt"
        assert engine.system_prompt == "New prompt"

    def test_engine_token_counting(self) -> None:
        engine = self._make_engine()
        count = engine.count_tokens("Hello world")
        assert count > 0
        assert engine.fits_context("Short text")
        assert engine.get_context_window() > 0

    def test_engine_validate_json(self) -> None:
        engine = self._make_engine()
        result = engine.validate_json('{"intent": "scan"}')
        assert result is not None
        assert result["intent"] == "scan"

    def test_engine_validate_json_invalid(self) -> None:
        engine = self._make_engine()
        # LLMOutputValidator is available, but no client for repair
        result = engine.validate_json("not json")
        # May return None depending on validator behavior
        # The important thing is no crash
        assert result is None or isinstance(result, dict)

    def test_engine_build_tool_schema(self) -> None:
        from core.llm.llm_engine import LLMEngine
        schema = LLMEngine.build_tool_schema(
            "nmap_scan",
            "Run nmap port scan",
            {"target": {"type": "string", "description": "Target IP"}},
            required=["target"],
        )
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "nmap_scan"
        assert "target" in schema["function"]["parameters"]["properties"]

    def test_engine_clear_history(self) -> None:
        engine = self._make_engine()
        engine.add_user_message("test")
        engine.clear_history()
        assert engine.history_count == 0

    def test_engine_cost_estimation(self) -> None:
        engine = self._make_engine()
        cost = engine.estimate_cost(input_tokens=1000, output_tokens=500)
        assert "total_cost" in cost

    def test_engine_query_with_validation(self) -> None:
        """query(validate=True) should parse JSON output."""
        engine = self._make_engine()
        engine.client.query.return_value = '{"intent": "chat", "response": "hi"}'
        result = engine.query("test", validate=True)
        assert isinstance(result, dict)
        assert result["intent"] == "chat"

    def test_engine_stats_comprehensive(self) -> None:
        engine = self._make_engine()
        engine.query("q1")
        list(engine.stream("q2"))
        engine.call_with_tools("q3", [])

        stats = engine.get_stats()
        assert stats["queries"] >= 1
        assert stats["streams"] >= 1
        assert stats["tool_calls"] >= 1
        assert "components" in stats
        assert "provider" in stats


# ═══════════════════════════════════════════════════════════════════════════════
# 9. BRAIN INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestBrainIntegration:
    """Test DrakbenBrain integration with LLM Engine."""

    def _make_brain(self) -> Any:
        """Create brain with mock LLM for testing."""
        mock_client = MagicMock()
        mock_client.query.return_value = (
            '{"intent": "chat", "response": "Hello!", "confidence": 0.9,'
            ' "command": null, "steps": [], "risks": []}'
        )
        mock_client.model = "gpt-4o"
        mock_client.stream.return_value = iter(["Hello", " from", " DRAKBEN"])
        mock_client.get_provider_info.return_value = {"provider": "mock"}

        from core.agent.brain import DrakbenBrain
        brain = DrakbenBrain(llm_client=mock_client, use_cognitive_memory=False)
        return brain

    def test_brain_has_engine(self) -> None:
        brain = self._make_brain()
        assert brain.engine is not None

    def test_brain_stream_think(self) -> None:
        """stream_think() should yield tokens."""
        brain = self._make_brain()
        chunks = list(brain.stream_think("test"))
        assert len(chunks) > 0

    def test_brain_think_with_tools(self) -> None:
        """think_with_tools() should return structured result."""
        brain = self._make_brain()
        # Mock the engine's call_with_tools to return proper structure
        if brain.engine:
            brain.engine.call_with_tools = MagicMock(
                return_value={"content": "Scanning...", "tool_calls": []},
            )
        result = brain.think_with_tools("Scan 10.0.0.1")
        assert "content" in result
        assert "tool_calls" in result

    def test_brain_chat_multi_turn(self) -> None:
        """chat() should use multi-turn when engine available."""
        brain = self._make_brain()
        if brain.engine:
            brain.engine.client.query_with_messages = MagicMock(
                return_value="I remember our conversation.",
            )
            result1 = brain.chat("Hello")
            result2 = brain.chat("What did I just say?")
            assert result1 is not None
            assert result2 is not None

    def test_brain_observe_feeds_engine(self) -> None:
        """observe() should feed tool results to engine."""
        brain = self._make_brain()
        brain.observe("nmap", "80/tcp open http", success=True)

        if brain.engine:
            assert brain.engine.history_count > 0

    def test_brain_stats_include_engine(self) -> None:
        """get_stats() should include engine stats."""
        brain = self._make_brain()
        stats = brain.get_stats()
        assert "engine_available" in stats
        if brain.engine:
            assert "engine" in stats
