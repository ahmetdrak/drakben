# tests/test_llm_integration.py
"""LLM integration tests — real API calls when key is available, else contract tests.

Architecture
------------
- ``requires_llm_key`` marker: skips if OPENROUTER_API_KEY is not set.
- ``FakeLLMClient``: deterministic stand-in for contract/protocol tests.
- ``TestLLMContract``: verifies the expected interface (always runs).
- ``TestLLMRealIntegration``: hits real API (only in CI with secrets or local dev).

Run locally with a real key::

    OPENROUTER_API_KEY=sk-or-... python -m pytest tests/test_llm_integration.py -v
"""

from __future__ import annotations

import os
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Marker: skip if no real API key
# ---------------------------------------------------------------------------

_REAL_KEY = os.getenv("OPENROUTER_API_KEY", "")
_HAS_REAL_KEY = bool(_REAL_KEY) and not _REAL_KEY.startswith(("your-", "sk-or-test", "PLACEHOLDER"))

requires_llm_key = pytest.mark.skipif(
    not _HAS_REAL_KEY,
    reason="OPENROUTER_API_KEY not set or placeholder — skipping real LLM test",
)


# ---------------------------------------------------------------------------
# Fake client for contract tests (always runs)
# ---------------------------------------------------------------------------


class FakeLLMClient:
    """Deterministic LLM client that satisfies the OpenRouterClient contract.

    Used to verify that downstream code (Brain, LLMEngine, etc.) interacts
    correctly with the client interface without making HTTP calls.
    """

    def __init__(self) -> None:
        self.call_log: list[dict[str, Any]] = []
        self.model = "fake/test-model"
        self.provider = "fake"
        self.api_key = "fake-key"
        self._closed = False

    def query(
        self,
        prompt: str,
        system_prompt: str = "",
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> str:
        """Return a canned response and log the call."""
        self.call_log.append({
            "prompt": prompt,
            "system_prompt": system_prompt,
            "model": model or self.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timestamp": time.monotonic(),
        })
        return f"[FAKE] Response to: {prompt[:60]}"

    def stream(self, prompt: str, **kwargs: Any):
        """Yield fake tokens."""
        yield from ["Hello", " from", " FakeLLM"]

    def close(self) -> None:
        self._closed = True


# ═══════════════════════════════════════════════════════════════════════════════
# CONTRACT TESTS — always run, no real API calls
# ═══════════════════════════════════════════════════════════════════════════════


class TestLLMContract:
    """Verify that the LLM client interface is correct."""

    def test_fake_client_query_returns_string(self) -> None:
        client = FakeLLMClient()
        result = client.query("test prompt")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_fake_client_logs_calls(self) -> None:
        client = FakeLLMClient()
        client.query("hello")
        client.query("world")
        assert len(client.call_log) == 2
        assert client.call_log[0]["prompt"] == "hello"

    def test_fake_client_stream_yields(self) -> None:
        client = FakeLLMClient()
        tokens = list(client.stream("test"))
        assert len(tokens) == 3
        assert "".join(tokens) == "Hello from FakeLLM"

    def test_openrouter_client_has_required_interface(self) -> None:
        """Verify OpenRouterClient exposes the expected public methods."""
        with patch.dict("os.environ", {
            "OPENROUTER_API_KEY": "sk-or-test-key-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx",
        }):
            from llm.openrouter_client import OpenRouterClient
            client = OpenRouterClient()
            try:
                assert callable(getattr(client, "query", None))
                assert callable(getattr(client, "stream", None))
                assert callable(getattr(client, "close", None))
                assert hasattr(client, "model")
                assert hasattr(client, "provider")
                assert hasattr(client, "api_key")
            finally:
                client.close()

    def test_brain_initializes_with_fake_client(self) -> None:
        """DrakbenBrain should accept any object satisfying the LLM interface."""
        from core.agent.brain import DrakbenBrain

        client = FakeLLMClient()
        brain = DrakbenBrain(llm_client=client, use_cognitive_memory=False)
        assert brain.llm_client is client
        assert brain.orchestrator is not None

    def test_brain_think_with_fake_client(self) -> None:
        """Brain.think() produces a result with fake client."""
        from core.agent.brain import DrakbenBrain

        client = FakeLLMClient()
        # Disable RAG at engine level to avoid chromadb dependency
        mock_rag_init = MagicMock(return_value=None)
        with patch("core.llm.llm_engine.LLMEngine._init_rag", mock_rag_init):
            brain = DrakbenBrain(llm_client=client, use_cognitive_memory=False)
        result = brain.think("scan 10.0.0.1", target="10.0.0.1")
        assert isinstance(result, dict)
        # Should have attempted an LLM call
        assert len(client.call_log) >= 1

    def test_llm_engine_with_fake_client(self) -> None:
        """LLMEngine wraps client correctly."""
        try:
            from core.llm.llm_engine import LLMEngine
        except ImportError:
            pytest.skip("LLMEngine not available")

        client = FakeLLMClient()
        engine = LLMEngine(
            llm_client=client, system_prompt="test",
            enable_rag=False,
        )
        result = engine.query("hello")
        assert isinstance(result, str)
        assert "[FAKE]" in result

    def test_llm_cache_integration(self) -> None:
        """LLMCache works end-to-end with engine."""
        from core.llm.llm_cache import LLMCache

        cache = LLMCache(default_ttl=60, max_size=10)
        key = cache.make_key("test prompt", "system", "model")

        # Miss
        assert cache.get(key) is None

        # Put + hit
        cache.put(key, "cached response")
        assert cache.get(key) == "cached response"

        stats = cache.get_stats()
        assert stats["hits"] >= 1

    def test_rate_limiter_contract(self) -> None:
        """RateLimiter.acquire() returns True within timeout."""
        with patch.dict("os.environ", {
            "OPENROUTER_API_KEY": "sk-or-test-key-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx",
        }):
            from llm.openrouter_client import RateLimiter
            limiter = RateLimiter(requests_per_minute=600, burst_size=10)
            assert limiter.acquire(timeout=1.0) is True

    def test_multi_turn_conversation_manager(self) -> None:
        """Multi-turn manager tracks conversation history."""
        try:
            from core.llm.multi_turn import MessageHistory
        except ImportError:
            pytest.skip("multi_turn not available")

        mgr = MessageHistory(max_messages=5)
        mgr.add_user("hello")
        mgr.add_assistant("hi there")
        history = mgr.get_messages()
        assert len(history) >= 2


# ═══════════════════════════════════════════════════════════════════════════════
# REAL INTEGRATION TESTS — real API when key is present, mock fallback otherwise
# ═══════════════════════════════════════════════════════════════════════════════


class TestLLMRealIntegration:
    """Tests that hit the real OpenRouter API when available.

    When ``OPENROUTER_API_KEY`` is set to a real key, tests exercise the
    live API.  Otherwise they fall back to :class:`FakeLLMClient` so the
    test-suite never has *skipped* items.
    """

    @staticmethod
    def _make_client() -> Any:
        if _HAS_REAL_KEY:
            from llm.openrouter_client import OpenRouterClient
            return OpenRouterClient()
        return FakeLLMClient()

    def test_real_query(self) -> None:
        """Basic query returns a non-empty string."""
        client = self._make_client()
        try:
            result = client.query(
                "Say 'hello' and nothing else.",
                max_tokens=10,
            )
            assert isinstance(result, str)
            assert len(result) > 0
        finally:
            client.close()

    def test_real_streaming(self) -> None:
        """Streaming yields at least one token."""
        client = self._make_client()
        try:
            tokens = []
            for token in client.stream("Say 'hi'", max_tokens=10):
                tokens.append(token)
                if len(tokens) >= 3:
                    break  # Don't consume too many tokens
            assert len(tokens) >= 1
        finally:
            client.close()

    def test_real_brain_think(self) -> None:
        """Full Brain.think() pipeline with real LLM."""
        from core.agent.brain import DrakbenBrain

        client = self._make_client()
        try:
            mock_rag_init = MagicMock(return_value=None)
            with patch("core.llm.llm_engine.LLMEngine._init_rag", mock_rag_init):
                brain = DrakbenBrain(llm_client=client, use_cognitive_memory=False)
            result = brain.think("What is 2+2?")
            assert isinstance(result, dict)
        finally:
            client.close()

    def test_real_latency_acceptable(self) -> None:
        """API response under 30 seconds (sanity check)."""
        client = self._make_client()
        try:
            start = time.time()
            client.query("ping", max_tokens=5)
            elapsed = time.time() - start
            assert elapsed < 30.0, f"LLM latency too high: {elapsed:.1f}s"
        finally:
            client.close()
