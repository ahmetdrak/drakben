# core/llm/async_client.py
# DRAKBEN — Async LLM Client
# Provides ainvoke(), astream(), abatch() for parallel tool execution.
# Uses aiohttp (already in requirements.txt).

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

# Graceful aiohttp import
_AIOHTTP_AVAILABLE = False
try:
    import aiohttp

    _AIOHTTP_AVAILABLE = True
except ImportError:
    logger.info("aiohttp not installed — async LLM client disabled.")


class AsyncLLMClient:
    """Async LLM client for parallel operations.

    Wraps OpenAI-compatible APIs with async HTTP via aiohttp.
    Provides ainvoke(), astream(), abatch() similar to LangChain.

    Usage::

        async with AsyncLLMClient(api_key="sk-...", model="gpt-4o") as client:
            result = await client.ainvoke("Hello")
            results = await client.abatch(["Q1", "Q2", "Q3"])
            async for chunk in client.astream("Tell me about nmap"):
                print(chunk, end="")

    """

    def __init__(
        self,
        *,
        api_key: str = "",
        model: str = "",
        base_url: str = "",
        provider: str = "",
        timeout: int = 30,
        max_concurrent: int = 5,
    ) -> None:
        """Initialize async client.

        If no parameters given, reads from OpenRouterClient config.

        Args:
            api_key: API key for the provider.
            model: Model name.
            base_url: API base URL.
            provider: Provider name (openrouter, openai, ollama, custom).
            timeout: Request timeout in seconds.
            max_concurrent: Maximum concurrent requests for abatch().

        """
        self._session: aiohttp.ClientSession | None = None
        self._timeout = timeout
        self._max_concurrent = max_concurrent
        self._closed = False

        # Auto-detect from OpenRouterClient if not specified
        if not api_key and not base_url:
            self._auto_configure()
        else:
            self.api_key = api_key
            self.model = model
            self.base_url = base_url
            self.provider = provider or "openai"

    def _auto_configure(self) -> None:
        """Auto-configure from existing OpenRouterClient settings."""
        try:
            from llm.openrouter_client import OpenRouterClient

            client = OpenRouterClient()
            self.api_key = client.api_key  # type: ignore[assignment]
            self.model = client.model
            self.base_url = client.base_url
            self.provider = client.provider
            client.close()
        except (ImportError, ValueError, OSError, KeyError):
            logger.warning("OpenRouterClient init failed, using defaults", exc_info=True)
            self.api_key = ""
            self.model = "gpt-4o"
            self.base_url = "https://openrouter.ai/api/v1/chat/completions"
            self.provider = "openrouter"

    def _ensure_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session (sync — no async I/O needed)."""
        if self._session is None or self._session.closed:
            if not _AIOHTTP_AVAILABLE:
                msg = "aiohttp is required for AsyncLLMClient"
                raise ImportError(msg)

            headers: dict[str, str] = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            if self.provider == "openrouter":
                headers["HTTP-Referer"] = "https://github.com/drakben/drakben"
                headers["X-Title"] = "DRAKBEN Pentest AI"

            timeout = aiohttp.ClientTimeout(total=self._timeout)
            self._session = aiohttp.ClientSession(headers=headers, timeout=timeout)

        return self._session

    def _build_payload(
        self,
        prompt: str,
        system_prompt: str = "",
        *,
        stream: bool = False,
        tools: list[dict] | None = None,
    ) -> dict[str, Any]:
        """Build API request payload."""
        messages: list[dict[str, str]] = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
        }

        if tools:
            payload["tools"] = tools

        return payload

    async def ainvoke(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> str:
        """Async single query to LLM.

        Args:
            prompt: User prompt.
            system_prompt: System prompt.

        Returns:
            LLM response text.

        """
        session = self._ensure_session()
        payload = self._build_payload(prompt, system_prompt)

        try:
            async with asyncio.timeout(self._timeout), session.post(self.base_url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._extract_content(data)
                text = await resp.text()
                return f"[API Error] {resp.status}: {text[:200]}"
        except TimeoutError:
            return "[Timeout] Async request timed out."
        except aiohttp.ClientError as exc:
            return f"[Connection Error] {exc!s}"
        except (KeyError, ValueError, RuntimeError) as exc:
            logger.exception("Async query error: %s", exc)
            return f"[Error] {exc!s}"

    async def astream(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> AsyncIterator[str]:
        """Async streaming query — yields tokens as they arrive.

        Args:
            prompt: User prompt.
            system_prompt: System prompt.

        Yields:
            Text chunks (tokens) as they arrive from the API.

        """
        session = self._ensure_session()
        payload = self._build_payload(prompt, system_prompt, stream=True)

        try:
            async with session.post(self.base_url, json=payload) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    yield f"[API Error] {resp.status}: {text[:200]}"
                    return

                async for line in resp.content:
                    decoded = line.decode("utf-8", errors="replace").strip()
                    if not decoded or not decoded.startswith("data: "):
                        continue

                    data_str = decoded[6:]  # Remove "data: " prefix
                    if data_str == "[DONE]":
                        break

                    try:
                        chunk_data = json.loads(data_str)
                        delta = chunk_data.get("choices", [{}])[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            yield content
                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue

        except TimeoutError:
            yield "[Timeout] Stream timed out."
        except aiohttp.ClientError as exc:
            yield f"[Connection Error] {exc!s}"
        except (KeyError, ValueError, RuntimeError) as exc:
            logger.exception("Async stream error: %s", exc)
            yield f"[Error] {exc!s}"

    async def abatch(
        self,
        prompts: list[str],
        system_prompt: str = "",
    ) -> list[str]:
        """Execute multiple queries in parallel with concurrency control.

        Args:
            prompts: List of user prompts.
            system_prompt: Shared system prompt.

        Returns:
            List of responses (same order as prompts).

        """
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def _limited_invoke(prompt: str) -> str:
            async with semaphore:
                return await self.ainvoke(prompt, system_prompt)

        tasks = [_limited_invoke(p) for p in prompts]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    async def ainvoke_with_tools(
        self,
        prompt: str,
        system_prompt: str = "",
        *,
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Async function calling query.

        Args:
            prompt: User prompt.
            system_prompt: System prompt.
            tools: OpenAI-format tool definitions.

        Returns:
            Response dict with content and/or tool_calls.

        """
        session = self._ensure_session()
        payload = self._build_payload(prompt, system_prompt, tools=tools)

        try:
            async with session.post(self.base_url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self._extract_full_response(data)
                text = await resp.text()
                return {"error": f"[API Error] {resp.status}: {text[:200]}"}
        except (aiohttp.ClientError, OSError, ValueError) as exc:
            return {"error": f"[Error] {exc!s}"}

    @staticmethod
    def _extract_content(data: dict) -> str:
        """Extract text content from API response."""
        try:
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
            return "[API Error] No choices in response"
        except (KeyError, IndexError):
            return "[API Error] Failed to parse response"

    @staticmethod
    def _extract_full_response(data: dict) -> dict[str, Any]:
        """Extract full response including tool calls."""
        try:
            choices = data.get("choices", [])
            if not choices:
                return {"error": "No choices in response"}

            message = choices[0].get("message", {})
            result: dict[str, Any] = {
                "content": message.get("content", ""),
                "role": message.get("role", "assistant"),
            }

            tool_calls = message.get("tool_calls")
            if tool_calls:
                result["tool_calls"] = [
                    {
                        "id": tc.get("id", ""),
                        "type": tc.get("type", "function"),
                        "function": {
                            "name": tc.get("function", {}).get("name", ""),
                            "arguments": tc.get("function", {}).get("arguments", "{}"),
                        },
                    }
                    for tc in tool_calls
                ]

            return result
        except (KeyError, IndexError):
            return {"error": "Failed to parse response"}

    async def close(self) -> None:
        """Close the async session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._closed = True

    async def __aenter__(self) -> AsyncLLMClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
