# llm/streaming_tools_mixin.py
# Streaming and function-calling support — extracted from OpenRouterClient
"""Mixin providing SSE streaming, function calling, and multi-turn query methods."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import requests  # type: ignore[import-untyped]

from llm.constants import MSG_OFFLINE_NO_CONN, MSG_OFFLINE_NO_KEY, MSG_RATE_LIMITED

if TYPE_CHECKING:
    from collections.abc import Generator

logger = logging.getLogger(__name__)


class StreamingToolsMixin:
    """Streaming, function calling, and multi-turn conversation support."""

    # ─────────────────── Streaming Support ───────────────────
    def stream(
        self,
        prompt: str,
        system_prompt: str | None = None,
        timeout: int = 30,
    ) -> Generator[str, None, None]:
        """Stream LLM response token-by-token (SSE).

        Instead of waiting 30s for the full response, yields each token
        as it arrives from the API. Compatible with ``rich.live`` and
        any iterator consumer.

        Args:
            prompt: User prompt.
            system_prompt: System prompt (optional).
            timeout: Request timeout in seconds.

        Yields:
            Text chunks (tokens) as they arrive from the API.

        Example::

            for chunk in client.stream("Explain nmap"):
                print(chunk, end="", flush=True)

        """
        if system_prompt is None:
            system_prompt = "You are a penetration testing assistant."

        if self.provider == "ollama":
            yield from self._stream_ollama(prompt, system_prompt, timeout)
            return

        if not self.api_key:
            yield MSG_OFFLINE_NO_KEY
            return

        if not self._rate_limiter.acquire(timeout=timeout):
            yield MSG_RATE_LIMITED
            return

        headers = self._build_api_headers()
        payload = self._build_api_payload(system_prompt, prompt)
        payload["stream"] = True

        try:
            response = self._session.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=timeout,
                stream=True,
            )

            if response.status_code != 200:
                yield f"[API Error] {response.status_code}: {response.text[:200]}"
                return

            collected = list(self._parse_sse_chunks(response))
            yield from collected

            # Cache the full collected response
            if collected and self.enable_cache and self._cache:
                self._cache.set(prompt, system_prompt, self.model, "".join(collected))

        except requests.exceptions.Timeout:
            yield "[Timeout] Stream request timed out."
        except requests.exceptions.ConnectionError:
            yield MSG_OFFLINE_NO_CONN
        except Exception as exc:
            logger.exception("Stream error: %s", exc)
            yield f"[Error] {exc!s}"

    @staticmethod
    def _parse_sse_chunks(response: requests.Response) -> Generator[str, None, None]:
        """Parse SSE stream and yield text content chunks."""
        for line in response.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            data_str = line[6:]  # Remove "data: " prefix
            if data_str.strip() == "[DONE]":
                break
            try:
                chunk = json.loads(data_str)
                content = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                if content:
                    yield content
            except (json.JSONDecodeError, IndexError, KeyError):
                continue

    # ─────────────────── Function Calling ───────────────────
    def query_with_tools(
        self,
        prompt: str,
        tools: list[dict[str, Any]],
        system_prompt: str | None = None,
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Query LLM with function/tool definitions for guaranteed structured output.

        Instead of hoping the LLM returns valid JSON, this uses the native
        ``tools`` parameter (OpenAI function calling protocol) to guarantee
        the model returns a proper tool call with validated arguments.

        Args:
            prompt: User prompt.
            tools: OpenAI-format tool definitions.
            system_prompt: System prompt (optional).
            timeout: Request timeout in seconds.

        Returns:
            Dict with ``content`` and/or ``tool_calls``.

        """
        if system_prompt is None:
            system_prompt = "You are a penetration testing assistant. Use the provided tools when appropriate."

        if not self.api_key and self.provider != "ollama":
            return {"content": MSG_OFFLINE_NO_KEY, "tool_calls": []}

        if not self._rate_limiter.acquire(timeout=timeout):
            return {"content": MSG_RATE_LIMITED, "tool_calls": []}

        headers = self._build_api_headers()
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "tools": tools,
        }

        try:
            response = self._session.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=timeout,
            )

            if response.status_code != 200:
                return {
                    "content": f"[API Error] {response.status_code}: {response.text[:200]}",
                    "tool_calls": [],
                }

            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                return {"content": "[API Error] No choices in response", "tool_calls": []}

            message = choices[0].get("message", {})
            result: dict[str, Any] = {
                "content": message.get("content", ""),
                "tool_calls": [],
            }

            raw_calls = message.get("tool_calls")
            if raw_calls:
                result["tool_calls"] = [
                    {
                        "id": tc.get("id", ""),
                        "function": {
                            "name": tc.get("function", {}).get("name", ""),
                            "arguments": tc.get("function", {}).get("arguments", "{}"),
                        },
                    }
                    for tc in raw_calls
                ]

            return result

        except requests.exceptions.Timeout:
            return {"content": "[Timeout] Function calling request timed out.", "tool_calls": []}
        except requests.exceptions.ConnectionError:
            return {"content": MSG_OFFLINE_NO_CONN, "tool_calls": []}
        except Exception as exc:
            logger.exception("Function calling error: %s", exc)
            return {"content": f"[Error] {exc!s}", "tool_calls": []}

    # ─────────────────── Multi-turn Conversation ───────────────────
    def query_with_messages(
        self,
        messages: list[dict[str, str]],
        timeout: int = 30,
        *,
        tools: list[dict[str, Any]] | None = None,
        stream: bool = False,
    ) -> str | Generator[str, None, None] | dict[str, Any]:
        """Query LLM with a full message history (multi-turn).

        This is the key method that enables multi-turn conversations.
        Instead of single prompt+system_prompt, accepts the full message
        list from ``MessageHistory.get_trimmed_messages()``.

        Args:
            messages: List of {"role": ..., "content": ...} messages.
            timeout: Request timeout in seconds.
            tools: Optional tool definitions for function calling.
            stream: If True, returns a generator yielding tokens.

        Returns:
            Response string, streaming generator, or tool-call dict.

        """
        if not messages:
            return "[Error] Empty message list"

        if not self.api_key and self.provider != "ollama":
            return MSG_OFFLINE_NO_KEY

        if not self._rate_limiter.acquire(timeout=timeout):
            return MSG_RATE_LIMITED

        headers = self._build_api_headers()
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }

        if tools:
            payload["tools"] = tools

        if stream:
            payload["stream"] = True
            return self._stream_messages(headers, payload, timeout)

        try:
            response = self._session.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=timeout,
            )
            if response.status_code != 200:
                return f"[API Error] {response.status_code}: {response.text[:200]}"

            data = response.json()
            message = data.get("choices", [{}])[0].get("message", {})

            # If tool calls present, return full dict
            if message.get("tool_calls"):
                return {
                    "content": message.get("content", ""),
                    "tool_calls": [
                        {
                            "id": tc.get("id", ""),
                            "function": {
                                "name": tc.get("function", {}).get("name", ""),
                                "arguments": tc.get("function", {}).get("arguments", "{}"),
                            },
                        }
                        for tc in message["tool_calls"]
                    ],
                }

            return message.get("content", "[API Error] No content in response")

        except requests.exceptions.Timeout:
            return "[Timeout] Request timed out."
        except requests.exceptions.ConnectionError:
            return MSG_OFFLINE_NO_CONN
        except Exception as exc:
            logger.exception("Multi-turn query error: %s", exc)
            return f"[Error] {exc!s}"

    def _stream_messages(
        self,
        headers: dict,
        payload: dict,
        timeout: int,
    ) -> Generator[str, None, None]:
        """Stream response from a multi-turn message payload."""
        try:
            response = self._session.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=timeout,
                stream=True,
            )
            if response.status_code != 200:
                yield f"[API Error] {response.status_code}: {response.text[:200]}"
                return

            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(data_str)
                    content = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                    if content:
                        yield content
                except (json.JSONDecodeError, IndexError, KeyError):
                    continue
        except Exception as exc:
            yield f"[Error] {exc!s}"
