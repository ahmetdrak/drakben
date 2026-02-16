# llm/ollama_mixin.py
# Ollama-specific LLM methods — extracted from OpenRouterClient
"""Mixin providing all Ollama (local LLM) query and streaming methods."""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING

import requests  # type: ignore[import-untyped]

if TYPE_CHECKING:
    from collections.abc import Generator

logger = logging.getLogger(__name__)


class OllamaMixin:
    """Ollama-specific query and streaming methods for OpenRouterClient."""

    # ─────────────────── Ollama Query ───────────────────

    def _query_ollama(self, prompt: str, system_prompt: str, timeout: int) -> str:
        """Query local Ollama instance with retry logic."""
        for attempt in range(self.max_retries):
            try:
                response = self._make_ollama_non_streaming_request(
                    prompt,
                    system_prompt,
                    timeout,
                )
                result = self._handle_ollama_response(response, attempt)
                if result is not None:
                    return result
            except requests.exceptions.ConnectionError:
                msg = self._handle_ollama_connection_error(attempt)
                if msg:  # Non-empty string means final error
                    return msg
                # Empty string means retry — continue the loop
            except requests.exceptions.Timeout:
                msg = self._handle_ollama_timeout(attempt)
                if msg:
                    return msg
            except Exception as e:
                logger.exception("Ollama query error: %s", e)
                return f"[Ollama Error] {e!s}"

        return "[Error] Max retries exceeded"

    def _make_ollama_non_streaming_request(
        self,
        prompt: str,
        system_prompt: str,
        timeout: int,
    ) -> requests.Response:
        """Make non-streaming Ollama request."""
        payload = {
            "model": self.model,
            "prompt": f"{system_prompt}\n\nUser: {prompt}\n\nAssistant:",
            "stream": False,
        }
        return self._session.post(self.base_url, json=payload, timeout=timeout)

    def _handle_ollama_response(self, response: requests.Response, attempt: int) -> str | None:
        """Handle Ollama response with retry logic."""
        if response.status_code == 200:
            return response.json().get("response", "")
        if response.status_code == 429:
            return self._handle_ollama_rate_limit(response, attempt)
        return self._handle_ollama_error(response, attempt)

    def _handle_ollama_rate_limit(self, response: requests.Response, attempt: int) -> str | None:
        """Handle Ollama rate limiting."""
        retry_after = int(response.headers.get("Retry-After", 5))
        self._rate_limiter.set_retry_after(retry_after)
        if attempt < self.max_retries - 1:
            time.sleep(retry_after)
            return None
        return "[Rate Limit] Ollama rate limited. Please wait."

    def _handle_ollama_error(self, response: requests.Response, attempt: int) -> str | None:
        """Handle Ollama error responses."""
        if attempt < self.max_retries - 1:
            time.sleep(2**attempt)
            return None
        return f"[Ollama Error] {response.status_code}: {response.text[:100]}"

    def _handle_ollama_connection_error(self, attempt: int) -> str:
        """Handle Ollama connection errors."""
        if attempt < self.max_retries - 1:
            time.sleep(2**attempt)
            return ""  # Continue retry
        return "[Offline] Ollama baglantisi yok. 'ollama serve' calistirin."

    def _handle_ollama_timeout(self, attempt: int) -> str:
        """Handle Ollama timeout errors."""
        if attempt < self.max_retries - 1:
            return ""  # Continue retry
        return "[Timeout] Ollama did not respond in time."

    # ─────────────────── Ollama Streaming ───────────────────

    def _stream_ollama(
        self,
        prompt: str,
        system_prompt: str,
        timeout: int,
    ) -> Generator[str, None, None]:
        """Stream from local Ollama instance."""
        payload = {
            "model": self.model,
            "prompt": f"{system_prompt}\n\nUser: {prompt}\n\nAssistant:",
            "stream": True,
        }
        try:
            response = self._session.post(
                self.base_url,
                json=payload,
                timeout=timeout,
                stream=True,
            )
            if response.status_code != 200:
                yield f"[Ollama Error] {response.status_code}"
                return

            for line in response.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    token = chunk.get("response", "")
                    if token:
                        yield token
                    if chunk.get("done"):
                        break
                except json.JSONDecodeError:
                    continue
        except requests.exceptions.ConnectionError:
            yield "[Offline] Ollama bağlantısı yok."
        except Exception as exc:
            yield f"[Error] {exc!s}"
