# llm/api_client_mixin.py
# API request/response handling — extracted from OpenRouterClient
"""Mixin providing OpenAI-compatible API query and error handling methods."""

from __future__ import annotations

import logging
import time

import requests  # type: ignore[import-untyped]

from llm.constants import MSG_OFFLINE_NO_KEY

logger = logging.getLogger(__name__)


class APIClientMixin:
    """API call, response handling, and error recovery for OpenRouterClient."""

    def _query_openai_compatible(
        self,
        prompt: str,
        system_prompt: str,
        timeout: int,
    ) -> str:
        """Query OpenAI-compatible API with retry logic and rate limit handling."""
        if not self.api_key:
            return MSG_OFFLINE_NO_KEY

        # Validate key format before sending request
        key_warning = self._validate_api_key_format()
        if key_warning:
            logger.warning(key_warning)

        headers = self._build_api_headers()
        payload = self._build_api_payload(system_prompt, prompt)

        for attempt in range(self.max_retries):
            result = self._attempt_api_call(headers, payload, timeout, attempt)
            if result is not None:
                return result

        return "[Error] Max retries exceeded"

    def _attempt_api_call(
        self,
        headers: dict,
        payload: dict,
        timeout: int,
        attempt: int,
    ) -> str | None:
        """Execute a single API call attempt. Returns result or None to retry."""
        try:
            response = self._session.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=timeout,
            )
            return self._handle_api_response(response, attempt)
        except requests.exceptions.Timeout:
            msg = self._handle_api_timeout(timeout, attempt)
            return msg if msg else None
        except requests.exceptions.ConnectionError as e:
            msg = self._handle_api_connection_error(e, attempt)
            return msg if msg else None
        except requests.exceptions.RequestException as e:
            msg = self._handle_api_request_error(e, attempt)
            return msg if msg else None
        except Exception as e:
            logger.exception("API query error: %s", e)
            return f"[Error] {e!s}"

    def _build_api_headers(self) -> dict[str, str]:
        """Build API request headers."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/drakben/drakben"  # updated to generic
            headers["X-Title"] = "DRAKBEN Pentest AI"
        return headers

    def _build_api_payload(self, system_prompt: str, prompt: str) -> dict:
        """Build API request payload."""
        return {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
        }

    def _handle_api_response(self, response: requests.Response, attempt: int) -> str | None:
        """Handle API response with status code logic."""
        if response.status_code == 200:
            return self._parse_api_success(response)
        if response.status_code == 401:
            return self._handle_api_auth_error(response)
        if response.status_code == 429:
            return self._handle_api_rate_limit(response, attempt)
        if response.status_code >= 500:
            return self._handle_api_server_error(response, attempt)
        return f"[API Error] {response.status_code}: {response.text[:100]}"

    def _parse_api_success(self, response: requests.Response) -> str:
        """Parse successful API response."""
        try:
            data = response.json()
            if "choices" in data and len(data["choices"]) > 0:
                return data["choices"][0]["message"]["content"]
            return "[API Error] Unexpected response format"
        except (KeyError, IndexError, ValueError) as e:
            return f"[API Error] Failed to parse response: {e}"

    def _handle_api_auth_error(self, response: requests.Response) -> str:
        """Handle 401 Unauthorized response with detailed logging."""
        detail = self._extract_error_detail(response)
        key_hint = self._build_key_hint()
        logger.error("API 401 Unauthorized%s: %s", key_hint, detail)
        if detail:
            return f"[Auth Error] Invalid API key: {detail}. Check config/api.env"
        return "[Auth Error] Invalid API key. Check config/api.env"

    def _build_key_hint(self) -> str:
        """Build masked API key hint for logging."""
        if not self.api_key:
            return ""
        if len(self.api_key) > 20:
            masked = self.api_key[:12] + "..." + self.api_key[-4:]
        else:
            masked = "***"
        return f" (key: {masked}, len={len(self.api_key)})"

    def _handle_api_rate_limit(self, response: requests.Response, attempt: int) -> str | None:
        """Handle API rate limiting."""
        retry_after = int(response.headers.get("Retry-After", 5))
        self._rate_limiter.set_retry_after(retry_after)
        if attempt < self.max_retries - 1:
            logger.warning(
                f"Rate limited, waiting {retry_after}s (attempt {attempt + 1}/{self.max_retries})",
            )
            time.sleep(retry_after)
            return None
        return "[Rate Limit] Too many requests. Please wait and retry."

    def _handle_api_server_error(self, response: requests.Response, attempt: int) -> str | None:
        """Handle API server errors (5xx)."""
        if attempt < self.max_retries - 1:
            wait_time = min(2**attempt, 5)
            logger.warning(
                f"Server error {response.status_code}, retrying in "
                f"{wait_time}s (attempt {attempt + 1}/{self.max_retries})",
            )
            time.sleep(wait_time)
            return None
        return f"[Server Error] {response.status_code}: Service unavailable"

    def _handle_api_timeout(self, timeout: int, attempt: int) -> str:
        """Handle API timeout errors."""
        logger.warning(
            f"Request timeout after {timeout}s (attempt {attempt + 1}/{self.max_retries}) - possible WAF blocking",
        )
        if attempt < self.max_retries - 1:
            wait_time = min(2**attempt, 5)
            time.sleep(wait_time)
            return ""  # Signal retry
        return "[Timeout] API did not respond in time (possible WAF blocking)."

    def _handle_api_connection_error(self, e: Exception, attempt: int) -> str:
        """Handle API connection errors."""
        logger.warning("Connection error: %s", e)
        if attempt < self.max_retries - 1:
            time.sleep(min(2**attempt, 5))
            return ""  # Continue retry
        return "[Offline] No internet connection or connection refused."

    def _handle_api_request_error(self, e: Exception, attempt: int) -> str:
        """Handle API request errors."""
        logger.error("Request error: %s", e)
        if attempt < self.max_retries - 1:
            time.sleep(1)
            return ""  # Continue retry
        return f"[Request Error] {e!s}"
