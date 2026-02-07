# llm/openrouter_client.py
# Multi-Provider LLM Client - OpenRouter, Ollama, OpenAI, Custom
# Enhanced with: Retry Logic, Rate Limiting, Caching, Connection Pooling

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Setup logger
logger = logging.getLogger(__name__)

# Load environment variables - proje kokunden
try:
    from dotenv import load_dotenv

    # Proje kokunu bul
    _this_file = Path(__file__).resolve()
    _project_root = _this_file.parent.parent
    _env_file = _project_root / "config" / "api.env"
    if _env_file.exists():
        load_dotenv(_env_file)
except ImportError:
    pass  # dotenv not installed, use OS env


@dataclass
class CacheEntry:
    """Cache entry for LLM responses."""

    response: str
    timestamp: float
    ttl: float  # Time to live in seconds


class LLMCache:
    """Thread-safe LLM response cache.
    Reduces API costs and improves response time for repeated queries.
    """

    def __init__(self, default_ttl: float = 300.0, max_entries: int = 1000) -> None:
        """Initialize cache.

        Args:
            default_ttl: Default time-to-live for cache entries (seconds)
            max_entries: Maximum number of cache entries

        """
        self._cache: dict[str, CacheEntry] = {}
        self._lock = Lock()
        self.default_ttl = default_ttl
        self.max_entries = max_entries
        self._hits = 0
        self._misses = 0

    def _generate_key(self, prompt: str, system_prompt: str, model: str) -> str:
        """Generate unique cache key from prompt, system prompt, and model."""
        content = f"{model}:{system_prompt}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()

    def get(self, prompt: str, system_prompt: str, model: str) -> str | None:
        """Get cached response if available and not expired.

        Returns:
            Cached response or None if not found/expired

        """
        key = self._generate_key(prompt, system_prompt, model)

        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None

            # Check if expired
            if time.time() - entry.timestamp > entry.ttl:
                del self._cache[key]
                self._misses += 1
                return None

            self._hits += 1
            return entry.response

    def set(
        self,
        prompt: str,
        system_prompt: str,
        model: str,
        response: str,
        ttl: float | None = None,
    ) -> None:
        """Store response in cache."""
        key = self._generate_key(prompt, system_prompt, model)

        with self._lock:
            # Evict oldest entries if at capacity
            if len(self._cache) >= self.max_entries:
                oldest_key = min(
                    self._cache.keys(),
                    key=lambda k: self._cache[k].timestamp,
                )
                del self._cache[oldest_key]

            self._cache[key] = CacheEntry(
                response=response,
                timestamp=time.time(),
                ttl=ttl if ttl is not None else self.default_ttl,
            )

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def get_stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0
            return {
                "entries": len(self._cache),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": hit_rate,
                "max_entries": self.max_entries,
            }


class RateLimiter:
    """Token bucket rate limiter for API requests.
    Prevents hitting rate limits by spacing out requests.
    Uses threading.Condition for efficient waiting instead of busy-polling.
    """

    def __init__(self, requests_per_minute: int = 60, burst_size: int = 10) -> None:
        """Initialize rate limiter.

        Args:
            requests_per_minute: Max sustained requests per minute
            burst_size: Max burst requests allowed

        """
        self.rate = requests_per_minute / 60.0  # requests per second
        self.burst_size = float(burst_size)
        self.tokens: float = self.burst_size
        self.last_update = time.time()
        self._lock = Lock()
        self._condition = threading.Condition(self._lock)
        self._retry_after: float | None = None

    def acquire(self, timeout: float = 30.0) -> bool:
        """Acquire a token to make a request.
        Uses Condition.wait() for efficient blocking instead of busy-polling.

        Returns:
            True if token acquired, False if timeout

        """
        deadline = time.time() + timeout

        with self._condition:
            while True:
                # Check if we're in a retry-after period
                if self._retry_after and time.time() < self._retry_after:
                    wait_time = self._retry_after - time.time()
                else:
                    # Refill tokens based on time passed
                    now = time.time()
                    elapsed = now - self.last_update
                    self.tokens = min(
                        self.burst_size,
                        self.tokens + elapsed * self.rate,
                    )
                    self.last_update = now

                    if self.tokens >= 1:
                        self.tokens -= 1
                        return True

                    wait_time = (1 - self.tokens) / self.rate

                # Check timeout
                remaining = deadline - time.time()
                if remaining <= 0:
                    return False

                # Efficient wait using Condition (releases lock while waiting)
                actual_wait = min(wait_time, remaining, 1.0)  # Max 1 second wait
                self._condition.wait(timeout=actual_wait)

    def set_retry_after(self, seconds: float) -> None:
        """Set retry-after period from API response.

        Safety: Caps maximum wait time to 60 seconds to prevent
        indefinite blocking from malformed/malicious responses.
        """
        # Cap retry-after to maximum 60 seconds for safety
        safe_seconds = min(seconds, 60.0)
        with self._lock:
            self._retry_after = time.time() + safe_seconds
            if seconds > 60.0:
                logger.warning(
                    f"Rate limit retry-after capped from {seconds}s to {safe_seconds}s",
                )
            else:
                logger.warning(
                    f"Rate limit hit, waiting {safe_seconds}s before next request",
                )


class OpenRouterClient:
    """Multi-provider LLM client supporting:
    - OpenRouter (100+ models including free ones)
    - Ollama (local LLMs)
    - OpenAI Direct
    - Custom OpenAI-compatible APIs.

    Enhanced with:
    - Automatic retry with exponential backoff
    - Rate limiting to prevent 429 errors
    - Response caching to reduce costs
    - Connection pooling for better performance
    """

    def __init__(
        self,
        enable_cache: bool = True,
        cache_ttl: float = 300.0,
        max_retries: int = 3,
        requests_per_minute: int = 60,
    ) -> None:
        """Initialize LLM client.

        Args:
            enable_cache: Enable response caching (default: True)
            cache_ttl: Cache time-to-live in seconds (default: 300)
            max_retries: Maximum retry attempts (default: 3)
            requests_per_minute: Rate limit for requests (default: 60)

        """
        self.provider = self._detect_provider()
        self._setup_provider()

        # Setup caching
        self.enable_cache = enable_cache
        self._cache = LLMCache(default_ttl=cache_ttl) if enable_cache else None

        # Setup rate limiting
        self._rate_limiter = RateLimiter(requests_per_minute=requests_per_minute)

        # Setup connection pooling with retry strategy
        self.max_retries = max_retries
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create requests session with connection pooling and retry strategy."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,  # 1, 2, 4 seconds between retries
            status_forcelist=[500, 502, 503, 504],  # Server errors only
            allowed_methods=["POST", "GET"],
            raise_on_status=False,
        )

        # Configure connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20,
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _detect_provider(self) -> str:
        """Auto-detect which LLM provider to use."""
        if os.getenv("LOCAL_LLM_URL"):
            return "ollama"
        if os.getenv("OPENAI_API_KEY") and not os.getenv("OPENROUTER_API_KEY"):
            return "openai"
        if os.getenv("CUSTOM_API_URL"):
            return "custom"
        return "openrouter"

    def _setup_provider(self) -> None:
        """Setup provider-specific configuration."""
        if self.provider == "ollama":
            self.base_url = os.getenv(
                "LOCAL_LLM_URL",
                "http://localhost:11434/api/generate",
            )
            self.model = os.getenv("LOCAL_LLM_MODEL", "llama3.1")
            self.api_key = None
        elif self.provider == "openai":
            self.base_url = "https://api.openai.com/v1/chat/completions"
            self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            self.api_key = os.getenv("OPENAI_API_KEY")
        elif self.provider == "custom":
            self.base_url = os.getenv("CUSTOM_API_URL")
            self.model = os.getenv("CUSTOM_MODEL", "default")
            self.api_key = os.getenv("CUSTOM_API_KEY")
        else:  # openrouter (default)
            self.base_url = "https://openrouter.ai/api/v1/chat/completions"
            self.model = os.getenv(
                "OPENROUTER_MODEL",
                "meta-llama/llama-3.1-8b-instruct:free",
            )
            self.api_key = os.getenv("OPENROUTER_API_KEY")

    def query(
        self,
        prompt: str,
        system_prompt: str | None = None,
        use_cache: bool = True,
        timeout: int = 20,  # Reduced from 30 to prevent long waits on WAF blocking
    ) -> str:
        """Query the LLM with automatic provider routing.

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            use_cache: Whether to use cached responses (default: True)
            timeout: Request timeout in seconds (default: 30)

        Returns:
            LLM response string

        """
        # Check for global stop signal
        try:
            from core.stop_controller import check_stop
            if check_stop():
                return "[Stopped] Operation cancelled by user."
        except ImportError:
            pass

        if system_prompt is None:
            system_prompt = "You are a penetration testing assistant. Provide clear, actionable security advice."

        # Check cache first
        if use_cache and self._cache:
            cached = self._cache.get(prompt, system_prompt, self.model)
            if cached:
                logger.debug("Cache hit for prompt")
                return cached

        # Acquire rate limit token
        if not self._rate_limiter.acquire(timeout=timeout):
            return "[Rate Limited] Too many requests, please wait."

        # Route to appropriate provider
        if self.provider == "ollama":
            result = self._query_ollama(prompt, system_prompt, timeout)
        else:
            result = self._query_openai_compatible(prompt, system_prompt, timeout)

        # Cache successful responses (not errors)
        if use_cache and self._cache and not result.startswith("["):
            self._cache.set(prompt, system_prompt, self.model, result)

        return result

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
                return self._handle_ollama_connection_error(attempt)
            except requests.exceptions.Timeout:
                return self._handle_ollama_timeout(attempt)
            except Exception as e:
                logger.exception(f"Ollama query error: {e}")
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

    def _query_openai_compatible(
        self,
        prompt: str,
        system_prompt: str,
        timeout: int,
    ) -> str:
        """Query OpenAI-compatible API with retry logic and rate limit handling."""
        if not self.api_key:
            return "[Offline Mode] No API key configured."

        # Validate key format before sending request
        key_warning = self._validate_api_key_format()
        if key_warning:
            logger.warning(key_warning)

        headers = self._build_api_headers()
        payload = self._build_api_payload(system_prompt, prompt)

        for attempt in range(self.max_retries):
            try:
                response = self._session.post(
                    self.base_url,
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                )
                result = self._handle_api_response(response, attempt)
                if result is not None:
                    return result
            except requests.exceptions.Timeout:
                return self._handle_api_timeout(timeout, attempt)
            except requests.exceptions.ConnectionError as e:
                return self._handle_api_connection_error(e, attempt)
            except requests.exceptions.RequestException as e:
                return self._handle_api_request_error(e, attempt)
            except Exception as e:
                logger.exception(f"API query error: {e}")
                return f"[Error] {e!s}"

        return "[Error] Max retries exceeded"

    def _build_api_headers(self) -> dict[str, str]:
        """Build API request headers."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = (
                "https://github.com/drakben/drakben"  # updated to generic
            )
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
                f"Server error {response.status_code}, retrying in {wait_time}s (attempt {attempt + 1}/{self.max_retries})",
            )
            time.sleep(wait_time)
            return None
        return f"[Server Error] {response.status_code}: Service unavailable"

    def _handle_api_timeout(self, timeout: int, attempt: int) -> str:
        """Handle API timeout errors."""
        logger.warning(
            f"Request timeout after {timeout}s (attempt {attempt + 1}/{self.max_retries}) - possible WAF blocking",
        )
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

    def get_provider_info(self) -> dict:
        """Return current provider configuration."""
        info = {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "has_api_key": bool(self.api_key),
            "cache_enabled": self.enable_cache,
            "max_retries": self.max_retries,
        }

        if self._cache:
            info["cache_stats"] = self._cache.get_stats()

        return info

    def test_connection(self) -> bool:
        """Test if the LLM connection is working."""
        try:
            result = self.query("Hello", use_cache=False, timeout=10)
            return "[Error]" not in result and "[Offline]" not in result
        except (ConnectionError, TimeoutError, ValueError) as e:
            logger.debug("Health check failed: %s", e)
            return False

    def _extract_error_detail(self, response: requests.Response) -> str:
        """Extract error detail message from API error response."""
        try:
            data = response.json()
            error = data.get("error", {})
            if isinstance(error, dict):
                return error.get("message", "")
            return str(error) if error else ""
        except (ValueError, AttributeError):
            return ""

    def _validate_api_key_format(self) -> str:
        """Validate API key format and return warning message if invalid.

        Returns:
            Warning message string if key format is suspicious, empty string if OK.

        """
        if not self.api_key:
            return ""
        key = self.api_key.strip()
        if key != self.api_key:
            return "API key contains leading/trailing whitespace"
        if self.provider == "openrouter" and key.startswith("sk-or-"):
            # OpenRouter keys: sk-or-v1-<64 hex chars> = total ~74 chars
            if len(key) < 70:
                return f"OpenRouter key looks too short (len={len(key)}, expected ~74)"
        return ""

    def close(self) -> None:
        """Close the session and cleanup resources."""
        if self._session:
            self._session.close()
            logger.info("LLM client session closed")

    def __del__(self) -> None:
        """Cleanup on deletion."""
        try:
            self.close()
        except (AttributeError, RuntimeError) as e:
            logger.debug("Error during cleanup: %s", e)
