# llm/openrouter_client.py
# Multi-Provider LLM Client - OpenRouter, Ollama, OpenAI, Custom
# Enhanced with: Retry Logic, Rate Limiting, Caching, Connection Pooling,
#                Streaming, Function Calling, Token Counting

import logging
import os
import threading
import time
from pathlib import Path
from threading import Lock

import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Placeholder values that should not be treated as valid keys
# Canonical definition in core.config._PLACEHOLDER_VALUES; aliased here for convenience.
from core.config import _PLACEHOLDER_VALUES as _PLACEHOLDER_API_VALUES

# ── Unified cache — delegates to core.llm.llm_cache ──
from core.llm.llm_cache import LLMCache as _CoreLLMCache

# Mixin classes — extracted from this file for maintainability
from llm.api_client_mixin import APIClientMixin

# Error message constants (SonarCloud: avoid duplicate literals)
# Canonical definitions in llm.constants; re-exported here for backward compat.
from llm.constants import MSG_RATE_LIMITED as _MSG_RATE_LIMITED
from llm.ollama_mixin import OllamaMixin
from llm.streaming_tools_mixin import StreamingToolsMixin

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
        load_dotenv(_env_file, override=True)
except ImportError:
    pass  # dotenv not installed, use OS env


class LLMCache:
    """Provider-level LLM cache — thin adapter over :class:`core.llm.llm_cache.LLMCache`.

    Maintains the original ``get(prompt, system_prompt, model)`` /
    ``set(prompt, system_prompt, model, response)`` convenience API while
    delegating all storage to the single canonical cache implementation.
    """

    def __init__(self, default_ttl: float = 300.0, max_entries: int = 1000) -> None:
        self._core = _CoreLLMCache(default_ttl=default_ttl, max_size=max_entries)

    def get(self, prompt: str, system_prompt: str, model: str) -> str | None:
        """Get cached response if available and not expired."""
        key = self._core.make_key(prompt, system_prompt, model)
        result = self._core.get(key)
        if result is None:
            return None
        return str(result)

    def set(
        self,
        prompt: str,
        system_prompt: str,
        model: str,
        response: str,
        ttl: float | None = None,
    ) -> None:
        """Store response in cache."""
        key = self._core.make_key(prompt, system_prompt, model)
        self._core.put(key, response, ttl=ttl)

    def clear(self) -> None:
        """Clear all cache entries."""
        self._core.clear()

    def get_stats(self) -> dict:
        """Get cache statistics."""
        return self._core.get_stats()


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


class OpenRouterClient(OllamaMixin, APIClientMixin, StreamingToolsMixin):
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
            raw_key = os.getenv("OPENAI_API_KEY", "")
            self.api_key = raw_key if raw_key not in _PLACEHOLDER_API_VALUES else None  # type: ignore[assignment]
        elif self.provider == "custom":
            self.base_url = os.getenv("CUSTOM_API_URL")  # type: ignore[assignment]
            self.model = os.getenv("CUSTOM_MODEL", "default")
            self.api_key = os.getenv("CUSTOM_API_KEY")  # type: ignore[assignment]
        else:  # openrouter (default)
            self.base_url = "https://openrouter.ai/api/v1/chat/completions"
            self.model = os.getenv(
                "OPENROUTER_MODEL",
                "meta-llama/llama-3.1-8b-instruct:free",
            )
            raw_key = os.getenv("OPENROUTER_API_KEY", "")
            self.api_key = raw_key if raw_key not in _PLACEHOLDER_API_VALUES else None  # type: ignore[assignment]

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
            return _MSG_RATE_LIMITED

        # Route to appropriate provider
        import time as _time

        _t0 = _time.time()

        if self.provider == "ollama":
            result = self._query_ollama(prompt, system_prompt, timeout)
        else:
            result = self._query_openai_compatible(prompt, system_prompt, timeout)

        _duration = _time.time() - _t0

        # Log to transparency dashboard (non-error responses only)
        if not result.startswith("["):
            try:
                from core.ui.transparency import get_transparency

                td = get_transparency()
                td.log_llm_query(prompt[:200], result[:200], _duration)
            except (ImportError, AttributeError) as e:
                # Transparency is optional, never break LLM flow
                logger.debug("Transparency logging skipped: %s", e)

        # Cache successful responses (not errors)
        if use_cache and self._cache and not result.startswith("["):
            self._cache.set(prompt, system_prompt, self.model, result)

        return result

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
        # Check for placeholder values
        if key in _PLACEHOLDER_API_VALUES:
            return f"API key is a placeholder value: '{key}'"
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

    def __enter__(self) -> "OpenRouterClient":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context manager, closing session."""
        self.close()

    def __del__(self) -> None:
        """Cleanup on deletion."""
        try:
            self.close()
        except (AttributeError, RuntimeError) as e:
            logger.debug("Error during cleanup: %s", e)
