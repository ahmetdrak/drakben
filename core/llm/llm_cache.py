# core/llm/llm_cache.py
# DRAKBEN — LLM Response Cache
# TTL-based in-memory cache to avoid duplicate LLM calls for identical prompts.

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CacheKey:
    """Hashable cache key derived from prompt + system_prompt + model."""

    digest: str


@dataclass
class CacheEntry:
    """Single cached LLM response with TTL metadata."""

    value: str | dict[str, Any]
    created_at: float
    ttl: float
    hit_count: int = 0

    @property
    def expired(self) -> bool:
        return (time.monotonic() - self.created_at) >= self.ttl


@dataclass
class CacheStats:
    """Cache performance counters."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_entries: int = 0

    def to_dict(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "total_entries": self.total_entries,
            "hit_rate": round(self.hits / total, 4) if total > 0 else 0.0,
        }


class LLMCache:
    """Thread-safe, TTL-based in-memory LLM response cache.

    Features
    --------
    - SHA-256 key from (prompt, system_prompt, model)
    - Configurable TTL per entry (default 300s)
    - Max capacity with LRU-like eviction of expired entries first
    - Thread-safe via ``threading.Lock``
    - Cache bypass for streaming / tool-call queries (caller decides)

    Usage::

        cache = LLMCache(default_ttl=300, max_size=512)

        key = cache.make_key("scan 10.0.0.1", "You are a pentester", "gpt-4o")
        cached = cache.get(key)
        if cached is not None:
            return cached

        result = llm_client.query(...)
        cache.put(key, result)

    """

    def __init__(
        self,
        *,
        default_ttl: float = 300.0,
        max_size: int = 512,
    ) -> None:
        self._default_ttl = default_ttl
        self._max_size = max_size
        self._store: dict[CacheKey, CacheEntry] = {}
        self._lock = threading.Lock()
        self._stats = CacheStats()

    # ── Public API ──

    @staticmethod
    def make_key(
        prompt: str,
        system_prompt: str = "",
        model: str = "",
    ) -> CacheKey:
        """Create a deterministic cache key from query parameters."""
        raw = f"{prompt}\x00{system_prompt}\x00{model}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return CacheKey(digest=digest)

    def get(self, key: CacheKey) -> str | dict[str, Any] | None:
        """Retrieve a cached response, or ``None`` on miss / expiry."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._stats.misses += 1
                return None
            if entry.expired:
                del self._store[key]
                self._stats.evictions += 1
                self._stats.misses += 1
                self._stats.total_entries = len(self._store)
                return None
            entry.hit_count += 1
            self._stats.hits += 1
            return entry.value

    def put(
        self,
        key: CacheKey,
        value: str | dict[str, Any],
        *,
        ttl: float | None = None,
    ) -> None:
        """Store a response in the cache."""
        effective_ttl = ttl if ttl is not None else self._default_ttl
        with self._lock:
            # Evict expired entries if at capacity
            if len(self._store) >= self._max_size:
                self._evict_expired()
            # If still at capacity, evict oldest entry
            if len(self._store) >= self._max_size:
                self._evict_oldest()

            self._store[key] = CacheEntry(
                value=value,
                created_at=time.monotonic(),
                ttl=effective_ttl,
            )
            self._stats.total_entries = len(self._store)

    def invalidate(self, key: CacheKey) -> bool:
        """Remove a specific entry. Returns True if it existed."""
        with self._lock:
            removed = self._store.pop(key, None) is not None
            self._stats.total_entries = len(self._store)
            return removed

    def clear(self) -> int:
        """Clear all entries. Returns count of removed entries."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            self._stats.total_entries = 0
            self._stats.evictions += count
            return count

    def get_stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        with self._lock:
            self._stats.total_entries = len(self._store)
            return self._stats.to_dict()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)

    # ── Internal ──

    def _evict_expired(self) -> None:
        """Remove all expired entries (caller holds lock)."""
        expired_keys = [k for k, v in self._store.items() if v.expired]
        for k in expired_keys:
            del self._store[k]
            self._stats.evictions += 1

    def _evict_oldest(self) -> None:
        """Remove the oldest entry (caller holds lock)."""
        if not self._store:
            return
        oldest_key = min(self._store, key=lambda k: self._store[k].created_at)
        del self._store[oldest_key]
        self._stats.evictions += 1
