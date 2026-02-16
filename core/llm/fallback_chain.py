# core/llm/fallback_chain.py
"""LLM Fallback Chain for DRAKBEN.

Wraps multiple LLM providers and tries them in order until one succeeds.
This ensures resilience when a single provider is down or rate-limited.

Usage::

    from core.llm.fallback_chain import FallbackChain

    chain = FallbackChain()
    chain.add_provider("openrouter", client1)
    chain.add_provider("ollama", client2)
    result = chain.query("Scan 10.0.0.1")
    # If openrouter fails, automatically retries with ollama
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class LLMClientProtocol(Protocol):
    """Minimal interface that any LLM client must satisfy."""

    def query(
        self,
        prompt: str,
        system_prompt: str | None = None,
        use_cache: bool = True,
        timeout: int = 30,
    ) -> str: ...

    def test_connection(self) -> bool: ...


@dataclass
class ProviderEntry:
    """A provider in the fallback chain."""

    name: str
    client: Any
    priority: int = 0
    healthy: bool = True
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    max_failures_before_circuit_break: int = 3
    circuit_break_seconds: float = 60.0


@dataclass
class QueryResult:
    """Result from a fallback chain query."""

    response: str
    provider_used: str
    latency_ms: float
    providers_tried: list[str] = field(default_factory=list)
    success: bool = True


class FallbackChain:
    """Multi-provider LLM fallback chain with circuit breaker pattern."""

    def __init__(self) -> None:
        self._providers: list[ProviderEntry] = []
        self._stats = {
            "total_queries": 0,
            "successful_queries": 0,
            "failovers": 0,
            "circuit_breaks": 0,
        }

    def add_provider(
        self,
        name: str,
        client: Any,
        priority: int = 0,
        *,
        max_failures: int = 3,
        cooldown: float = 60.0,
    ) -> None:
        """Add a provider to the chain."""
        entry = ProviderEntry(
            name=name,
            client=client,
            priority=priority,
            max_failures_before_circuit_break=max_failures,
            circuit_break_seconds=cooldown,
        )
        self._providers.append(entry)
        self._providers.sort(key=lambda p: p.priority)

    def query(
        self,
        prompt: str,
        system_prompt: str | None = None,
        *,
        timeout: int = 30,
    ) -> QueryResult:
        """Query providers in order until one succeeds."""
        self._stats["total_queries"] += 1
        providers_tried: list[str] = []

        for entry in self._providers:
            if not self._is_available(entry):
                continue

            providers_tried.append(entry.name)
            start = time.monotonic()

            try:
                response = entry.client.query(
                    prompt,
                    system_prompt=system_prompt,
                    timeout=timeout,
                )

                if isinstance(response, str) and response.startswith("["):
                    msg = f"Provider returned error: {response[:100]}"
                    raise RuntimeError(msg)

                latency = (time.monotonic() - start) * 1000
                entry.consecutive_failures = 0
                entry.healthy = True
                self._stats["successful_queries"] += 1

                if len(providers_tried) > 1:
                    self._stats["failovers"] += 1

                return QueryResult(
                    response=response,
                    provider_used=entry.name,
                    latency_ms=round(latency, 1),
                    providers_tried=providers_tried,
                    success=True,
                )

            except Exception as exc:
                entry.consecutive_failures += 1
                entry.last_failure_time = time.time()

                if entry.consecutive_failures >= entry.max_failures_before_circuit_break:
                    entry.healthy = False
                    self._stats["circuit_breaks"] += 1

                logger.warning("Provider '%s' failed: %s", entry.name, exc)
                continue

        return QueryResult(
            response="[Error] All LLM providers exhausted.",
            provider_used="none",
            latency_ms=0.0,
            providers_tried=providers_tried,
            success=False,
        )

    def health_check(self) -> dict[str, bool]:
        """Run health check on all providers."""
        results: dict[str, bool] = {}
        for entry in self._providers:
            try:
                healthy = entry.client.test_connection()
            except Exception:
                healthy = False
            if healthy:
                entry.healthy = True
                entry.consecutive_failures = 0
            results[entry.name] = healthy
        return results

    def get_stats(self) -> dict[str, Any]:
        """Get fallback chain statistics."""
        return {
            **self._stats,
            "providers": [
                {
                    "name": e.name,
                    "priority": e.priority,
                    "healthy": e.healthy,
                    "consecutive_failures": e.consecutive_failures,
                }
                for e in self._providers
            ],
        }

    def _is_available(self, entry: ProviderEntry) -> bool:
        """Check if a provider is available (not circuit-broken)."""
        if entry.healthy:
            return True
        elapsed = time.time() - entry.last_failure_time
        return elapsed >= entry.circuit_break_seconds
