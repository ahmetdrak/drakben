# core/observability.py
# DRAKBEN — Observability & Tracing Module
# Structured metrics, tracing, and monitoring for AI agent operations.
# Inspired by PentAGI's OpenTelemetry + Langfuse approach.

"""Lightweight observability layer for DRAKBEN.

Provides:
- Span-based tracing (tool executions, LLM calls, brain pipeline)
- Metrics collection (counters, gauges, histograms)
- Structured event logging
- Export to JSON for external tools

Usage::

    from core.observability import get_tracer, get_metrics

    tracer = get_tracer()
    with tracer.span("nmap_scan", {"target": "10.0.0.1"}) as span:
        result = run_nmap(...)
        span.set_attribute("ports_found", 5)
        span.set_status("ok")

    metrics = get_metrics()
    metrics.increment("tools.executed", tags={"tool": "nmap"})
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Span (trace unit)
# ---------------------------------------------------------------------------
@dataclass
class Span:
    """A single trace span representing an operation."""

    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    status: str = "unset"  # unset, ok, error
    parent_id: str | None = None
    span_id: str = ""
    children: list[Span] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        import uuid
        if not self.span_id:
            self.span_id = uuid.uuid4().hex[:16]

    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute."""
        self.attributes[key] = value

    def set_status(self, status: str, message: str = "") -> None:
        """Set span status (ok/error)."""
        self.status = status
        if message:
            self.attributes["status_message"] = message

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add a timestamped event to the span."""
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes or {},
        })

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds."""
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000

    def to_dict(self, _depth: int = 0) -> dict[str, Any]:
        """Serialize span to dictionary.

        Args:
            _depth: Internal recursion depth counter (max 50).
        """
        children: list[dict[str, Any]] = []
        if _depth < 50:
            children = [c.to_dict(_depth=_depth + 1) for c in self.children]
        return {
            "span_id": self.span_id,
            "name": self.name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "attributes": self.attributes,
            "events": self.events,
            "parent_id": self.parent_id,
            "children": children,
        }


# ---------------------------------------------------------------------------
# Tracer
# ---------------------------------------------------------------------------
class Tracer:
    """Span-based tracer for DRAKBEN operations.

    Thread-safe singleton.
    """

    _instance: Tracer | None = None
    _lock = threading.Lock()

    MAX_TRACES = 500

    def __new__(cls) -> Tracer:
        with cls._lock:
            if cls._instance is None:
                instance = super().__new__(cls)
                instance._traces: list[Span] = []
                instance._active_spans: dict[int, Span] = {}  # thread_id → span
                instance._tracer_lock = threading.RLock()
                instance._enabled = True
                cls._instance = instance
            return cls._instance

    @contextmanager
    def span(
        self,
        name: str,
        attributes: dict[str, Any] | None = None,
    ):
        """Context manager that creates and tracks a span.

        Yields the Span object so callers can add attributes/events.
        """
        if not self._enabled:
            yield _NoOpSpan()
            return

        sp = Span(name=name, attributes=attributes or {})
        tid = threading.get_ident()

        with self._tracer_lock:
            parent = self._active_spans.get(tid)
            if parent:
                sp.parent_id = parent.span_id
                parent.children.append(sp)
            self._active_spans[tid] = sp

        try:
            yield sp
            if sp.status == "unset":
                sp.set_status("ok")
        except Exception as exc:
            sp.set_status("error", str(exc))
            raise
        finally:
            sp.end_time = time.time()
            with self._tracer_lock:
                if parent:
                    self._active_spans[tid] = parent
                else:
                    self._active_spans.pop(tid, None)
                # Only store root spans
                if sp.parent_id is None:
                    self._traces.append(sp)
                    if len(self._traces) > self.MAX_TRACES:
                        self._traces = self._traces[-self.MAX_TRACES:]

    def get_traces(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent traces as dicts."""
        with self._tracer_lock:
            return [t.to_dict() for t in self._traces[-limit:]]

    def export_json(self, path: str | Path) -> None:
        """Export all traces to a JSON file."""
        traces = self.get_traces(limit=self.MAX_TRACES)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(traces, indent=2, default=str),
            encoding="utf-8",
        )

    def enable(self) -> None:
        """Enable tracing."""
        self._enabled = True

    def disable(self) -> None:
        """Disable tracing (zero overhead)."""
        self._enabled = False

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        with cls._lock:
            cls._instance = None


class _NoOpSpan:
    """No-op span when tracing is disabled."""

    span_id: str = ""

    @property
    def children(self) -> list:
        """Always return a fresh empty list."""
        return []

    def set_attribute(self, key: str, value: Any) -> None:
        # Intentionally empty: no-op when tracing is disabled
        pass

    def set_status(self, status: str, message: str = "") -> None:
        # Intentionally empty: no-op when tracing is disabled
        pass

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        # Intentionally empty: no-op when tracing is disabled
        pass

    @property
    def duration_ms(self) -> float:
        """Always zero when tracing is disabled."""
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        """Empty dict when tracing is disabled."""
        return {}


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
class MetricsCollector:
    """Lightweight metrics collector with counters, gauges, histograms.

    Thread-safe singleton.
    """

    _instance: MetricsCollector | None = None
    _lock = threading.Lock()

    def __new__(cls) -> MetricsCollector:
        with cls._lock:
            if cls._instance is None:
                instance = super().__new__(cls)
                instance._counters: dict[str, float] = defaultdict(float)
                instance._gauges: dict[str, float] = {}
                instance._histograms: dict[str, list[float]] = defaultdict(list)
                instance._metrics_lock = threading.RLock()
                instance._enabled = True
                cls._instance = instance
            return cls._instance

    def increment(self, name: str, value: float = 1.0, tags: dict[str, str] | None = None) -> None:
        """Increment a counter."""
        if not self._enabled:
            return
        key = self._make_key(name, tags)
        with self._metrics_lock:
            self._counters[key] += value

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Set a gauge value."""
        if not self._enabled:
            return
        key = self._make_key(name, tags)
        with self._metrics_lock:
            self._gauges[key] = value

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Record a histogram value."""
        if not self._enabled:
            return
        key = self._make_key(name, tags)
        with self._metrics_lock:
            bucket = self._histograms[key]
            bucket.append(value)
            # Cap at 1000 samples per metric
            if len(bucket) > 1000:
                self._histograms[key] = bucket[-1000:]

    def get_all(self) -> dict[str, Any]:
        """Get all metrics as a dict."""
        with self._metrics_lock:
            result: dict[str, Any] = {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
            }
            # Compute histogram stats
            hist_stats: dict[str, dict[str, float]] = {}
            for key, values in self._histograms.items():
                if values:
                    sorted_v = sorted(values)
                    p95_idx = min(int(len(sorted_v) * 0.95), len(sorted_v) - 1)
                    hist_stats[key] = {
                        "count": len(values),
                        "min": sorted_v[0],
                        "max": sorted_v[-1],
                        "avg": sum(values) / len(values),
                        "p50": sorted_v[len(sorted_v) // 2],
                        "p95": sorted_v[p95_idx],
                    }
            result["histograms"] = hist_stats
            return result

    def export_json(self, path: str | Path) -> None:
        """Export metrics to a JSON file."""
        data = self.get_all()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )

    @staticmethod
    def _make_key(name: str, tags: dict[str, str] | None) -> str:
        """Create a unique key from name + tags."""
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}{{{tag_str}}}"

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        with cls._lock:
            cls._instance = None


# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------
def get_tracer() -> Tracer:
    """Get the global Tracer singleton."""
    return Tracer()


def get_metrics() -> MetricsCollector:
    """Get the global MetricsCollector singleton."""
    return MetricsCollector()
