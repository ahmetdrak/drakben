# core/events.py
# DRAKBEN — Event-Driven Architecture (EventBus)
# Decouples agent logic from UI for multi-frontend support.
# Inspired by PentestGPT's EventBus pub/sub pattern.

"""Thread-safe publish/subscribe event system.

Usage::

    from core.events import EventBus, EventType

    bus = EventBus()
    bus.subscribe(EventType.TOOL_START, my_handler)
    bus.publish(EventType.TOOL_START, {"tool": "nmap", "target": "10.0.0.1"})
"""

from __future__ import annotations

import enum
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event Types
# ---------------------------------------------------------------------------
class EventType(enum.Enum):
    """All event types in the DRAKBEN system."""

    # Agent lifecycle
    AGENT_STARTED = "agent.started"
    AGENT_STOPPED = "agent.stopped"
    AGENT_PAUSED = "agent.paused"
    AGENT_RESUMED = "agent.resumed"
    AGENT_ERROR = "agent.error"

    # State changes
    STATE_CHANGED = "state.changed"
    PHASE_CHANGED = "state.phase_changed"
    TARGET_SET = "state.target_set"

    # Tool execution
    TOOL_START = "tool.start"
    TOOL_COMPLETE = "tool.complete"
    TOOL_FAILED = "tool.failed"
    TOOL_BLOCKED = "tool.blocked"

    # Planning
    PLAN_CREATED = "plan.created"
    PLAN_STEP_START = "plan.step.start"
    PLAN_STEP_DONE = "plan.step.done"
    PLAN_REPLANNED = "plan.replanned"
    PLAN_DYNAMIC_INJECT = "plan.dynamic_inject"

    # LLM
    LLM_QUERY_START = "llm.query.start"
    LLM_QUERY_DONE = "llm.query.done"
    LLM_FALLBACK = "llm.fallback"
    LLM_STREAM_TOKEN = "llm.stream.token"

    # Brain pipeline
    REASONING_START = "brain.reasoning.start"
    REASONING_DONE = "brain.reasoning.done"
    DECISION_MADE = "brain.decision.made"
    SELF_CORRECTION = "brain.self_correction"

    # Security
    HALLUCINATION_DETECTED = "security.hallucination"
    DANGEROUS_COMMAND = "security.dangerous_command"
    APPROVAL_REQUIRED = "security.approval_required"
    STAGNATION_DETECTED = "security.stagnation"

    # Findings
    VULN_FOUND = "finding.vulnerability"
    SERVICE_FOUND = "finding.service"
    CREDENTIAL_FOUND = "finding.credential"
    FOOTHOLD_GAINED = "finding.foothold"

    # Reports
    REPORT_GENERATED = "report.generated"

    # Evolution
    EVOLUTION_PENALTY = "evolution.penalty"
    PROFILE_MUTATED = "evolution.profile_mutated"
    PROFILE_RETIRED = "evolution.profile_retired"
    TOOL_CREATED = "evolution.tool_created"

    # User interaction
    USER_INPUT = "user.input"
    USER_COMMAND = "user.command"

    # System
    LOG_MESSAGE = "system.log"
    METRIC = "system.metric"


# ---------------------------------------------------------------------------
# Event Data
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Event:
    """Immutable event object."""

    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    source: str = ""


# ---------------------------------------------------------------------------
# Handler Protocol
# ---------------------------------------------------------------------------
class EventHandler(Protocol):
    """Protocol for event handlers."""

    def __call__(self, event: Event) -> None: ...


# ---------------------------------------------------------------------------
# EventBus (Singleton)
# ---------------------------------------------------------------------------
class EventBus:
    """Thread-safe publish/subscribe event bus.

    Singleton — all components share one bus instance via ``get_event_bus()``.
    """

    _instance: EventBus | None = None
    _lock = threading.Lock()

    MAX_HISTORY = 1000  # ring-buffer size

    def __new__(cls) -> EventBus:
        with cls._lock:
            if cls._instance is None:
                instance = super().__new__(cls)
                instance._subscribers: dict[EventType, list[EventHandler]] = defaultdict(list)
                instance._global_subscribers: list[EventHandler] = []
                instance._history: list[Event] = []
                instance._bus_lock = threading.RLock()
                instance._paused = False
                cls._instance = instance
            return cls._instance

    # -- Subscribe / Unsubscribe --

    def subscribe(self, event_type: EventType | str, handler: EventHandler) -> None:
        """Subscribe to a specific event type."""
        if isinstance(event_type, str):
            # Allow string event types for convenience
            event_type = EventType(event_type) if event_type in {e.value for e in EventType} else event_type  # type: ignore[assignment]
        with self._bus_lock:
            if handler not in self._subscribers[event_type]:
                self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe to ALL event types (global listener)."""
        with self._bus_lock:
            if handler not in self._global_subscribers:
                self._global_subscribers.append(handler)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Unsubscribe from a specific event type."""
        with self._bus_lock:
            handlers = self._subscribers.get(event_type)
            if handlers and handler in handlers:
                handlers.remove(handler)

    def unsubscribe_all(self, handler: EventHandler) -> None:
        """Unsubscribe from all event types."""
        with self._bus_lock:
            for handlers in self._subscribers.values():
                if handler in handlers:
                    handlers.remove(handler)
            if handler in self._global_subscribers:
                self._global_subscribers.remove(handler)

    # -- Publish --

    def publish(
        self,
        event_type: EventType | str,
        data: dict[str, Any] | None = None,
        source: str = "",
    ) -> None:
        """Publish an event to all subscribers (non-blocking)."""
        # Resolve string event_type to enum if possible
        resolved_type = event_type
        if isinstance(event_type, str):
            try:
                resolved_type = EventType(event_type)
            except ValueError:
                resolved_type = event_type  # type: ignore[assignment]

        event = Event(type=resolved_type, data=data or {}, source=source)  # type: ignore[arg-type]

        with self._bus_lock:
            if self._paused:
                return

            # Store in ring-buffer history
            self._history.append(event)
            if len(self._history) > self.MAX_HISTORY:
                self._history = self._history[-self.MAX_HISTORY :]

            # Snapshot handlers to avoid lock during dispatch
            specific = list(self._subscribers.get(event_type, []))
            global_handlers = list(self._global_subscribers)

        # Dispatch without holding the lock
        event_label = event_type.value if hasattr(event_type, "value") else str(event_type)
        for handler in specific + global_handlers:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Event handler error for %s",
                    event_label,
                )

    # -- Control --

    def pause(self) -> None:
        """Pause event dispatching."""
        with self._bus_lock:
            self._paused = True

    def resume(self) -> None:
        """Resume event dispatching."""
        with self._bus_lock:
            self._paused = False

    def clear(self) -> None:
        """Clear all subscribers and history."""
        with self._bus_lock:
            self._subscribers.clear()
            self._global_subscribers.clear()
            self._history.clear()

    # -- Query --

    def get_history(
        self,
        event_type: EventType | None = None,
        limit: int = 50,
    ) -> list[Event]:
        """Get recent events, optionally filtered by type."""
        with self._bus_lock:
            if event_type:
                filtered = [e for e in self._history if e.type == event_type]
            else:
                filtered = list(self._history)
            return filtered[-limit:]

    @property
    def subscriber_count(self) -> int:
        """Total number of subscriptions."""
        with self._bus_lock:
            return sum(len(h) for h in self._subscribers.values()) + len(
                self._global_subscribers,
            )

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.clear()
            cls._instance = None


def get_event_bus() -> EventBus:
    """Get the global EventBus singleton."""
    return EventBus()
