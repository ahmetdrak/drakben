# core/events.py
# DRAKBEN Event System

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Callable, List, Union
from datetime import datetime


class EventType(Enum):
    """Event types"""
    # Workflow events
    WORKFLOW_START = "workflow_start"
    WORKFLOW_COMPLETE = "workflow_complete"
    WORKFLOW_ERROR = "workflow_error"
    
    # Step events
    STEP_START = "step_start"
    STEP_COMPLETE = "step_complete"
    STEP_ERROR = "step_error"
    STEP_SKIP = "step_skip"
    
    # Approval events
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    
    # User events
    NOTIFY_USER = "notify_user"
    USER_INPUT = "user_input"
    
    # Plugin events
    PLUGIN_LOAD = "plugin_load"
    PLUGIN_EXECUTE = "plugin_execute"
    PLUGIN_COMPLETE = "plugin_complete"
    PLUGIN_ERROR = "plugin_error"
    
    # LLM events
    LLM_QUERY = "llm_query"
    LLM_RESPONSE = "llm_response"
    LLM_ERROR = "llm_error"


@dataclass
class Event:
    """Event data structure"""
    type: EventType
    data: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "system"
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type.value,
            "data": self.data,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source
        }


class EventEmitter:
    """
    Event emitter for DRAKBEN
    Allows subscribing to and emitting events
    """
    
    def __init__(self):
        self._handlers: Dict[EventType, List[Callable]] = {}
        self._history: List[Event] = []
        self._max_history = 100
    
    def on(self, event_type: EventType, handler: Callable):
        """Subscribe to an event"""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
    
    def off(self, event_type: EventType, handler: Callable = None):
        """Unsubscribe from an event"""
        if event_type in self._handlers:
            if handler:
                self._handlers[event_type].remove(handler)
            else:
                self._handlers[event_type] = []
    
    def emit(self, event_or_type, data: Dict = None, source: str = "system"):
        """
        Emit an event
        
        Args:
            event_or_type: Either an Event object or EventType
            data: Event data (only used if event_or_type is EventType)
            source: Event source (only used if event_or_type is EventType)
        """
        # Handle both Event object and EventType
        if isinstance(event_or_type, Event):
            event = event_or_type
            event_type = event.type
        else:
            event_type = event_or_type
            event = Event(
                type=event_type,
                data=data or {},
                source=source
            )
        
        # Add to history
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)
        
        # Call handlers
        if event_type in self._handlers:
            for handler in self._handlers[event_type]:
                try:
                    handler(event)
                except Exception as e:
                    print(f"Event handler error: {e}")
        
        return event
    
    def emit_step_start(self, step_name: str, description: str = None):
        """Emit step start event"""
        self.emit(EventType.STEP_START, {
            "step": step_name,
            "description": description or step_name
        })
    
    def emit_step_complete(self, step_name: str, result: Any = None):
        """Emit step complete event"""
        self.emit(EventType.STEP_COMPLETE, {
            "step": step_name,
            "result": result
        })
    
    def emit_step_error(self, step_name: str, error: str):
        """Emit step error event"""
        self.emit(EventType.STEP_ERROR, {
            "step": step_name,
            "error": error
        })
    
    def emit_notify(self, message: str, level: str = "info"):
        """Emit user notification"""
        self.emit(EventType.NOTIFY_USER, {
            "message": message,
            "level": level
        })
    
    def get_history(self, event_type: EventType = None, limit: int = 10) -> List[Event]:
        """Get event history"""
        history = self._history
        if event_type:
            history = [e for e in history if e.type == event_type]
        return history[-limit:]


# Global event emitter
_emitter: EventEmitter = None


def get_emitter() -> EventEmitter:
    """Get global event emitter"""
    global _emitter
    if _emitter is None:
        _emitter = EventEmitter()
    return _emitter
