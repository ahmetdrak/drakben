# core/security/audit_decorator.py
"""Audit auto-instrumentation decorator for DRAKBEN.

Provides ``@audited`` — a decorator that automatically logs function calls
to the forensic AuditLogger with hash-chain integrity.

Usage::

    from core.security.audit_decorator import audited
    from core.security.security_utils import AuditEventType

    @audited(AuditEventType.COMMAND_EXECUTED, risk_level="medium")
    def execute(self, command: str, timeout: int = 120) -> ExecutionResult:
        ...
"""

from __future__ import annotations

import functools
import logging
import os
import time
from datetime import datetime
from typing import TYPE_CHECKING, Any

from core.security.security_utils import AuditEvent, AuditEventType, get_audit_logger

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


def audited(
    event_type: AuditEventType = AuditEventType.COMMAND_EXECUTED,
    *,
    risk_level: str = "low",
    action_arg: str | int | None = None,
    target_arg: str | int | None = None,
) -> Callable:
    """Decorator that logs function calls to the forensic audit trail.

    Args:
        event_type: Type of audit event to record.
        risk_level: Default risk level ("low", "medium", "high", "critical").
        action_arg: Name (str) or positional index (int) of the parameter
                    to use as the ``action`` field.  Falls back to
                    ``<module>.<func>(...)``.
        target_arg: Name (str) or positional index (int) of the parameter
                    to use as the ``target`` field.

    Returns:
        Decorated function.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            action = _resolve_arg(func, args, kwargs, action_arg, func.__qualname__)
            target = _resolve_arg(func, args, kwargs, target_arg, "")
            start = time.monotonic()
            success = True
            error_detail: str | None = None

            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                success = False
                error_detail = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                duration_ms = round((time.monotonic() - start) * 1000, 1)
                details: dict[str, Any] = {"duration_ms": duration_ms}
                if error_detail:
                    details["error"] = error_detail

                _emit_event(
                    event_type=event_type,
                    action=str(action)[:500],  # cap length
                    target=str(target)[:200],
                    success=success,
                    risk_level=risk_level,
                    details=details,
                )

            return result

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            action = _resolve_arg(func, args, kwargs, action_arg, func.__qualname__)
            target = _resolve_arg(func, args, kwargs, target_arg, "")
            start = time.monotonic()
            success = True
            error_detail: str | None = None

            try:
                result = await func(*args, **kwargs)
            except Exception as exc:
                success = False
                error_detail = f"{type(exc).__name__}: {exc}"
                raise
            finally:
                duration_ms = round((time.monotonic() - start) * 1000, 1)
                details: dict[str, Any] = {"duration_ms": duration_ms}
                if error_detail:
                    details["error"] = error_detail

                _emit_event(
                    event_type=event_type,
                    action=str(action)[:500],
                    target=str(target)[:200],
                    success=success,
                    risk_level=risk_level,
                    details=details,
                )

            return result

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_arg(
    func: Callable,
    args: tuple,
    kwargs: dict,
    spec: str | int | None,
    fallback: str,
) -> str:
    """Extract a value from the call arguments based on ``spec``."""
    if spec is None:
        return fallback
    try:
        if isinstance(spec, int):
            return str(args[spec]) if spec < len(args) else fallback
        # spec is a string → try kwargs, then positional by name
        if spec in kwargs:
            return str(kwargs[spec])
        import inspect

        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())
        if spec in param_names:
            idx = param_names.index(spec)
            if idx < len(args):
                return str(args[idx])
    except (TypeError, ValueError):
        pass
    return fallback


def _emit_event(
    *,
    event_type: AuditEventType,
    action: str,
    target: str,
    success: bool,
    risk_level: str,
    details: dict[str, Any],
) -> None:
    """Emit an audit event, swallowing failures so decorated code never breaks."""
    try:
        event = AuditEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            user=os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            source_ip="127.0.0.1",
            target=target,
            action=action,
            details=details,
            success=success,
            risk_level=risk_level,
        )
        get_audit_logger().log(event)
    except Exception:
        # Audit must NEVER break production code
        logger.debug("Audit emit failed", exc_info=True)
