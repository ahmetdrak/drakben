# core/security/__init__.py
"""Security module - stealth, security utilities, and detection."""

from core.security.ghost_protocol import GhostProtocol
from core.security.kali_detector import KaliDetector
from core.security.security_utils import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    CredentialStore,
    ProxyConfig,
    ProxyManager,
)

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "CredentialStore",
    "GhostProtocol",
    "KaliDetector",
    "ProxyConfig",
    "ProxyManager",
]
