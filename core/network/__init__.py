# core/network/__init__.py
"""Network module - distributed state, daemon, and web research."""

from core.network.daemon_service import DaemonService
from core.network.distributed_state import DistributedStateManager as DistributedState
from core.network.web_researcher import WebResearcher

__all__ = [
    "DaemonService",
    "DistributedState",
    "WebResearcher",
]
