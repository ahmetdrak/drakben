# core/plugins/__init__.py
# DRAKBEN Plugin System

from .base import PluginBase, PluginResult, PluginKind
from .registry import PluginRegistry

__all__ = ["PluginBase", "PluginResult", "PluginKind", "PluginRegistry"]
