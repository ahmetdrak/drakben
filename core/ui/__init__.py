# core/ui/__init__.py
"""UI module - menus, shells, prompts, and visualization."""

from core.ui.commands import COMMANDS, CommandInfo, get_command_list
from core.ui.i18n import t
from core.ui.menu import DrakbenMenu
from core.ui.prompt_utils import DrakbenProgress, EnhancedPrompt, StatusDisplay
from core.ui.unified_display import (
    ConfirmationRequest,
    LiveOperationDisplay,
    OperationType,
    ResultDisplay,
    RiskLevel,
    ScanDisplay,
    ThinkingDisplay,
    UnifiedConfirmation,
    create_confirmation,
    create_result_display,
    create_scan_display,
    create_thinking_display,
)
from core.ui.visualizer import NetworkVisualizer

__all__ = [
    "COMMANDS",
    "CommandInfo",
    "ConfirmationRequest",
    "DrakbenMenu",
    "DrakbenProgress",
    "EnhancedPrompt",
    "LiveOperationDisplay",
    "NetworkVisualizer",
    "OperationType",
    "ResultDisplay",
    "RiskLevel",
    "ScanDisplay",
    "StatusDisplay",
    "ThinkingDisplay",
    "UnifiedConfirmation",
    "create_confirmation",
    "create_result_display",
    "create_scan_display",
    "create_thinking_display",
    "get_command_list",
    "t",
]
