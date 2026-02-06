# Core module - DRAKBEN
# Backward compatibility re-exports - allows old imports to work
# New code should import from submodules directly

# Agent module
from core.agent.brain import DrakbenBrain
from core.agent.planner import Planner
from core.agent.refactored_agent import RefactoredDrakbenAgent
from core.agent.state import (
    AgentState,
    AttackPhase,
    ServiceInfo,
    VulnerabilityInfo,
    reset_state,
)

# Config (stays at root level)
from core.config import ConfigManager, SessionManager

# Execution module
from core.execution.execution_engine import (
    CommandSanitizer,
    ExecutionEngine,
    ExecutionResult,
    ExecutionStatus,
    SecurityError,
)
from core.execution.sandbox_manager import SandboxManager
from core.execution.tool_selector import ToolSelector

# Intelligence module
from core.intelligence.code_review import CodeReview, CodeReviewMiddleware
from core.intelligence.coder import AICoder, ASTSecurityChecker
from core.intelligence.evolution_memory import ActionRecord, EvolutionMemory, PlanRecord
from core.intelligence.self_refining_engine import (
    Policy,
    PolicyTier,
    SelfRefiningEngine,
    Strategy,
    StrategyProfile,
)
from core.intelligence.universal_adapter import UniversalAdapter, get_universal_adapter

# Security module
from core.security.ghost_protocol import GhostProtocol
from core.security.security_utils import AuditLogger, CredentialStore, ProxyManager

# Storage module
from core.storage.llm_cache import LLMCache

# Tools module
from core.tools.tool_parsers import (
    parse_nmap_output,
    parse_sqlmap_output,
)

# UI module
from core.ui.i18n import t
from core.ui.interactive_shell import InteractiveShell, start_interactive_shell
from core.ui.menu import DrakbenMenu

__all__ = [
    # Intelligence
    "AICoder",
    "ASTSecurityChecker",
    "ActionRecord",
    # Agent
    "AgentState",
    "AttackPhase",
    "AuditLogger",
    "CodeReview",
    "CodeReviewMiddleware",
    # Execution
    "CommandSanitizer",
    # Config
    "ConfigManager",
    "CredentialStore",
    "DrakbenBrain",
    # UI
    "DrakbenMenu",
    "EvolutionMemory",
    "ExecutionEngine",
    "ExecutionResult",
    "ExecutionStatus",
    # Security
    "GhostProtocol",
    "InteractiveShell",
    # Storage
    "LLMCache",
    "PlanRecord",
    "Planner",
    "Policy",
    "PolicyTier",
    "ProxyManager",
    "RefactoredDrakbenAgent",
    "SandboxManager",
    "SecurityError",
    "SelfRefiningEngine",
    "ServiceInfo",
    "SessionManager",
    "Strategy",
    "StrategyProfile",
    "ToolSelector",
    "UniversalAdapter",
    "VulnerabilityInfo",
    "get_universal_adapter",
    # Tools
    "parse_nmap_output",
    "parse_sqlmap_output",
    "reset_state",
    "start_interactive_shell",
    "t",
]
