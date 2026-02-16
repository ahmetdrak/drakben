# Core module - DRAKBEN
# Lazy import pattern — eliminates circular import risks.
# Old `from core import X` still works via __getattr__.
# New code should import from submodules directly.

from __future__ import annotations

from typing import Any

# -- Module path constants (avoids duplicated string literals) --
_M_STATE = "core.agent.state"
_M_EXEC = "core.execution.execution_engine"
_M_EVOMEM = "core.intelligence.evolution_memory"
_M_SRE = "core.intelligence.self_refining_engine"
_M_SECUTIL = "core.security.security_utils"
_M_EVENTS = "core.events"
_M_OBS = "core.observability"
_M_STRUCTURED = "core.intelligence.structured_output"

# Map of symbol name → (module_path, symbol_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    # Agent module
    "DrakbenBrain": ("core.agent.brain", "DrakbenBrain"),
    "Planner": ("core.agent.planner", "Planner"),
    "RefactoredDrakbenAgent": ("core.agent.refactored_agent", "RefactoredDrakbenAgent"),
    "AgentState": (_M_STATE, "AgentState"),
    "AttackPhase": (_M_STATE, "AttackPhase"),
    "ServiceInfo": (_M_STATE, "ServiceInfo"),
    "VulnerabilityInfo": (_M_STATE, "VulnerabilityInfo"),
    "reset_state": (_M_STATE, "reset_state"),
    # Config (stays at root level)
    "ConfigManager": ("core.config", "ConfigManager"),
    "SessionManager": ("core.config", "SessionManager"),
    # Execution module
    "CommandSanitizer": (_M_EXEC, "CommandSanitizer"),
    "ExecutionEngine": (_M_EXEC, "ExecutionEngine"),
    "ExecutionResult": (_M_EXEC, "ExecutionResult"),
    "ExecutionStatus": (_M_EXEC, "ExecutionStatus"),
    "SecurityError": (_M_EXEC, "SecurityError"),
    "SandboxManager": ("core.execution.sandbox_manager", "SandboxManager"),
    "ToolSelector": ("core.execution.tool_selector", "ToolSelector"),
    # Intelligence module
    "AICoder": ("core.intelligence.coder", "AICoder"),
    "ASTSecurityChecker": ("core.intelligence.coder", "ASTSecurityChecker"),
    "ActionRecord": (_M_EVOMEM, "ActionRecord"),
    "EvolutionMemory": (_M_EVOMEM, "EvolutionMemory"),
    "PlanRecord": (_M_EVOMEM, "PlanRecord"),
    "Policy": (_M_SRE, "Policy"),
    "PolicyTier": (_M_SRE, "PolicyTier"),
    "SelfRefiningEngine": (_M_SRE, "SelfRefiningEngine"),
    "Strategy": (_M_SRE, "Strategy"),
    "StrategyProfile": (_M_SRE, "StrategyProfile"),
    "UniversalAdapter": ("core.intelligence.universal_adapter", "UniversalAdapter"),
    "get_universal_adapter": ("core.intelligence.universal_adapter", "get_universal_adapter"),
    # Intelligence v2 — ReAct, Structured Output, Analysis, Compression, Reflection
    "ReActLoop": ("core.intelligence.react_loop", "ReActLoop"),
    "StructuredOutputParser": (_M_STRUCTURED, "StructuredOutputParser"),
    "PentestAction": (_M_STRUCTURED, "PentestAction"),
    "ToolAnalysis": (_M_STRUCTURED, "ToolAnalysis"),
    "PromptTemplates": (_M_STRUCTURED, "PromptTemplates"),
    "ToolOutputAnalyzer": ("core.intelligence.tool_output_analyzer", "ToolOutputAnalyzer"),
    "AnalyzedOutput": ("core.intelligence.tool_output_analyzer", "AnalyzedOutput"),
    "ContextCompressor": ("core.intelligence.context_compressor", "ContextCompressor"),
    "SelfReflectionEngine": ("core.intelligence.self_reflection", "SelfReflectionEngine"),
    # Intelligence v3 — Few-Shot, Cross-Correlation, Adversarial, Prediction, KB, Router
    "FewShotEngine": ("core.intelligence.few_shot_engine", "FewShotEngine"),
    "CrossCorrelator": ("core.intelligence.cross_correlator", "CrossCorrelator"),
    "TargetProfile": ("core.intelligence.cross_correlator", "TargetProfile"),
    "AdversarialAdapter": ("core.intelligence.adversarial_adapter", "AdversarialAdapter"),
    "ExploitPredictor": ("core.intelligence.exploit_predictor", "ExploitPredictor"),
    "CrossSessionKB": ("core.intelligence.knowledge_base", "CrossSessionKB"),
    "ModelRouter": ("core.intelligence.model_router", "ModelRouter"),
    # Security module
    "GhostProtocol": ("core.security.ghost_protocol", "GhostProtocol"),
    "AuditLogger": (_M_SECUTIL, "AuditLogger"),
    "CredentialStore": (_M_SECUTIL, "CredentialStore"),
    "ProxyManager": (_M_SECUTIL, "ProxyManager"),
    # Storage module
    "LLMCache": ("core.storage.llm_cache", "LLMCache"),
    # Tools module
    "parse_nmap_output": ("core.tools.tool_parsers", "parse_nmap_output"),
    "parse_sqlmap_output": ("core.tools.tool_parsers", "parse_sqlmap_output"),
    # UI module
    "t": ("core.ui.i18n", "t"),
    "InteractiveShell": ("core.ui.interactive_shell", "InteractiveShell"),
    "start_interactive_shell": ("core.ui.interactive_shell", "start_interactive_shell"),
    "DrakbenMenu": ("core.ui.menu", "DrakbenMenu"),
    # New modules
    "EventBus": (_M_EVENTS, "EventBus"),
    "EventType": (_M_EVENTS, "EventType"),
    "get_event_bus": (_M_EVENTS, "get_event_bus"),
    "KnowledgeGraph": ("core.knowledge_graph", "KnowledgeGraph"),
    "get_knowledge_graph": ("core.knowledge_graph", "get_knowledge_graph"),
    "Tracer": (_M_OBS, "Tracer"),
    "MetricsCollector": (_M_OBS, "MetricsCollector"),
    "get_tracer": (_M_OBS, "get_tracer"),
    "get_metrics": (_M_OBS, "get_metrics"),
    "ContextKey": ("core.agent.brain_context", "ContextKey"),
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str) -> Any:
    """Lazy import — only loads the module when the symbol is first accessed."""
    if name in _LAZY_IMPORTS:
        module_path, symbol = _LAZY_IMPORTS[name]
        import importlib

        mod = importlib.import_module(module_path)
        value = getattr(mod, symbol)
        # Cache on the module so __getattr__ is not called again
        globals()[name] = value
        return value
    msg = f"module 'core' has no attribute {name!r}"
    raise AttributeError(msg)
