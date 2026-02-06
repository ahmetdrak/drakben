# core/brain.py
# DRAKBEN - AI Brain with 5 Core Modules
# Real LLM Integration
# Modules extracted to brain_*.py for maintainability.

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from core.agent.brain_cognitive_memory import CognitiveMemoryManager
from core.agent.brain_context import ContextManager
from core.agent.brain_decision import DecisionEngine
from core.agent.brain_orchestrator import MasterOrchestrator
from core.agent.brain_reasoning import (
    MODEL_TIMEOUTS,  # noqa: F401 (re-exported)
    ContinuousReasoning,
    get_model_timeout,  # noqa: F401 (re-exported)
)
from core.agent.brain_self_correction import SelfCorrection
from core.intelligence.coder import AICoder

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)

# Error message constants (SonarCloud: avoid duplicate literals)
_ERR_ORCHESTRATOR_NOT_INIT = "Orchestrator modules are not initialized"
_ERR_CONTEXT_NOT_INIT = "Context manager is not initialized"


# LLM Client import
OpenRouterClient: Any = None  # Type placeholder
LLM_AVAILABLE = False
try:
    from llm.openrouter_client import OpenRouterClient as _OpenRouterClient

    OpenRouterClient = _OpenRouterClient
    LLM_AVAILABLE = True
    logger.debug("LLM client loaded successfully")
except ImportError:
    logger.warning("LLM client not available, running in offline mode")


@dataclass
class ExecutionContext:
    """Execution context for tracking state."""

    target: str | None = None
    language: str = "tr"
    system_info: dict[str, Any] = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)
    current_step: int = 0
    total_steps: int = 0
    errors_encountered: list[dict] = field(default_factory=list)


# Brain Facade - Main interface
class DrakbenBrain:
    """Ana beyin interface - 5 modülü koordine eder
    Gerçek LLM entegrasyonu ile.
    """

    def __init__(self, llm_client=None, use_cognitive_memory: bool = True) -> None:
        # Auto-initialize LLM client if not provided
        if llm_client is None and LLM_AVAILABLE:
            try:
                llm_client = OpenRouterClient()
            except (ValueError, ConnectionError, ImportError) as e:
                logger.debug("Could not initialize LLM client: %s", e)
                llm_client = None

        self.llm_client = llm_client

        # Initialize Stanford-style Cognitive Memory System FIRST
        self.cognitive_memory: CognitiveMemoryManager | None = None
        if use_cognitive_memory:
            try:
                self.cognitive_memory = CognitiveMemoryManager(llm_client=llm_client)
                logger.info("Cognitive Memory System initialized (Stanford-style)")
            except Exception as e:
                logger.warning("Could not initialize Cognitive Memory: %s", e)
                self.cognitive_memory = None

        # Initialize modules (pass cognitive_memory to reasoning)
        self.orchestrator = MasterOrchestrator()
        self.reasoning = ContinuousReasoning(llm_client, self.cognitive_memory)
        self.context_mgr = ContextManager()
        self.self_correction = SelfCorrection()
        self.decision_engine = DecisionEngine()

        # Connect modules
        self.orchestrator.initialize(
            self.reasoning,
            self.context_mgr,
            self.self_correction,
            self.decision_engine,
        )

    def think(
        self,
        user_input: str,
        target: str | None = None,
        language: str = "en",
    ) -> dict:
        """AI-powered thinking - Ana giriş noktası.

        Args:
            user_input: Kullanıcı komutu/sorusu
            target: Hedef IP/domain (opsiyonel)
            language: Kullanıcı dili (tr/en)

        Returns:
            {
                "intent": str,
                "reply": str,
                "command": str (optional),
                "steps": list,
                "needs_approval": bool,
                "llm_response": str (the actual response to show user)
            }

        """
        # Build context
        system_context = {
            "target": target,
            "language": language,
            "llm_available": self.llm_client is not None,
        }

        # Process through orchestrator
        result = self.process(user_input, system_context)

        # Check for errors
        if result.get("error"):
            return {
                "intent": "error",
                "reply": "",
                "error": result.get("error"),
                "command": None,
                "steps": [],
                "needs_approval": False,
                "confidence": 0,
                "risks": [],
                "llm_response": None,
            }

        # Get the actual response to show user
        # Priority: response > llm_response
        actual_response = result.get("response") or result.get("llm_response")

        # If it's a chat, we don't necessarily want to show reasoning as the main reply
        # but if we have no response, we fallback to reasoning
        if not actual_response:
            actual_response = result.get("reasoning", "")

        # Format response
        return {
            "intent": result.get("action", "chat"),
            "reply": actual_response,
            "command": result.get("command"),
            "steps": result.get("steps", []),
            "needs_approval": result.get("needs_approval", False),
            "confidence": result.get("confidence", 0.5),
            "risks": result.get("risks", []),
            "llm_response": actual_response,
        }

    def chat(self, message: str) -> str:
        """Direct chat with LLM.

        Args:
            message: User message

        Returns:
            AI response string

        """
        if self.llm_client:
            return self.llm_client.query(message)
        return (
            "[Offline Mode] LLM bağlantısı yok. config/api.env dosyasını kontrol edin."
        )

    def process(self, user_input: str, system_context: dict) -> dict:
        """Main entry point - Process user request."""
        return self.orchestrator.process_request(user_input, system_context)

    def get_context(self) -> dict:
        """Get current context."""
        return self.context_mgr.get_full_context()

    def update_context(self, context_update: dict) -> None:
        """Update brain context."""
        self.context_mgr.update(context_update)

    def observe(self, tool: str, output: str, success: bool = True) -> None:
        """Observe tool output and update context.
        This allows the Brain to 'see' what happened in the terminal.
        """
        logger.info("Brain observing tool %s (success=%s)", tool, success)

        # Create a history entry (for specialized history if needed)
        entry = {
            "type": "observation",
            "tool": tool,
            "output": output,
            "success": success,
            "timestamp": "recent",
        }

        # Update context manager
        if self.context_mgr:
            # We add it to context history
            self.context_mgr.context_history.append(entry)

            # Update current context with latest tool info
            current_update = {
                "last_tool": tool,
                # Store truncated output in current context to avoid bloating every prompt
                # But keep it somewhat long for immediate next turn
                "last_output": output[:10000],
                "last_success": success,
            }

            # Executed tools list
            prev_tools = self.context_mgr.get("executed_tools", []) or []
            if tool not in prev_tools:
                prev_tools.append(tool)
                current_update["executed_tools"] = prev_tools

            self.context_mgr.update(current_update)

        # Cognitive Memory: Perceive tool output (Stanford-style)
        if self.cognitive_memory:
            target = self.context_mgr.get("target") if self.context_mgr else None
            self.cognitive_memory.perceive_tool_output(
                tool_name=tool,
                tool_output=output,
                target=target,
                success=success,
            )

    def get_cognitive_context(
        self,
        query: str,
        target: str | None = None,
    ) -> str:
        """Get token-efficient context from Cognitive Memory.

        This is the KEY FUNCTION for token efficiency.
        Instead of passing entire history, we retrieve relevant memories.

        Args:
            query: Current query/focal point
            target: Target IP/domain

        Returns:
            Formatted context string for LLM
        """
        if not self.cognitive_memory:
            return ""

        return self.cognitive_memory.get_context_for_llm(
            query=query,
            target=target,
        )

    def get_stats(self) -> dict:
        """Get brain statistics."""
        stats = {
            "reasoning_history": len(self.reasoning.reasoning_history),
            "corrections_made": len(self.self_correction.correction_history),
            "decisions_made": len(self.decision_engine.decision_history),
            "llm_available": self.llm_client is not None,
        }

        # Add cognitive memory stats if available
        if self.cognitive_memory:
            stats["cognitive_memory"] = self.cognitive_memory.get_stats()

        return stats

    def test_llm(self) -> dict:
        """Test LLM connection."""
        if not self.llm_client:
            return {"connected": False, "error": "No LLM client configured"}

        try:
            # Add timeout to prevent hanging
            response = self.llm_client.query("Merhaba, çalışıyor musun?", timeout=15)
            is_error = response.startswith("[") and any(
                x in response for x in ["Error", "Offline", "Timeout"]
            )
            return {
                "connected": not is_error,
                "provider": self.llm_client.get_provider_info(),
                "response": response[:200],
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}

    def select_next_tool(self, context: dict) -> dict | None:
        """REFACTORED: Get SINGLE tool selection from LLM.

        Args:
            context: {
                "state_snapshot": Dict,  # 5 line summary
                "allowed_tools": List[str],
                "remaining_surfaces": List[str],
                "last_observation": str,
                "phase": str
            }

        Returns:
            {"tool": "tool_name", "args": {...}} or None

        """
        if not self.llm_client:
            # Fallback - return first allowed tool with simple args
            allowed = context.get("allowed_tools", [])
            if allowed:
                return {
                    "tool": allowed[0],
                    "args": {"target": context.get("state_snapshot", {}).get("target")},
                }
            return None

        # Get language from context
        user_lang = context.get("state_snapshot", {}).get("language", "tr")
        lang_instruction: str = (
            "Respond in Turkish (Türkçe)."
            if user_lang == "tr"
            else "Respond in English."
        )

        # Build minimal prompt for LLM
        prompt: str = f"""You are DRAKBEN penetration testing agent. {lang_instruction}
Current state:
- Phase: {context.get("phase")}
- Iteration: {context.get("state_snapshot", {}).get("iteration")}
- Open services: {context.get("state_snapshot", {}).get("open_services_count")}
- Remaining to test: {context.get("state_snapshot", {}).get("remaining_count")}
- Last observation: {context.get("last_observation", "None")[:100]}

Allowed tools: {", ".join(context.get("allowed_tools", [])[:5])}
Remaining surfaces: {", ".join(context.get("remaining_surfaces", [])[:3])}

Select ONE tool to execute next. Respond ONLY in JSON format:
{{"tool": "tool_name", "args": {{"param": "value"}}}}"""

        try:
            # Add timeout to prevent hanging on API calls
            response = self.llm_client.query(
                prompt,
                system_prompt="You are a penetration testing AI. Respond only in JSON.",
                timeout=20,
            )

            # Parse JSON using reasoning module's parser
            parsed: dict[str, Any] | None = self.reasoning._parse_llm_response(response)
            if parsed and "tool" in parsed:
                return parsed

            # Fallback to rule-based
            return None

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.debug("Tool response parsing failed: %s", e)
            return None

    def ask_coder(self, instruction: str, context: dict | None = None) -> dict:
        """Delegate coding task to AICoder.

        Args:
            instruction: What to code
            context: Additional context

        Returns:
            Result dict from AICoder

        """
        # Since AICoder is stateful, we might need a persistent instance in Brain
        # checking if we have one, if not create
        if not hasattr(self, "coder"):
            self.coder: AICoder = AICoder(self)

        return self.coder.create_tool("dynamic_tool", instruction, context or "")
