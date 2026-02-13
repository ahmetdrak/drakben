# core/brain.py
# DRAKBEN - AI Brain with 5 Core Modules
# Real LLM Integration + Unified LLM Engine
# Modules extracted to brain_*.py for maintainability.

import logging
from collections.abc import Generator
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

# Intelligence v2 imports (lazy-safe)
_ToolOutputAnalyzer: Any = None
_ContextCompressor: Any = None
_StructuredOutputParser: Any = None
try:
    from core.intelligence.context_compressor import ContextCompressor as _ContextCompressor
    from core.intelligence.structured_output import StructuredOutputParser as _StructuredOutputParser
    from core.intelligence.tool_output_analyzer import ToolOutputAnalyzer as _ToolOutputAnalyzer
except ImportError:
    pass

# Intelligence v3 imports (lazy-safe)
_FewShotEngine: Any = None
_CrossCorrelator: Any = None
_AdversarialAdapter: Any = None
_ExploitPredictor: Any = None
_CrossSessionKB: Any = None
_ModelRouter: Any = None
try:
    from core.intelligence.adversarial_adapter import AdversarialAdapter as _AdversarialAdapter
    from core.intelligence.cross_correlator import CrossCorrelator as _CrossCorrelator
    from core.intelligence.exploit_predictor import ExploitPredictor as _ExploitPredictor
    from core.intelligence.few_shot_engine import FewShotEngine as _FewShotEngine
    from core.intelligence.knowledge_base import CrossSessionKB as _CrossSessionKB
    from core.intelligence.model_router import ModelRouter as _ModelRouter
except ImportError:
    pass

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

# LLM Engine import (unified layer)
LLMEngine: Any = None
_ENGINE_AVAILABLE = False
try:
    from core.llm.llm_engine import LLMEngine as _LLMEngine

    LLMEngine = _LLMEngine
    _ENGINE_AVAILABLE = True
except ImportError:
    logger.debug("LLMEngine not available — using raw client only.")


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

    Enhanced with:
    - Streaming: ``stream_think()`` for token-by-token output
    - Function Calling: ``think_with_tools()`` for guaranteed schema
    - Multi-Turn: LLM sees its own previous responses
    - Token Counting: auto context window management
    - Output Validation: auto-retry on broken JSON
    - RAG: CVE/exploit enrichment from vector DB
    - Async: ``athink()`` for parallel operations
    """

    def __init__(self, llm_client=None, use_cognitive_memory: bool = True) -> None:
        # Auto-initialize LLM client if not provided
        self.llm_client = self._init_llm_client(llm_client)

        # ── Initialize Unified LLM Engine ──
        self.engine: Any = self._init_engine(self.llm_client)

        # Initialize Stanford-style Cognitive Memory System FIRST
        self.cognitive_memory: CognitiveMemoryManager | None = self._init_cognitive_memory(
            self.llm_client, use_cognitive_memory,
        )

        # Initialize modules (pass cognitive_memory to reasoning)
        self.orchestrator = MasterOrchestrator()
        self.reasoning = ContinuousReasoning(self.llm_client, self.cognitive_memory)
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

        # ── Intelligence v2 + v3 modules ──
        self._init_intelligence_modules(self.llm_client)

    @staticmethod
    def _init_llm_client(llm_client: Any) -> Any:
        """Auto-initialize LLM client if not provided."""
        if llm_client is not None or not LLM_AVAILABLE:
            return llm_client
        try:
            return OpenRouterClient()
        except (ValueError, ConnectionError, ImportError) as e:
            logger.debug("Could not initialize LLM client: %s", e)
            return None

    @staticmethod
    def _init_engine(llm_client: Any) -> Any:
        """Initialize unified LLM engine."""
        if not _ENGINE_AVAILABLE or llm_client is None:
            return None
        try:
            engine = LLMEngine(
                llm_client=llm_client,
                system_prompt="You are DRAKBEN, an elite AI pentesting assistant.",
                enable_rag=True,
                enable_validation=True,
                enable_token_management=True,
            )
            logger.info("LLM Engine initialized (streaming, tools, RAG, multi-turn)")
            return engine
        except Exception as e:
            logger.debug("Could not initialize LLM Engine: %s", e)
            return None

    @staticmethod
    def _init_cognitive_memory(
        llm_client: Any, use_cognitive_memory: bool,
    ) -> CognitiveMemoryManager | None:
        """Initialize Stanford-style cognitive memory system."""
        if not use_cognitive_memory:
            return None
        try:
            mem = CognitiveMemoryManager(llm_client=llm_client)
            logger.info("Cognitive Memory System initialized (Stanford-style)")
            return mem
        except Exception as e:
            logger.warning("Could not initialize Cognitive Memory: %s", e)
            return None

    @staticmethod
    def _safe_init(klass: Any, *args: Any, label: str = "", **kwargs: Any) -> Any:
        """Safely initialize an optional component, returning None on failure."""
        if klass is None:
            return None
        try:
            instance = klass(*args, **kwargs)
            logger.info("%s initialized", label or type(instance).__name__)
            return instance
        except Exception as e:
            logger.debug("Could not initialize %s: %s", label or klass, e)
            return None

    def _init_intelligence_modules(self, llm_client: Any) -> None:
        """Initialize all Intelligence v2 + v3 modules safely."""
        # v2 modules
        self.output_analyzer = self._safe_init(
            _ToolOutputAnalyzer, llm_client=llm_client, label="Tool Output Analyzer",
        )
        self.context_compressor = self._safe_init(
            _ContextCompressor, llm_client=llm_client, label="Context Compressor",
        )
        self.output_parser = self._safe_init(
            _StructuredOutputParser, llm_client=llm_client, label="Structured Output Parser",
        )
        # v3 modules
        self.few_shot = self._safe_init(_FewShotEngine, label="Few-Shot Engine")
        self.correlator = self._safe_init(_CrossCorrelator, label="Cross-Correlator")
        self.adversarial = self._safe_init(_AdversarialAdapter, label="Adversarial Adapter")
        self.exploit_predictor = self._safe_init(_ExploitPredictor, label="Exploit Predictor")
        self.knowledge_base = self._safe_init(_CrossSessionKB, label="Cross-Session KB")
        # Model Router needs special init
        self.model_router = self._init_model_router(llm_client)

    def _init_model_router(self, llm_client: Any) -> Any:
        """Initialize model router with auto-detection."""
        router = self._safe_init(_ModelRouter, label="Model Router")
        if router and llm_client:
            try:
                router.auto_detect_models(llm_client)
            except Exception as e:
                logger.debug("Model Router auto-detect failed: %s", e)
        return router

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
        """Direct chat with LLM (multi-turn aware).

        If LLMEngine is available, the LLM sees all previous messages
        in the conversation, enabling coherent multi-turn dialog.

        Args:
            message: User message

        Returns:
            AI response string

        """
        # Multi-turn via engine
        if self.engine:
            result = self.engine.query_with_history(message)
            if isinstance(result, str):
                self.engine.add_assistant_message(result)
                return result
            # Dict result (tool calls) — extract content
            content = result.get("content", "")
            if content:
                self.engine.add_assistant_message(content)
            return content or str(result)

        # Fallback: raw client
        if self.llm_client:
            return self.llm_client.query(message)
        return (
            "[Offline Mode] LLM bağlantısı yok. config/api.env dosyasını kontrol edin."
        )

    def stream_think(
        self,
        user_input: str,
        system_prompt: str | None = None,
    ) -> Generator[str, None, None]:
        """Stream AI response token-by-token.

        Instead of waiting 30s for a complete response, yields each token
        as it arrives. Use with ``rich.live`` or any streaming consumer.

        Args:
            user_input: User message.
            system_prompt: Optional system prompt override.

        Yields:
            Text chunks as they arrive from the LLM.

        Example::

            for chunk in brain.stream_think("Explain XSS"):
                print(chunk, end="", flush=True)

        """
        if self.engine:
            yield from self.engine.stream(user_input, system_prompt)
        elif self.llm_client and hasattr(self.llm_client, "stream"):
            yield from self.llm_client.stream(user_input, system_prompt)
        elif self.llm_client:
            yield self.llm_client.query(user_input, system_prompt)
        else:
            yield "[Offline Mode] LLM bağlantısı yok."

    def think_with_tools(
        self,
        user_input: str,
        tool_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """Think with function calling — LLM selects tools with guaranteed schema.

        Instead of hoping the LLM returns valid JSON tool selections,
        uses the native function calling protocol for guaranteed structure.

        Args:
            user_input: User message.
            tool_names: Specific tools to offer. None = all registered tools.

        Returns:
            Dict with ``content`` and ``tool_calls``::

                {
                    "content": "I'll scan the target...",
                    "tool_calls": [{
                        "function": {"name": "nmap", "arguments": "{\\"target\\": \\"10.0.0.1\\"}"}
                    }]
                }

        """
        if not self.engine:
            # Fallback to regular think
            result = self.think(user_input)
            return {"content": result.get("reply", ""), "tool_calls": []}

        try:
            schemas = self.engine.build_tool_schemas_from_registry(tool_names)
        except Exception:
            schemas = []

        if not schemas:
            result = self.think(user_input)
            return {"content": result.get("reply", ""), "tool_calls": []}

        return self.engine.call_with_tools(user_input, schemas)

    def process(self, user_input: str, system_context: dict) -> dict:
        """Main entry point - Process user request."""
        return self.orchestrator.process_request(user_input, system_context)

    def observe(self, tool: str, output: str, success: bool = True) -> None:
        """Observe tool output and update context.
        This allows the Brain to 'see' what happened in the terminal.

        Also feeds:
        - Multi-turn history (so LLM sees tool results in next query)
        - RAG pipeline (so tool output is searchable for future prompts)
        - Tool Output Analyzer (structured parsing for compact context)
        """
        logger.info("Brain observing tool %s (success=%s)", tool, success)

        analyzed = self._observe_analyze(tool, output, success)
        self._observe_engine_feed(tool, output, success, analyzed)
        self._observe_context_update(tool, output, success, analyzed)
        self._observe_cognitive_memory(tool, output, success)
        self._observe_cross_correlate(tool, output, analyzed)
        self._observe_adversarial(tool, output)
        self._observe_kb_learn(tool, output, success, analyzed)

    def _observe_analyze(self, tool: str, output: str, success: bool) -> Any:
        """Parse tool output into structured data via analyzer."""
        if not self.output_analyzer:
            return None
        try:
            analyzed = self.output_analyzer.analyze(tool, output, success=success)
            logger.debug(
                "Analyzed %s: %d ports, %d vulns, severity=%s",
                tool, len(analyzed.ports), len(analyzed.vulnerabilities), analyzed.severity,
            )
            return analyzed
        except Exception as e:
            logger.debug("Output analysis failed for %s: %s", tool, e)
            return None

    def _observe_engine_feed(
        self, tool: str, output: str, success: bool, analyzed: Any,
    ) -> None:
        """Feed observation into LLM engine history and RAG."""
        if not self.engine:
            return
        observation_text = output
        if analyzed:
            compact = analyzed.to_compact_str(max_chars=2000)
            if compact:
                observation_text = compact
        self.engine.add_tool_result(tool, observation_text, success=success)
        target = self.context_mgr.get("target") if self.context_mgr else ""
        self.engine.ingest_tool_output(tool, output, target=target or "")

    def _observe_context_update(
        self, tool: str, output: str, success: bool, analyzed: Any,
    ) -> None:
        """Update context manager with observation data."""
        if not self.context_mgr:
            return
        entry = {
            "type": "observation", "tool": tool,
            "output": output, "success": success, "timestamp": "recent",
        }
        self.context_mgr.context_history.append(entry)

        current_update: dict[str, Any] = {
            "last_tool": tool,
            "last_output": output[:10000],
            "last_success": success,
        }
        if analyzed:
            current_update["last_analysis"] = analyzed.to_dict()

        prev_tools = self.context_mgr.get("executed_tools", []) or []
        if tool not in prev_tools:
            prev_tools.append(tool)
            current_update["executed_tools"] = prev_tools

        self.context_mgr.update(current_update)

    def _observe_cognitive_memory(
        self, tool: str, output: str, success: bool,
    ) -> None:
        """Feed observation into cognitive memory system."""
        if not self.cognitive_memory:
            return
        target = self.context_mgr.get("target") if self.context_mgr else None
        self.cognitive_memory.perceive_tool_output(
            tool_name=tool, tool_output=output, target=target, success=success,
        )

    def _observe_cross_correlate(self, tool: str, output: str, analyzed: Any) -> None:
        """Feed observation into cross-correlator."""
        if not self.correlator:
            return
        try:
            target = self.context_mgr.get("target") if self.context_mgr else ""
            parsed_data = analyzed.to_dict() if analyzed else None
            self.correlator.ingest(
                tool, output, target=target or "unknown", parsed_data=parsed_data,
            )
        except Exception as e:
            logger.debug("Cross-correlation failed: %s", e)

    def _observe_adversarial(self, tool: str, output: str) -> None:
        """Feed observation into adversarial adapter."""
        if not self.adversarial:
            return
        try:
            detections = self.adversarial.analyze_output(tool, output)
            if detections:
                logger.info(
                    "Defense detected: %s",
                    ", ".join(d.defense_type.value for d in detections),
                )
        except Exception as e:
            logger.debug("Adversarial analysis failed: %s", e)

    def _observe_kb_learn(
        self, tool: str, _output: str, success: bool, analyzed: Any,
    ) -> None:
        """Feed observation into cross-session knowledge base."""
        if not self.knowledge_base:
            return
        try:
            target = self.context_mgr.get("target") if self.context_mgr else ""
            findings: list = []
            if analyzed and hasattr(analyzed, "vulnerabilities"):
                findings = analyzed.vulnerabilities[:5]
            self.knowledge_base.learn_from_scan(
                target=target or "unknown",
                tool_name=tool,
                success=success,
                findings=findings,
            )
        except Exception as e:
            logger.debug("KB learning failed: %s", e)

    def get_stats(self) -> dict:
        """Get brain statistics."""
        stats = {
            "reasoning_history": len(self.reasoning.reasoning_history),
            "corrections_made": len(self.self_correction.correction_history),
            "decisions_made": len(self.decision_engine.decision_history),
            "llm_available": self.llm_client is not None,
            "engine_available": self.engine is not None,
        }

        # Add engine stats (streaming, tools, RAG, etc.)
        if self.engine:
            stats["engine"] = self.engine.get_stats()

        # Add cognitive memory stats if available
        if self.cognitive_memory:
            stats["cognitive_memory"] = self.cognitive_memory.get_stats()  # type: ignore[assignment]

        # Intelligence v2 stats
        if self.output_analyzer:
            stats["output_analyzer"] = True
        if self.context_compressor:
            stats["context_compressor"] = self.context_compressor.get_stats()
        if self.output_parser:
            stats["structured_parser"] = self.output_parser.get_stats()

        # Intelligence v3 stats
        if self.few_shot:
            stats["few_shot"] = self.few_shot.get_stats()
        if self.correlator:
            stats["cross_correlator"] = self.correlator.get_stats()
        if self.adversarial:
            stats["adversarial"] = self.adversarial.get_stats()
        if self.exploit_predictor:
            stats["exploit_predictor"] = self.exploit_predictor.get_stats()
        if self.knowledge_base:
            stats["knowledge_base"] = self.knowledge_base.get_stats()
        if self.model_router:
            stats["model_router"] = self.model_router.get_stats()

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

        return self.coder.create_tool("dynamic_tool", instruction, context or "")  # type: ignore[arg-type]
