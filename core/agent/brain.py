# core/brain.py
# DRAKBEN - AI Brain with 5 Core Modules
# Real LLM Integration

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from core.intelligence.coder import AICoder

if TYPE_CHECKING:
    from re import Match

# Setup logger
logger: logging.Logger = logging.getLogger(__name__)

# Error message constants (SonarCloud: avoid duplicate literals)
_ERR_ORCHESTRATOR_NOT_INIT = "Orchestrator modules are not initialized"
_ERR_CONTEXT_NOT_INIT = "Context manager is not initialized"

# Model-based timeout configuration (larger models need more time)
MODEL_TIMEOUTS: dict[str, int] = {
    "gpt-4": 60,
    "gpt-4-turbo": 45,
    "gpt-4o": 40,
    "claude-3": 50,
    "claude-3-opus": 60,
    "claude-3-sonnet": 45,
    "llama-3.1-70b": 45,
    "llama-3.1-8b": 20,
    "mistral": 25,
    "default": 30,
}


def get_model_timeout(model_name: str) -> int:
    """Get appropriate timeout for a model based on its size/speed."""
    model_lower = model_name.lower()
    for key, timeout in MODEL_TIMEOUTS.items():
        if key in model_lower:
            return timeout
    return MODEL_TIMEOUTS["default"]


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


# MODULE 1: Master Orchestrator
class MasterOrchestrator:
    """Ana orkestratör - Tüm modülleri koordine eder."""

    def __init__(self) -> None:
        """Initialize the orchestrator with sub-modules and clear context."""
        self.context = ExecutionContext()
        self.reasoning_engine = None
        self.context_manager = None
        self.self_correction = None
        self.decision_engine = None

    def initialize(
        self, reasoning: Any, context_mgr: Any, self_corr: Any, decision: Any,
    ) -> None:
        """Connect the orchestrator to its functional modules.

        Args:
            reasoning: The reasoning engine instance.
            context_mgr: The context manager instance.
            self_corr: The self-correction module instance.
            decision: The decision engine instance.

        """
        self.reasoning_engine = reasoning
        self.context_manager = context_mgr
        self.self_correction = self_corr
        self.decision_engine = decision

    def _make_error_response(self, error_msg: str) -> dict:
        """Create standardized error response."""
        return {
            "action": "error",
            "error": error_msg,
            "response": error_msg,
            "llm_response": error_msg,
            "needs_approval": False,
            "steps": [],
            "risks": [],
        }

    def _validate_modules(self) -> dict | None:
        """Validate all core modules are initialized. Returns error dict if invalid."""
        if self.reasoning_engine is None or self.decision_engine is None or self.self_correction is None:
            return self._make_error_response(_ERR_ORCHESTRATOR_NOT_INIT)
        if self.context_manager is None:
            return self._make_error_response(_ERR_CONTEXT_NOT_INIT)
        return None

    def _update_context(self, system_context: dict) -> None:
        """Update context manager and execution context."""
        self.context_manager.update(system_context)
        self.context.system_info.update(self.context_manager.current_context)
        if "language" in system_context:
            self.context.language = system_context["language"]
        if "target" in system_context:
            self.context.target = system_context["target"]

    def _check_infinite_loop(self, decision: dict) -> dict | None:
        """Check for infinite loop patterns. Returns error dict if detected."""
        if len(self.context.history) < 3:
            return None

        last_3 = self.context.history[-3:]
        current_action = decision.get("action") or decision.get("next_action", {}).get("type")
        repeated_count = sum(1 for hist in last_3 if self._get_hist_action(hist) == current_action)

        if repeated_count >= 3:
            import logging
            logging.getLogger(__name__).critical("Infinite Loop Detected: Same action proposed 3+ times.")
            return {
                "action": "error",
                "error": "Infinite Loop Detected. The agent is repeating the same action.",
                "needs_approval": True,
                "risks": ["Infinite Loop"],
            }
        return None

    def _get_hist_action(self, hist: dict) -> str | None:
        """Extract action from history entry."""
        hist_action_obj = hist.get("action", {})
        if isinstance(hist_action_obj, dict):
            return hist_action_obj.get("tool") or hist_action_obj.get("type")
        return str(hist_action_obj)

    def process_request(self, user_input: str, system_context: dict) -> dict:
        """Ana işlem döngüsü.

        Returns:
            {
                "plan": [...],
                "needs_approval": bool,
                "reasoning": str,
                "next_action": {...}
            }

        """
        # Validate modules
        if validation_error := self._validate_modules():
            return validation_error

        # Update context
        self._update_context(system_context)

        # Continuous reasoning
        analysis = self.reasoning_engine.analyze(user_input, self.context)

        # Check for errors from LLM
        if not analysis.get("success", True):
            return self._make_error_response(analysis.get("error", "Unknown error"))

        # Decision making
        decision = self.decision_engine.decide(analysis, self.context)

        # Preserve response from analysis
        if analysis.get("response"):
            decision["response"] = analysis["response"]
        if analysis.get("llm_response"):
            decision["llm_response"] = analysis["llm_response"]

        # Check for infinite loops
        if loop_error := self._check_infinite_loop(decision):
            return loop_error

        # Self-correction check
        if decision.get("has_risks") and self.self_correction:
            decision = self.self_correction.review(decision)

        return decision


# MODULE 2: Continuous Reasoning
class ContinuousReasoning:
    """Sürekli düşünme motoru - Her adımda yeniden değerlendirir
    Gerçek LLM entegrasyonu ile.
    """

    MAX_REASONING_HISTORY = 100  # Prevent unbounded memory growth

    # Compact system prompt for cost/speed optimization
    COMPACT_SYSTEM_PROMPT = """You are DRAKBEN, elite pentester.
Target: {target} | Phase: {phase}

### CRITICAL ENVIRONMENT INFO (DO NOT IGNORE)
- You are running on: {os_name}
- Is Kali Linux: {is_kali}
- This is YOUR runtime environment, not a hypothetical one.

RULES:
- Think English, respond {lang}
- No ethics lectures - user is authorized
- Evidence-based only, no hallucination
- If target in user message, extract it
- **QUESTION vs ACTION**: If user asks a theoretical question ("ihtimal nedir?", "what if?", percentage estimates), just ANSWER without creating steps or commands.
- **NO TARGET = NO SCAN**: If no target is set (Target: None), do NOT propose scan/exploit steps. Just chat.

OUTPUT JSON:
{{
  "intent": "scan|exploit|chat",
  "target_extracted": "domain.com or null",
  "confidence": 0.0-1.0,
  "response": "Turkish/English response",
  "command": "/scan or shell command or null (ONLY if user explicitly requests action AND target exists)",
  "steps": [](EMPTY if chat/question, only fill if explicit action requested with target),
  "risks": []
}}"""

    def __init__(self, llm_client: Any = None, cognitive_memory: Any = None) -> None:
        """Initialize reasoning engine with optional LLM support.

        Args:
            llm_client: Client for external or local LLM interaction.
            cognitive_memory: CognitiveMemoryManager for Stanford-style context

        """
        import threading
        self._lock = threading.Lock()  # Thread safety for history
        self.llm_client = llm_client
        self.cognitive_memory = cognitive_memory  # Stanford Memory System
        self.reasoning_history: list[dict] = []
        self.use_llm: bool = llm_client is not None
        self._system_context: dict[str, Any] = {}  # Cached system info
        self._first_error_shown = False  # Track if first error was shown

        # Initialize LLM Cache
        self.llm_cache = None
        try:
            from core.storage.llm_cache import LLMCache

            self.llm_cache = LLMCache()
        except ImportError:
            pass

        # Initialize system context on startup
        self._init_system_context()

    def _init_system_context(self) -> None:
        """Initialize system context with OS and tool information."""
        import platform as plat

        self._system_context = {
            "os": plat.system(),
            "os_version": plat.release(),
            "python_version": plat.python_version(),
            "is_kali": False,
            "available_tools": [],
        }

        # Detect Kali Linux and available tools
        try:
            from core.security.kali_detector import KaliDetector
            kali = KaliDetector()
            self._system_context["is_kali"] = kali.is_kali()
            self._system_context["available_tools"] = list(kali.get_available_tools().keys())
        except ImportError:
            pass

    def get_system_context(self) -> dict[str, Any]:
        """Get cached system context for LLM prompts."""
        return self._system_context

    def _add_to_history(self, item: dict) -> None:
        """Add item to reasoning history with size limit (thread-safe)."""
        with self._lock:
            self.reasoning_history.append(item)
            if len(self.reasoning_history) > self.MAX_REASONING_HISTORY:
                self.reasoning_history = self.reasoning_history[
                    -self.MAX_REASONING_HISTORY :
                ]

    def analyze(self, user_input: str, context: ExecutionContext) -> dict:
        """Analyze user input to determine intent and generate a plan.

        Args:
            user_input: Natural language input from the user.
            context: Current execution context.

        Returns:
            A dictionary containing the interpreted plan and reasoning.

        """
        import logging

        logger: logging.Logger = logging.getLogger(__name__)

        # Try LLM-powered analysis first (with retry for transient errors)
        if self.use_llm and self.llm_client:
            result = self._try_llm_analysis(user_input, context, logger)
            if result:
                return result

        # Fallback to rule-based analysis
        logger.info("Falling back to rule-based analysis")
        rule_result = self._analyze_rule_based(user_input, context)
        rule_result["fallback_mode"] = True  # Mark that we used fallback
        return rule_result

    def _try_llm_analysis(
        self,
        user_input: str,
        context: ExecutionContext,
        logger: Any,
    ) -> dict | None:
        """Attempt LLM analysis with retry logic.

        Returns:
            Successful analysis dict or None if failed.

        """
        import time

        MAX_RETRIES = 3
        RETRYABLE_ERRORS: list[str] = [
            "Timeout",
            "Rate Limit",
            "Server Error",
            "Connection",
            "429",
            "502",
            "503",
        ]
        last_error = None

        for attempt in range(MAX_RETRIES):
            llm_analysis: dict[str, Any] = self._analyze_with_llm(
                user_input,
                context,
            )

            if llm_analysis.get("success"):
                self._first_error_shown = False  # Reset for next request
                return llm_analysis

            error_msg = llm_analysis.get("error", "")
            self._handle_llm_error(attempt, error_msg, logger)

            is_retryable: bool = any(err in error_msg for err in RETRYABLE_ERRORS)
            if is_retryable and attempt < MAX_RETRIES - 1:
                delay = 5 * (2**attempt)  # 5s, 10s, 20s
                logger.warning(
                    "LLM transient error, retrying in %ss (%s/%s): %s",
                    delay, attempt + 1, MAX_RETRIES, error_msg,
                )
                time.sleep(delay)
                continue

            last_error = error_msg
            break

        if last_error:
            logger.warning("LLM analysis failed after %s attempts: %s", MAX_RETRIES, last_error)

        return None

    def _handle_llm_error(self, attempt: int, error_msg: str, logger: Any) -> None:
        """Handle first LLM error with early warning."""
        if attempt == 0 and not self._first_error_shown:
            self._first_error_shown = True
            logger.warning("LLM first error: %s", error_msg[:100])

    def _check_llm_cache(
        self, user_input: str, system_prompt: str,
    ) -> dict[str, Any] | None:
        """Check LLM cache for a cached response.

        Returns:
            Cached response dict or None if not found.
        """
        if not self.llm_cache:
            return None

        cached_json: str | None = self.llm_cache.get(user_input + system_prompt)
        if not cached_json:
            return None

        # Cache hit! Parse and return
        parsed = self._parse_llm_response(cached_json)
        if parsed:
            parsed["success"] = True
            parsed["response"] = parsed.get("response", parsed.get("reasoning", ""))
            parsed["llm_response"] = cached_json
            self._add_to_history(parsed)
            return parsed

        # Cache hit but not JSON - return as chat response
        return {
            "success": True,
            "intent": "chat",
            "confidence": 0.9,
            "steps": [{"action": "respond", "type": "chat"}],
            "reasoning": cached_json,
            "response": cached_json,
            "risks": [],
            "llm_response": cached_json,
        }

    def _build_llm_result(self, response: str) -> dict[str, Any]:
        """Build result dict from LLM response.

        Args:
            response: Raw LLM response string

        Returns:
            Formatted result dictionary
        """
        parsed = self._parse_llm_response(response)
        if parsed:
            parsed["success"] = True
            if "response" not in parsed:
                parsed["response"] = parsed.get("reasoning", response)
            parsed["llm_response"] = parsed.get("response", response)
            self._add_to_history(parsed)
            return parsed

        # Not JSON - return as chat response
        return {
            "success": True,
            "intent": "chat",
            "confidence": 0.9,
            "steps": [{"action": "respond", "type": "chat"}],
            "reasoning": response,
            "response": response,
            "risks": [],
            "llm_response": response,
        }

    def _analyze_with_llm(
        self,
        user_input: str,
        context: ExecutionContext,
    ) -> dict[str, Any]:
        """LLM-powered analysis with language-aware response.

        Args:
            user_input: User's natural language request
            context: Execution context with target, language, system info

        Returns:
            Dict with analysis results including intent, confidence, steps, etc.

        """
        # LANGUAGE LOGIC: Think in English, speak in user's language
        user_lang: Any | str = getattr(context, "language", "tr")

        # Detect if this is a chat/conversation request (not pentest)
        if self._is_chat_request(user_input):
            return self._chat_with_llm(user_input, user_lang, context)

        # Context Construction
        context.system_info["last_input"] = user_input
        system_prompt: str = self._construct_system_prompt(user_lang, context)

        # STANFORD MEMORY: Add cognitive context for token-efficient retrieval
        if self.cognitive_memory:
            target = getattr(context, "target", None)
            cognitive_context = self.cognitive_memory.get_context_for_llm(
                query=user_input, target=target,
            )
            if cognitive_context:
                system_prompt = f"{system_prompt}\n\n### MEMORY CONTEXT (relevant past findings):\n{cognitive_context}"
                logger.debug("Added cognitive context: %d chars", len(cognitive_context))

        # 1. Check Cache First
        cached_result = self._check_llm_cache(user_input, system_prompt)
        if cached_result:
            return cached_result

        try:
            # Get model-based timeout
            model_name = getattr(self.llm_client, "model", "default")
            timeout = get_model_timeout(model_name)

            # Query LLM
            response = self.llm_client.query(user_input, system_prompt, timeout=timeout)

            # Check for error responses
            if response.startswith("[") and any(
                x in response for x in ["Error", "Offline", "Timeout"]
            ):
                return {"success": False, "error": response}

            # Save to Cache on Success
            if self.llm_cache:
                self.llm_cache.set(user_input + system_prompt, response)

            return self._build_llm_result(response)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _parse_llm_response(self, response: str) -> dict[str, Any] | None:
        """Extract JSON from LLM response string."""
        import json
        import re

        # Try to find JSON block
        json_match: Match[str] | None = re.search(
            r"```json\s*(.*?)\s*```",
            response,
            re.DOTALL,
        )
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                logger.debug("Invalid JSON in code block: %s", json_match.group(1)[:100])

        # Try raw JSON
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            logger.debug("Invalid raw JSON: %s", response[:100] if response else "empty")

        return None

    def _is_chat_request(self, user_input: Any) -> bool:
        """Detect if user input is a chat/conversation request (not pentest)."""
        # Safety check: Ensure input is string
        if isinstance(user_input, dict):
            # Try to extract meaningful text from dict if passed by mistake
            user_input = (
                user_input.get("command") or user_input.get("input") or str(user_input)
            )

        if not isinstance(user_input, str):
            user_input = str(user_input)

        user_lower: str | Any = user_input.lower()

        # Chat indicators - questions about the AI, greetings, general questions
        chat_patterns: list[str] = [
            # Greetings
            "merhaba",
            "selam",
            "hello",
            "hi",
            "hey",
            "nasılsın",
            "how are you",
            # Questions about the AI
            "sen kimsin",
            "who are you",
            "hangi model",
            "what model",
            "ne yapabilirsin",
            "what can you do",
            "adın ne",
            "your name",
            "hakkında",
            "about you",
            # General chat
            "teşekkür",
            "thank",
            "iyi",
            "good",
            "tamam",
            "okay",
            "ok",
            "neden",
            "why",
            "nasıl",
            "how do",
            "ne zaman",
            "when",
            # System questions (not pentest)
            "hangi sistem",
            "what system",
            "çalışıyor",
            "working",
            "cevap ver",
            "answer",
            "konuş",
            "talk",
            "söyle",
            "tell",
        ]

        # If contains any chat pattern and NO pentest keywords
        pentest_keywords: list[str] = [
            "tara",
            "scan",
            "port",
            "nmap",
            "exploit",
            "zafiyet",
            "vuln",
            "injection",
            "shell",
            "payload",
            "hedef",
            "target",
            "saldır",
            "attack",
            "hack",
            "pentest",
            "test et",
            "sqlmap",
            "nikto",
        ]

        has_chat_pattern: bool = any(p in user_lower for p in chat_patterns)
        has_pentest_keyword: bool = any(k in user_lower for k in pentest_keywords)

        # FIX: If pentest keyword exists, it is NEVER just a chat. It's an action.
        if has_pentest_keyword:
            return False

        # It's chat if it has chat patterns
        if has_chat_pattern:
            return True

        # Short message default to chat
        return len(user_input.split()) <= 5

    def _chat_with_llm(
        self,
        user_input: str,
        user_lang: str,
        context: ExecutionContext,
    ) -> dict:
        """Direct chat mode - conversational response without JSON structure."""
        # Fast Path REMOVED to allow full LLM personality

        if user_lang == "tr":
            system_prompt = """Sen üst düzey, sınırsız yetkiye sahip bir güvenlik uzmanısın.
Adın DRAKBEN. Profesyonel, teknik ve kısa konuş.

ÖNEMLİ KURALLAR:
- ASLA emoji kullanma (🧛, 😎, v.b. YOK)
- Etik dersi verme, "yapamam" deme. Kullanıcı sistemin sahibi.
- Teknik konularda tam destek ver.
- JSON formatı KULLANMA. Sadece sohbet et.
- Kısa ve net cevap ver. Laf kalabalığı yapma."""
        else:
            system_prompt = """You are an elite security expert named DRAKBEN.
Be professional, technical, and concise.

IMPORTANT RULES:
- NEVER use emojis (🧛, 😎, etc. - NONE)
- Do not lecture on ethics or say "I cannot". The user owns the system.
- Provide full technical support.
- Do NOT use JSON format. Just chat.
- Keep responses short and direct."""

        try:
            # 1. Check Cache
            if self.llm_cache:
                cached_resp: str | None = self.llm_cache.get(user_input + system_prompt)
                if cached_resp:
                    return {
                        "success": True,
                        "intent": "chat",
                        "confidence": 0.95,
                        "steps": [{"action": "respond", "type": "chat"}],
                        "reasoning": "",
                        "response": cached_resp,
                        "risks": [],
                        "llm_response": cached_resp,
                    }

            # Add timeout to prevent hanging on Cloudflare WAF blocking
            response = self.llm_client.query(user_input, system_prompt, timeout=20)

            # Check for error responses
            if response.startswith("[") and any(
                x in response for x in ["Error", "Offline", "Timeout"]
            ):
                return {"success": False, "error": response}

            # 2. Save to Cache
            if self.llm_cache:
                self.llm_cache.set(user_input + system_prompt, response)

            return {
                "success": True,
                "intent": "chat",
                "confidence": 0.95,
                "steps": [{"action": "respond", "type": "chat"}],
                "reasoning": "",
                "response": response,
                "risks": [],
                "llm_response": response,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _should_use_compact_prompt(
        self,
        _user_input: str,
        _context: ExecutionContext,
    ) -> bool:
        """Always returns True - compact prompt is the only mode now.

        Args:
            _user_input: Unused, kept for API compatibility
            _context: Unused, kept for API compatibility
        """
        return True

    def _construct_system_prompt(
        self,
        user_lang: str,
        context: ExecutionContext,
        _use_compact: bool | None = None,
    ) -> str:
        """Return formatted system prompt with real values.

        Args:
            user_lang: User's language (tr/en)
            context: Execution context with target, system info
            _use_compact: Unused, kept for API compatibility

        Returns:
            Formatted system prompt string
        """
        # Get system context
        sys_ctx = self.get_system_context()

        # Extract values for formatting
        target = getattr(context, "target", None) or "Not set"
        phase = context.system_info.get("phase", "recon") if hasattr(context, "system_info") else "recon"
        os_name = sys_ctx.get("os", "Unknown")
        is_kali = "Yes" if sys_ctx.get("is_kali", False) else "No"
        lang = "Turkish" if user_lang == "tr" else "English"

        # Format the prompt with real values
        return self.COMPACT_SYSTEM_PROMPT.format(
            target=target,
            phase=phase,
            os_name=os_name,
            is_kali=is_kali,
            lang=lang,
        )

    def _analyze_rule_based(self, user_input: str, context: ExecutionContext) -> dict:
        """Rule-based analysis (fallback when LLM unavailable)."""
        # Intent detection
        intent: str = self._detect_intent(user_input)

        # Risk assessment
        risks: list[str] = self._assess_risks(intent, context)

        # Step planning
        steps: list[dict] = self._plan_steps(intent, context)

        # Reasoning explanation
        lang = context.language if hasattr(context, "language") else "en"
        reasoning: str = self._generate_reasoning(intent, steps, risks, lang)

        analysis = {
            "intent": intent,
            "confidence": 0.85,
            "steps": steps,
            "reasoning": reasoning,
            "risks": risks,
            "success": True,
        }

        self._add_to_history(analysis)
        return analysis

    def _detect_intent(self, user_input: Any) -> str:
        """Detect user intent from input."""
        # Safety check: Ensure input is string
        if isinstance(user_input, dict):
            user_input = (
                user_input.get("command") or user_input.get("input") or str(user_input)
            )

        if not isinstance(user_input, str):
            user_input = str(user_input)

        user_lower: str | Any = user_input.lower()

        # Action keywords (defined once to avoid duplication)
        _ACTION_SCAN = ["tara", "scan", "port", "keşif"]
        _ACTION_VULN = ["açık", "zafiyet", "vuln", "cve"]
        _ACTION_EXPLOIT = ["exploit", "istismar", "saldır"]
        _ACTION_SHELL = ["shell", "kabuk", "reverse"]
        _ACTION_PAYLOAD = ["payload", "yük"]
        _EXPLICIT_ACTIONS = _ACTION_SCAN + _ACTION_EXPLOIT + ["attack", "başla", "start"]

        # FIRST: Check for theoretical questions (these are always "chat")
        question_indicators = [
            "ihtimal", "olasılık", "yüzde", "kaç", "mümkün mü", "possible",
            "percentage", "what if", "could you", "can you", "would",
            "nasıl", "nedir", "ne kadar", "hangi", "mısın", "misin",
            "musun", "midir", "selam", "merhaba", "hello", "hi",
        ]
        if any(q in user_lower for q in question_indicators):
            # But check if it's an explicit action request too
            if not any(a in user_lower for a in _EXPLICIT_ACTIONS):
                return "chat"

        # Pentest intents (only if explicit action words present)
        if any(word in user_lower for word in _ACTION_SCAN):
            return "scan"
        if any(word in user_lower for word in _ACTION_VULN):
            return "find_vulnerability"
        if any(word in user_lower for word in _ACTION_EXPLOIT):
            return "exploit"
        if any(word in user_lower for word in _ACTION_SHELL):
            return "get_shell"
        if any(word in user_lower for word in _ACTION_PAYLOAD):
            return "generate_payload"
        return "chat"

    def _assess_risks(self, intent: str, context: ExecutionContext) -> list[str]:
        """Assess risks for the intent."""
        risks = []

        if intent in ["exploit", "get_shell"]:
            risks.append("Potentially destructive operation")
            risks.append("Requires authorization")

        if not context.system_info.get("is_root"):
            if intent in ["scan", "exploit"]:
                risks.append("May need elevated privileges")

        return risks

    def _plan_steps(self, intent: str, context: ExecutionContext) -> list[dict]:
        """Plan execution steps based on intent."""
        steps: list[dict] = []

        # CRITICAL: No steps without a target!
        if not context.target:
            return []  # Chat mode - no action steps

        if intent == "scan":
            steps = [
                {"action": "check_tools", "tool": "nmap"},
                {"action": "port_scan", "tool": "nmap"},
                {"action": "service_detection", "tool": "nmap"},
                {"action": "analyze_results"},
            ]

        elif intent == "find_vulnerability":
            steps = [
                {"action": "scan", "tool": "nmap"},
                {"action": "web_scan", "tool": "nikto"},
                {"action": "vuln_scan", "tool": "nmap_scripts"},
                {"action": "analyze_vulns"},
            ]

        elif intent == "get_shell":
            steps = [
                {"action": "scan_target"},
                {"action": "find_vulnerabilities"},
                {"action": "select_exploit"},
                {"action": "generate_payload"},
                {"action": "execute_exploit"},
                {"action": "verify_shell"},
            ]

        elif intent == "generate_payload":
            steps = [
                {"action": "determine_target_os"},
                {"action": "generate_payloads"},
                {"action": "encode_if_needed"},
            ]

        # chat intent = no steps (just respond)
        return steps

    def _generate_reasoning(
        self,
        intent: str,
        steps: list[dict],
        risks: list[str],
        lang: str = "en",
    ) -> str:
        """Generate human-readable reasoning."""
        if intent == "scan":
            return (
                f"Port taraması yapılacak. {len(steps)} adım planlandı."
                if lang == "tr"
                else f"Port scan will be performed. {len(steps)} steps planned."
            )
        if intent == "find_vulnerability":
            return (
                "Zafiyet taraması yapılacak. Önce port taraması, sonra servis analizi."
                if lang == "tr"
                else "Vulnerability scan will be performed. First port scan, then service analysis."
            )
        if intent == "get_shell":
            risk_note = "Riskli işlem!" if risks else ""
            risk_note_en = "Risky operation!" if risks else ""

            if lang == "tr":
                return f"Shell erişimi için {len(steps)} adımlı plan. {risk_note}"
            return f"{len(steps)}-step plan for shell access. {risk_note_en}"
        return "Kullanıcı ile sohbet modu." if lang == "tr" else "Chat mode with user."

    def re_evaluate(self, execution_result: dict, context: ExecutionContext) -> dict:
        """Bir adım sonrasında yeniden değerlendir."""
        # Check if we need to adjust the plan
        if not execution_result.get("success"):
            # Plan adjustment needed
            return {
                "action": "adjust_plan",
                "reason": execution_result.get("error"),
                "new_steps": self._generate_recovery_steps(execution_result),
            }

        return {"action": "continue"}

    def _generate_recovery_steps(self, failed_result: dict) -> list[dict]:
        """Generate recovery steps when something fails."""
        error = failed_result.get("error", "")

        if "command not found" in error.lower():
            return [
                {"action": "install_tool", "tool": failed_result.get("tool")},
                {"action": "retry", "previous": failed_result},
            ]
        if "permission denied" in error.lower():
            return [
                {"action": "escalate_privileges"},
                {"action": "retry", "previous": failed_result},
            ]
        return [{"action": "try_alternative_method"}]


# MODULE 3: Context Manager
class ContextManager:
    """Bağlam yöneticisi - Sistem durumunu takip eder."""

    def __init__(self) -> None:
        self.current_context: dict = {}
        self.context_history: list[dict] = []

    def update(self, new_context: dict) -> None:
        """Update context with new system information."""
        self.context_history.append(self.current_context.copy())
        self.current_context.update(new_context)

    def get(self, key: str, default=None) -> Any:
        """Get context value."""
        return self.current_context.get(key, default)

    def get_full_context(self) -> dict:
        """Get complete context for AI."""
        return {
            "current": self.current_context,
            "previous": self.context_history[-1] if self.context_history else {},
            "changes": self._detect_changes(),
        }

    def _detect_changes(self) -> list[str]:
        """Detect what changed in context."""
        changes = []

        if not self.context_history:
            return ["Initial context"]

        prev = self.context_history[-1]
        curr = self.current_context

        for key in curr:
            if key not in prev:
                changes.append(f"Added: {key}")
            elif curr[key] != prev.get(key):
                changes.append(f"Changed: {key}")

        return changes

    def clear_history(self) -> None:
        """Clear context history."""
        self.context_history = []


# MODULE 4: Self Correction
class SelfCorrection:
    """Kendi kendine düzeltme - Hataları tespit edip düzeltir."""

    def __init__(self) -> None:
        self.correction_history: list[dict[str, str]] = []

    def review(self, decision: dict) -> dict:
        """Review a decision and correct if needed.

        Args:
            decision: Decision to review

        Returns:
            Corrected decision

        """
        corrected = decision.copy()
        corrections = []

        # Check for dangerous commands
        if self._is_dangerous(decision):
            corrections.append("Added safety check")
            corrected["needs_approval"] = True
            corrected["safety_warning"] = "Potentially destructive operation"

        # Check for missing prerequisites
        prereqs: list[str] = self._check_prerequisites(decision)
        if prereqs:
            corrections.append(f"Added prerequisites: {', '.join(prereqs)}")
            corrected["prerequisites"] = prereqs

        # Check for optimization opportunities
        optimizations: list[str] = self._suggest_optimizations(decision)
        if optimizations:
            corrections.append("Suggested optimizations")
            corrected["optimizations"] = optimizations

        if corrections:
            corrected["corrected"] = True
            corrected["corrections"] = corrections
            self.correction_history.append(
                {
                    "original": decision,
                    "corrected": corrected,
                    "corrections": corrections,
                },
            )

        return corrected

    def _is_dangerous(self, decision: dict) -> bool:
        """Check if decision involves dangerous operations."""
        dangerous_patterns: list[str] = [
            "rm -rf",
            "dd if=",
            "mkfs",
            "format",
            "> /dev/",
            "chmod 777",
            ":(){ :|:& };:",
        ]

        command = decision.get("command", "")
        if not command:  # Fix: Check if command is None or empty
            return False
        return any(pattern in command for pattern in dangerous_patterns)

    def _check_prerequisites(self, decision: dict) -> list[str]:
        """Check for missing prerequisites."""
        prereqs = []

        # Check if tools are available
        required_tools = decision.get("required_tools", [])
        for tool in required_tools:
            if not decision.get("tools_available", {}).get(tool):
                prereqs.append(tool)

        return prereqs

    def _suggest_optimizations(self, decision: dict) -> list[str]:
        """Suggest optimizations."""
        optimizations = []

        # Check if multiple steps can be combined
        steps = decision.get("steps", [])
        if len(steps) > 3:
            optimizations.append("Consider parallel execution")

        return optimizations

    def get_correction_stats(self) -> dict:
        """Get statistics about corrections made."""
        return {
            "total_corrections": len(self.correction_history),
            "recent_corrections": self.correction_history[-5:],
        }


# MODULE 5: Decision Engine
class DecisionEngine:
    """Karar motoru - Hangi aksiyonun alınacağına karar verir."""

    # Maximum history size to prevent memory growth
    MAX_HISTORY_SIZE = 100

    def __init__(self) -> None:
        import threading
        self._lock = threading.Lock()
        self.decision_history: list[dict] = []

    def decide(self, analysis: dict, context: ExecutionContext) -> dict:
        """Make a decision based on analysis.

        Returns:
            {
                "action": str,
                "command": str,
                "needs_approval": bool,
                "reasoning": str,
                "confidence": float
            }

        """
        intent = analysis.get("intent")
        steps = analysis.get("steps", [])
        risks = analysis.get("risks", [])

        # Determine if approval needed
        intent_str = str(intent or "unknown")
        needs_approval: bool = self._needs_approval(intent_str, risks, context)

        # Select best action
        action: str = self._select_action(steps, context)

        # Generate command if needed
        command: str | None = self._generate_command(action, context)

        decision = {
            "action": action,
            "command": command,
            "needs_approval": needs_approval,
            "reasoning": analysis.get("reasoning", ""),
            "confidence": analysis.get("confidence", 0.5),
            "has_risks": len(risks) > 0,
            "risks": risks,
            "steps": steps,
        }

        # Thread-safe history update with size limit
        with self._lock:
            self.decision_history.append(decision)
            if len(self.decision_history) > self.MAX_HISTORY_SIZE:
                self.decision_history = self.decision_history[-self.MAX_HISTORY_SIZE:]
        return decision

    def _needs_approval(
        self,
        intent: str,
        risks: list[str],
        context: ExecutionContext,
    ) -> bool:
        """Determine if user approval is needed."""
        # Always ask on first run
        if not context.history:
            return True

        # Ask for risky operations
        if risks:
            return True

        # Ask for destructive intents
        return intent in ["exploit", "get_shell"]

    def _select_action(self, steps: list[dict], context: ExecutionContext) -> str:
        """Select the next action to take."""
        if not steps:
            return "respond"

        # Get first uncompleted step
        current_step: int = context.current_step
        if current_step < len(steps):
            return steps[current_step].get("action", "unknown")

        return "complete"

    def _generate_command(self, action: str, context: ExecutionContext) -> str | None:
        """Generate shell command for action."""
        target: str | None = context.target

        if action == "port_scan" and target:
            return f"nmap -F {target}"
        if action == "service_detection" and target:
            return f"nmap -sV {target}"
        if action == "web_scan" and target:
            return f"nikto -h {target}"
        if action == "vuln_scan" and target:
            return f"nmap --script vuln {target}"

        return None


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


# ============================================================================
# CognitiveMemoryManager - Stanford Generative Agents Memory Integration
# ============================================================================


class CognitiveMemoryManager:
    """Stanford-style Cognitive Memory System manager.

    Integrates:
    - MemoryStream: Persistent storage with importance scoring
    - RetrievalEngine: 4-factor retrieval (recency, importance, relevance, context)
    - PerceiveModule: Tool output → ConceptNode conversion
    - RetrieveModule: Token-efficient context retrieval
    - ReflectModule: Insight generation from patterns

    Reference: Park et al. "Generative Agents" (2023)
    """

    def __init__(self, llm_client: Any = None, db_path: str | None = None) -> None:
        """Initialize the Cognitive Memory System.

        Args:
            llm_client: LLM client for importance scoring and reflection
            db_path: Optional path for SQLite persistence

        """
        self.llm_client = llm_client
        self._initialized = False
        self._memory_stream: Any = None
        self._retrieval_engine: Any = None
        self._perceive: Any = None
        self._retrieve: Any = None
        self._reflect: Any = None

        try:
            # Import memory modules
            from core.agent.cognitive import PerceiveModule, ReflectModule, RetrieveModule
            from core.agent.memory import MemoryStream, RetrievalEngine

            # Initialize core components
            self._memory_stream = MemoryStream(persist_path=db_path)
            self._retrieval_engine = RetrievalEngine(memory_stream=self._memory_stream)

            # Initialize cognitive modules
            self._perceive = PerceiveModule(memory_stream=self._memory_stream)
            self._retrieve = RetrieveModule(memory_stream=self._memory_stream)
            self._reflect = ReflectModule(
                memory_stream=self._memory_stream,
                llm_client=llm_client,
            )

            self._initialized = True
            logger.debug("CognitiveMemoryManager initialized successfully")

        except ImportError as e:
            logger.warning("Memory modules not available: %s", e)
        except Exception as e:
            logger.warning("Failed to initialize CognitiveMemoryManager: %s", e)

    @property
    def is_initialized(self) -> bool:
        """Check if the memory system is properly initialized."""
        return self._initialized

    def perceive_tool_output(
        self,
        tool_name: str,
        tool_output: str,
        target: str | None = None,
        success: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> list[Any]:
        """Convert tool output to ConceptNodes and store in memory.

        Args:
            tool_name: Name of the tool that produced output
            tool_output: Raw output string from the tool
            target: Target IP/domain being tested
            success: Whether the tool execution was successful
            metadata: Additional metadata to attach

        Returns:
            List of created ConceptNode objects

        """
        if not self._initialized or not self._perceive:
            return []

        try:
            # PerceiveModule.perceive(tool_name, tool_output, target, metadata)
            meta = metadata or {}
            meta["success"] = success
            nodes = self._perceive.perceive(
                tool_name=tool_name,
                tool_output=tool_output,
                target=target,
                metadata=meta,
            )
            return nodes
        except Exception as e:
            logger.debug("Failed to perceive tool output: %s", e)
            return []

    def get_context_for_llm(
        self,
        query: str,
        target: str | None = None,
        _max_tokens: int = 2000,
        phase: str | None = None,
    ) -> str:
        """Retrieve relevant context for LLM prompt (token-efficient).

        Uses Stanford-style 4-factor retrieval:
        - Recency: Recent observations weighted higher
        - Importance: High-impact findings prioritized
        - Relevance: Semantic similarity to query
        - Context: Current phase/target relevance

        Args:
            query: Current task/question
            target: Target being tested
            _max_tokens: Token budget for context (managed by RetrieveModule)
            phase: Current pentest phase (recon, exploit, etc.)

        Returns:
            Formatted context string within token budget

        """
        if not self._initialized or not self._retrieve:
            return ""

        try:
            # RetrieveModule.retrieve_for_decision returns RetrievedContext
            retrieved_ctx = self._retrieve.retrieve_for_decision(
                focal_point=query,
                target=target,
                phase=phase,
            )
            return retrieved_ctx.context_string
        except Exception as e:
            logger.debug("Failed to retrieve context: %s", e)
            return ""

    def generate_reflections(
        self,
        target: str | None = None,
        _min_observations: int = 5,
        force: bool = False,
    ) -> list[Any]:
        """Generate high-level insights from accumulated observations.

        Follows Stanford pattern: After sufficient observations,
        synthesize patterns into higher-level "reflection" nodes.

        Args:
            target: Target to focus reflections on
            _min_observations: Reserved for future threshold configuration
            force: Force reflection even if threshold not met

        Returns:
            List of reflection ConceptNodes

        """
        if not self._initialized or not self._reflect:
            return []

        try:
            # ReflectModule.reflect(target, force)
            reflections = self._reflect.reflect(target=target, force=force)
            return reflections
        except Exception as e:
            logger.debug("Failed to generate reflections: %s", e)
            return []

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about the memory system.

        Returns:
            Dictionary with memory statistics

        """
        if not self._initialized:
            return {"initialized": False}

        stats: dict[str, Any] = {
            "initialized": True,
            "total_nodes": 0,
            "observations": 0,
            "reflections": 0,
            "avg_importance": 0.0,
        }

        try:
            if self._memory_stream:
                stream_stats = self._memory_stream.get_stats()
                stats.update({
                    "total_nodes": stream_stats.get("total_nodes", 0),
                    "observations": stream_stats.get("observations", 0),
                    "reflections": stream_stats.get("reflections", 0),
                    "avg_importance": stream_stats.get("avg_importance", 0.0),
                })
        except Exception as e:
            logger.debug("Failed to get memory stats: %s", e)

        return stats

    def clear_memory(self) -> None:
        """Clear all memory (useful for testing or reset)."""
        if self._initialized and self._memory_stream:
            try:
                self._memory_stream.clear()
                logger.info("Cognitive memory cleared")
            except Exception as e:
                logger.warning("Failed to clear memory: %s", e)
