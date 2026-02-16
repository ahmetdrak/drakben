# core/intelligence/model_router.py
# DRAKBEN — Smart Model Router
#
# Problem: Every LLM query goes to the same model, regardless of
#          task complexity. Simple parsing wastes expensive model tokens,
#          while complex reasoning on cheap models produces bad output.
# Solution: Route queries to the best model based on task type:
#   - FAST: Simple parsing, JSON extraction, tool selection → cheap model
#   - BALANCED: Tool analysis, recovery planning → mid-tier model
#   - POWERFUL: Complex reasoning, exploitation planning → best model
#
# Works with ANY model provider (OpenRouter, OpenAI, Ollama).
# If only one model is available, gracefully falls back to it.

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TaskComplexity(Enum):
    """Query complexity classification."""

    FAST = "fast"  # Simple parsing, extraction
    BALANCED = "balanced"  # Analysis, moderate reasoning
    POWERFUL = "powerful"  # Complex planning, exploitation strategy


@dataclass
class ModelSpec:
    """Specification for an available model."""

    model_id: str  # e.g., "google/gemini-flash-1.5"
    provider: str = ""  # "openrouter", "openai", "ollama"
    tier: TaskComplexity = TaskComplexity.BALANCED
    cost_per_1k: float = 0.0  # $ per 1k tokens (0 = free)
    speed_rating: float = 1.0  # Relative speed (higher = faster)
    quality_rating: float = 1.0  # Relative quality (higher = better)
    max_context: int = 8192
    supports_tools: bool = False
    supports_json: bool = True

    def score_for_task(self, complexity: TaskComplexity) -> float:
        """Score this model's fitness for a given task complexity."""
        if complexity == TaskComplexity.FAST:
            # Prefer speed and low cost
            return self.speed_rating * 3.0 - self.cost_per_1k * 10 + self.quality_rating
        if complexity == TaskComplexity.POWERFUL:
            # Prefer quality
            return self.quality_rating * 3.0 + self.speed_rating - self.cost_per_1k * 2
        # BALANCED
        return self.quality_rating * 2.0 + self.speed_rating * 2.0 - self.cost_per_1k * 5


@dataclass
class RoutingDecision:
    """Result of routing a query to a model."""

    model_id: str
    tier: TaskComplexity
    reason: str
    estimated_quality: float = 0.0


class ModelRouter:
    """Routes LLM queries to the optimal model based on task complexity.

    Usage::

        router = ModelRouter()
        router.register_model(ModelSpec(
            model_id="google/gemini-flash-1.5",
            tier=TaskComplexity.FAST,
            speed_rating=3.0,
            quality_rating=0.7,
            cost_per_1k=0.0,
        ))
        router.register_model(ModelSpec(
            model_id="anthropic/claude-3.5-sonnet",
            tier=TaskComplexity.POWERFUL,
            speed_rating=1.5,
            quality_rating=3.0,
            cost_per_1k=0.003,
        ))

        # Route based on task
        decision = router.route("Analyze this nmap output for vulnerabilities")
        print(f"Using {decision.model_id} ({decision.tier.value})")

    """

    # ── Task classification patterns ──

    _FAST_PATTERNS = [
        re.compile(r"extract\s*(json|data|port|ip)", re.IGNORECASE),
        re.compile(r"parse\s*(this|output|response)", re.IGNORECASE),
        re.compile(r"convert\s*(to|into)", re.IGNORECASE),
        re.compile(r"format\s*(as|into|to)", re.IGNORECASE),
        re.compile(r"list\s*(the|all)", re.IGNORECASE),
        re.compile(r"what\s*(port|ip|service|version)", re.IGNORECASE),
        re.compile(r"is\s*(this|it)\s*(open|closed|vuln)", re.IGNORECASE),
    ]

    _POWERFUL_PATTERNS = [
        re.compile(r"exploit\w*\s*(plan|strateg|chain)", re.IGNORECASE),
        re.compile(r"(how|can|should)\s*(i|we)\s*(exploit|attack|compromise)", re.IGNORECASE),
        re.compile(r"(lateral|privilege)\s*(mov|escal)", re.IGNORECASE),
        re.compile(r"(complex|advanced|sophisticated)", re.IGNORECASE),
        re.compile(r"(plan|design|architect)\s*(an?\s*)?(attack|pentest|approach)", re.IGNORECASE),
        re.compile(r"(why|reason|explain)\s*(did|does|would|the)", re.IGNORECASE),
        re.compile(r"(compare|evaluate|assess|prioritize)", re.IGNORECASE),
        re.compile(r"(write|generate|create)\s*(a\s*)?(script|code|payload|exploit)", re.IGNORECASE),
    ]

    def __init__(self) -> None:
        self._models: dict[str, ModelSpec] = {}
        self._default_model: str = ""
        self._stats = {
            "routes": 0,
            "fast_routes": 0,
            "balanced_routes": 0,
            "powerful_routes": 0,
            "fallbacks": 0,
        }
        self._performance_log: list[dict[str, Any]] = []

    # ─────────────────────── Public API ───────────────────────

    def register_model(self, spec: ModelSpec) -> None:
        """Register an available model."""
        self._models[spec.model_id] = spec
        if not self._default_model:
            self._default_model = spec.model_id
        logger.debug("Model registered: %s (tier=%s)", spec.model_id, spec.tier.value)

    def set_default_model(self, model_id: str) -> None:
        """Set the default fallback model."""
        self._default_model = model_id

    def auto_detect_models(self, llm_client: Any) -> None:
        """Auto-detect available models from LLM client.

        Tries to detect the current model and register it with
        reasonable defaults.
        """
        model_name = ""
        if hasattr(llm_client, "model"):
            model_name = llm_client.model or ""
        elif hasattr(llm_client, "_model"):
            model_name = llm_client._model or ""

        if not model_name:
            return

        # Classify the model
        spec = self._classify_model(model_name)
        self.register_model(spec)
        self._default_model = model_name

    def route(
        self,
        prompt: str,
        *,
        task_type: str = "",
        force_tier: TaskComplexity | None = None,
    ) -> RoutingDecision:
        """Route a query to the optimal model.

        Args:
            prompt: The query prompt.
            task_type: Optional explicit task type hint.
            force_tier: Force a specific complexity tier.

        Returns:
            RoutingDecision with the selected model.

        """
        self._stats["routes"] += 1

        if not self._models:
            # No models registered — return default
            self._stats["fallbacks"] += 1
            return RoutingDecision(
                model_id=self._default_model or "default",
                tier=TaskComplexity.BALANCED,
                reason="No models registered — using default",
            )

        # Determine complexity
        if force_tier:
            complexity = force_tier
        elif task_type:
            complexity = self._task_type_to_complexity(task_type)
        else:
            complexity = self._classify_prompt(prompt)

        # Track stats
        stat_key = f"{complexity.value}_routes"
        if stat_key in self._stats:
            self._stats[stat_key] += 1

        # Find best model for this complexity
        best_model = self._select_best_model(complexity)

        if not best_model:
            self._stats["fallbacks"] += 1
            return RoutingDecision(
                model_id=self._default_model,
                tier=complexity,
                reason=f"No model for {complexity.value} — using default",
            )

        return RoutingDecision(
            model_id=best_model.model_id,
            tier=complexity,
            reason=f"Best {complexity.value} model: quality={best_model.quality_rating:.1f}, speed={best_model.speed_rating:.1f}",
            estimated_quality=best_model.quality_rating,
        )

    def route_for_task(self, task_type: str) -> RoutingDecision:
        """Route based on explicit task type.

        Task types:
            - "json_parse", "extract", "format" → FAST
            - "tool_analysis", "recovery", "next_step" → BALANCED
            - "exploit_plan", "code_gen", "reasoning" → POWERFUL
        """
        return self.route("", task_type=task_type)

    def record_performance(
        self,
        model_id: str,
        task_type: str,
        duration: float,
        success: bool,
        quality_score: float = 0.0,
    ) -> None:
        """Record model performance for future optimization.

        Over time, the router learns which models perform best
        for which tasks and adjusts scoring.
        """
        self._performance_log.append(
            {
                "model": model_id,
                "task": task_type,
                "duration": duration,
                "success": success,
                "quality": quality_score,
                "timestamp": time.time(),
            }
        )

        # Keep last 500 entries
        if len(self._performance_log) > 500:
            self._performance_log = self._performance_log[-500:]

        # Adjust model ratings based on accumulated data
        self._update_model_ratings(model_id)

    def get_stats(self) -> dict[str, Any]:
        """Return router statistics."""
        return {
            **self._stats,
            "registered_models": len(self._models),
            "performance_records": len(self._performance_log),
        }

    # ─────────────────── Classification ───────────────────

    def _classify_prompt(self, prompt: str) -> TaskComplexity:
        """Classify prompt complexity from content."""
        if not prompt:
            return TaskComplexity.BALANCED

        # Check FAST patterns
        fast_score = sum(1 for p in self._FAST_PATTERNS if p.search(prompt))
        # Check POWERFUL patterns
        powerful_score = sum(1 for p in self._POWERFUL_PATTERNS if p.search(prompt))

        # Length heuristic
        word_count = len(prompt.split())
        if word_count > 500:
            powerful_score += 1  # Long prompts need powerful models

        if fast_score > powerful_score and fast_score > 0:
            return TaskComplexity.FAST
        if powerful_score > fast_score and powerful_score > 0:
            return TaskComplexity.POWERFUL
        return TaskComplexity.BALANCED

    def _task_type_to_complexity(self, task_type: str) -> TaskComplexity:
        """Map explicit task type to complexity."""
        fast_tasks = {"json_parse", "extract", "format", "classify", "simple_parse"}
        powerful_tasks = {
            "exploit_plan",
            "code_gen",
            "reasoning",
            "strategy",
            "code_generation",
            "exploit_strategy",
            "complex_analysis",
        }

        task_lower = task_type.lower()
        if task_lower in fast_tasks:
            return TaskComplexity.FAST
        if task_lower in powerful_tasks:
            return TaskComplexity.POWERFUL
        return TaskComplexity.BALANCED

    def _classify_model(self, model_name: str) -> ModelSpec:
        """Classify a model by name into a ModelSpec with defaults."""
        name_lower = model_name.lower()

        # Powerful models
        if any(k in name_lower for k in ("claude-3-opus", "gpt-4o", "claude-3.5-sonnet", "gpt-4-turbo")):
            return ModelSpec(
                model_id=model_name,
                tier=TaskComplexity.POWERFUL,
                speed_rating=1.5,
                quality_rating=3.0,
                cost_per_1k=0.003,
                max_context=128000,
                supports_tools=True,
            )

        # Fast models
        if any(k in name_lower for k in ("flash", "mini", "haiku", "gemma", "phi", "llama-3.1-8b")):
            return ModelSpec(
                model_id=model_name,
                tier=TaskComplexity.FAST,
                speed_rating=3.0,
                quality_rating=0.8,
                cost_per_1k=0.0,
                max_context=32000,
            )

        # Balanced (default)
        return ModelSpec(
            model_id=model_name,
            tier=TaskComplexity.BALANCED,
            speed_rating=2.0,
            quality_rating=1.5,
            cost_per_1k=0.001,
            max_context=32000,
        )

    def _select_best_model(self, complexity: TaskComplexity) -> ModelSpec | None:
        """Select the best model for a given complexity level."""
        if not self._models:
            return None

        scored = [(spec.score_for_task(complexity), spec) for spec in self._models.values()]
        scored.sort(key=lambda x: -x[0])

        return scored[0][1] if scored else None

    def _update_model_ratings(self, model_id: str) -> None:
        """Update model ratings based on performance history."""
        if model_id not in self._models:
            return

        recent = [e for e in self._performance_log[-100:] if e["model"] == model_id]
        if len(recent) < 5:
            return  # Not enough data

        spec = self._models[model_id]

        # Update speed rating
        avg_duration = sum(e["duration"] for e in recent) / len(recent)
        if avg_duration < 3.0:
            spec.speed_rating = max(spec.speed_rating, 2.5)
        elif avg_duration > 15.0:
            spec.speed_rating = min(spec.speed_rating, 1.0)

        # Update quality rating based on success rate
        success_rate = sum(1 for e in recent if e["success"]) / len(recent)
        if success_rate > 0.9:
            spec.quality_rating = max(spec.quality_rating, 2.5)
        elif success_rate < 0.5:
            spec.quality_rating = min(spec.quality_rating, 1.0)
