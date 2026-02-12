# core/llm/token_counter.py
# DRAKBEN — Token Counting & Budget Management
# Uses tiktoken for accurate OpenAI-compatible tokenization.
# Graceful fallback to word-based estimation when tiktoken is unavailable.

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Model name constants (SonarQube: avoid duplicating string literals)
_MODEL_GPT_35_TURBO = "gpt-3.5-turbo"

# Graceful tiktoken import
_TIKTOKEN_AVAILABLE = False
try:
    import tiktoken

    _TIKTOKEN_AVAILABLE = True
except ImportError:
    logger.info("tiktoken not installed — using word-based token estimation.")

# Model → encoding mapping
_MODEL_ENCODING_MAP: dict[str, str] = {
    "gpt-4": "cl100k_base",
    "gpt-4o": "o200k_base",
    "gpt-4-turbo": "cl100k_base",
    _MODEL_GPT_35_TURBO: "cl100k_base",
    "claude": "cl100k_base",
    "llama": "cl100k_base",
    "mistral": "cl100k_base",
    "gemma": "cl100k_base",
    "qwen": "cl100k_base",
    "deepseek": "cl100k_base",
}

# Model → context window size (tokens)
_MODEL_CONTEXT_WINDOWS: dict[str, int] = {
    "gpt-4": 8192,
    "gpt-4-turbo": 128000,
    "gpt-4o": 128000,
    "gpt-4o-mini": 128000,
    _MODEL_GPT_35_TURBO: 16385,
    "claude-3-opus": 200000,
    "claude-3-sonnet": 200000,
    "claude-3-haiku": 200000,
    "claude-3.5-sonnet": 200000,
    "llama-3.1-70b": 131072,
    "llama-3.1-8b": 131072,
    "mistral-large": 128000,
    "mistral-7b": 32768,
    "deepseek-coder": 128000,
    "qwen-2.5": 131072,
    "default": 8192,
}

# Approximate cost per 1M tokens (USD) — input/output
_MODEL_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4": (30.0, 60.0),
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-4o": (2.5, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
    _MODEL_GPT_35_TURBO: (0.50, 1.50),
    "claude-3-opus": (15.0, 75.0),
    "claude-3-sonnet": (3.0, 15.0),
    "claude-3-haiku": (0.25, 1.25),
    "llama-3.1-70b": (0.59, 0.79),
    "llama-3.1-8b": (0.055, 0.055),
    "mistral-large": (2.0, 6.0),
    "mistral-7b": (0.07, 0.07),
    "deepseek-coder": (0.14, 0.28),
}

# Word-to-token ratio (fallback approximation: ~1.3 tokens per word for English)
_WORD_TOKEN_RATIO = 1.3


class TokenCounter:
    """Token counting engine with tiktoken and fallback estimation.

    Usage::

        counter = TokenCounter(model="gpt-4o")
        count = counter.count_tokens("Hello, world!")
        messages = counter.trim_to_budget(messages, max_tokens=4096)
        cost = counter.estimate_cost(input_tokens=1000, output_tokens=500)

    """

    def __init__(self, model: str = "gpt-4o") -> None:
        self.model = model
        self._encoder = None
        self._encoding_name = self._resolve_encoding(model)

        if _TIKTOKEN_AVAILABLE:
            try:
                self._encoder = tiktoken.get_encoding(self._encoding_name)
            except Exception as exc:
                logger.warning("Failed to load tiktoken encoding %s: %s", self._encoding_name, exc)

    @staticmethod
    def _resolve_encoding(model: str) -> str:
        """Resolve tiktoken encoding name for a model."""
        model_lower = model.lower()
        # Sort by key length descending so "gpt-4o" matches before "gpt-4"
        for prefix, encoding in sorted(_MODEL_ENCODING_MAP.items(), key=lambda x: -len(x[0])):
            if prefix in model_lower:
                return encoding
        return "cl100k_base"  # Safe default

    def count_tokens(self, text: str) -> int:
        """Count tokens in a text string.

        Args:
            text: Input text to tokenize.

        Returns:
            Token count (exact with tiktoken, estimated without).

        """
        if not text:
            return 0

        if self._encoder is not None:
            return len(self._encoder.encode(text))

        # Fallback: word-based estimation
        return int(len(text.split()) * _WORD_TOKEN_RATIO)

    def count_messages_tokens(self, messages: list[dict[str, str]]) -> int:
        """Count total tokens across a list of chat messages.

        Each message has overhead for role/content structure (~4 tokens per message).

        Args:
            messages: List of {"role": ..., "content": ...} dicts.

        Returns:
            Total token count including message overhead.

        """
        total = 0
        overhead_per_message = 4  # role + separators

        for msg in messages:
            content = msg.get("content", "")
            total += self.count_tokens(content) + overhead_per_message

        total += 2  # reply priming tokens
        return total

    def get_context_window(self) -> int:
        """Get the context window size for the current model.

        Returns:
            Maximum context window in tokens.

        """
        model_lower = self.model.lower()
        # Sort by key length descending so "gpt-4-turbo" matches before "gpt-4"
        for prefix, window in sorted(_MODEL_CONTEXT_WINDOWS.items(), key=lambda x: -len(x[0])):
            if prefix in model_lower:
                return window
        return _MODEL_CONTEXT_WINDOWS["default"]

    def trim_to_budget(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
        *,
        reserve_for_response: int = 1024,
    ) -> list[dict[str, str]]:
        """Trim message history to fit within token budget.

        Keeps the system message (first) and trims oldest user/assistant
        messages from the middle until the total fits.

        Args:
            messages: Chat messages in OpenAI format.
            max_tokens: Maximum token budget. Defaults to model context window.
            reserve_for_response: Tokens to reserve for the LLM response.

        Returns:
            Trimmed list of messages that fits the budget.

        """
        if not messages:
            return []

        if max_tokens is None:
            max_tokens = self.get_context_window()

        budget = max_tokens - reserve_for_response
        if budget <= 0:
            return messages[:1]  # At least keep system message

        # Always keep the system message (index 0) and latest user message (last)
        if len(messages) <= 2:
            return messages

        system_msg = messages[0] if messages[0].get("role") == "system" else None
        latest_msg = messages[-1]

        # Calculate fixed token costs
        fixed_tokens = 0
        if system_msg:
            fixed_tokens += self.count_tokens(system_msg.get("content", "")) + 4
        fixed_tokens += self.count_tokens(latest_msg.get("content", "")) + 4 + 2

        if fixed_tokens >= budget:
            # Even system + latest don't fit — return them anyway
            result = []
            if system_msg:
                result.append(system_msg)
            result.append(latest_msg)
            return result

        remaining_budget = budget - fixed_tokens

        # Fill from most recent to oldest (keep recency)
        middle_messages = messages[1:-1] if system_msg else messages[:-1]
        kept_middle: list[dict[str, str]] = []

        for msg in reversed(middle_messages):
            msg_tokens = self.count_tokens(msg.get("content", "")) + 4
            if msg_tokens <= remaining_budget:
                kept_middle.insert(0, msg)
                remaining_budget -= msg_tokens
            # Skip large messages but continue checking smaller earlier ones
            # (using 'continue' instead of 'break' avoids losing all prior
            # context when a single large tool-output message is encountered)

        result: list[dict[str, str]] = []
        if system_msg:
            result.append(system_msg)
        result.extend(kept_middle)
        result.append(latest_msg)
        return result

    def estimate_cost(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        model: str | None = None,
    ) -> dict[str, Any]:
        """Estimate API cost for given token counts.

        Args:
            input_tokens: Number of input/prompt tokens.
            output_tokens: Number of output/completion tokens.
            model: Model name (uses self.model if not specified).

        Returns:
            Dict with input_cost, output_cost, total_cost (USD).

        """
        target_model = (model or self.model).lower()
        pricing = None

        # Sort by key length descending so "gpt-4-turbo" matches before "gpt-4"
        for prefix, price in sorted(_MODEL_PRICING.items(), key=lambda x: -len(x[0])):
            if prefix in target_model:
                pricing = price
                break

        if pricing is None:
            return {
                "input_cost": 0.0,
                "output_cost": 0.0,
                "total_cost": 0.0,
                "note": "Unknown model pricing",
            }

        input_cost = (input_tokens / 1_000_000) * pricing[0]
        output_cost = (output_tokens / 1_000_000) * pricing[1]

        return {
            "input_cost": round(input_cost, 6),
            "output_cost": round(output_cost, 6),
            "total_cost": round(input_cost + output_cost, 6),
            "model": target_model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }

    def fits_context(self, text: str, *, reserve: int = 1024) -> bool:
        """Check if text fits within the model's context window.

        Args:
            text: Text to check.
            reserve: Tokens to reserve for response.

        Returns:
            True if text fits, False otherwise.

        """
        tokens = self.count_tokens(text)
        return tokens <= (self.get_context_window() - reserve)

    def get_stats(self) -> dict[str, Any]:
        """Return token counter configuration stats."""
        return {
            "model": self.model,
            "encoding": self._encoding_name,
            "tiktoken_available": _TIKTOKEN_AVAILABLE,
            "context_window": self.get_context_window(),
        }
