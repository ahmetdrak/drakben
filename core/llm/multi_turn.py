# core/llm/multi_turn.py
# DRAKBEN — Multi-Turn Conversation Manager
# Maintains message history so the LLM sees its own previous responses.
# Integrates with TokenCounter for automatic context window trimming.

from __future__ import annotations

import logging
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)


class MessageHistory:
    """Thread-safe multi-turn message history manager.

    Keeps a sliding window of conversation messages, automatically
    trimming to fit within the model's context window via TokenCounter.

    Usage::

        history = MessageHistory(system_prompt="You are DRAKBEN.")
        history.add_user("Scan 10.0.0.1")
        history.add_assistant("Starting port scan...")
        messages = history.get_messages()  # Full conversation for LLM
        messages = history.get_trimmed_messages(max_tokens=4096)

    """

    MAX_HISTORY_SIZE = 200  # Hard cap on message count

    def __init__(
        self,
        system_prompt: str = "",
        *,
        max_messages: int = 50,
        session_id: str | None = None,
    ) -> None:
        """Initialize message history.

        Args:
            system_prompt: System prompt to prepend to every conversation.
            max_messages: Maximum number of messages to keep (excluding system).
            session_id: Optional session identifier for multi-session support.

        """
        self._lock = threading.Lock()
        self._system_prompt = system_prompt
        self._max_messages = min(max_messages, self.MAX_HISTORY_SIZE)
        self._messages: list[dict[str, str]] = []
        self._token_counter = None
        self.session_id = session_id or f"session_{int(time.time())}"
        self._created_at = time.time()

        # Lazy-load TokenCounter
        self._init_token_counter()

    def _init_token_counter(self) -> None:
        """Initialize token counter (lazy, graceful)."""
        try:
            from core.llm.token_counter import TokenCounter

            self._token_counter = TokenCounter()
        except ImportError:
            logger.debug("TokenCounter unavailable — trimming by message count only.")

    @property
    def system_prompt(self) -> str:
        """Get the current system prompt."""
        return self._system_prompt

    @system_prompt.setter
    def system_prompt(self, value: str) -> None:
        """Update the system prompt."""
        self._system_prompt = value

    def add_user(self, content: str) -> None:
        """Add a user message to history.

        Args:
            content: User's message text.

        """
        self._add_message("user", content)

    def add_assistant(self, content: str) -> None:
        """Add an assistant response to history.

        Args:
            content: Assistant's response text.

        """
        self._add_message("assistant", content)

    def add_tool_result(self, tool_name: str, output: str, *, success: bool = True) -> None:
        """Add a tool execution result as a system-like message.

        Args:
            tool_name: Name of the tool that was executed.
            output: Tool's output text.
            success: Whether the tool succeeded.

        """
        status = "SUCCESS" if success else "FAILED"
        content = f"[Tool: {tool_name}] ({status})\n{output[:2000]}"
        self._add_message("user", content)  # Tool results go as user context

    def _add_message(self, role: str, content: str) -> None:
        """Add a message with thread safety and size limit."""
        if not content:
            return

        with self._lock:
            self._messages.append({
                "role": role,
                "content": content,
                "timestamp": time.time(),
            })

            # Enforce size limit (keep most recent)
            if len(self._messages) > self._max_messages:
                self._messages = self._messages[-self._max_messages:]

    def get_messages(self) -> list[dict[str, str]]:
        """Get all messages in OpenAI chat format (with system prompt).

        Returns:
            List of {"role": ..., "content": ...} dicts.

        """
        with self._lock:
            result: list[dict[str, str]] = []

            if self._system_prompt:
                result.append({"role": "system", "content": self._system_prompt})

            # Strip internal timestamps for API calls
            result.extend(
                {"role": msg["role"], "content": msg["content"]}
                for msg in self._messages
            )

            return result

    def get_trimmed_messages(
        self,
        max_tokens: int | None = None,
        *,
        reserve_for_response: int = 1024,
    ) -> list[dict[str, str]]:
        """Get messages trimmed to fit within token budget.

        Uses TokenCounter.trim_to_budget() for accurate trimming.
        Falls back to message-count trimming if TokenCounter is unavailable.

        Args:
            max_tokens: Maximum token budget. Defaults to model context window.
            reserve_for_response: Tokens to reserve for the LLM response.

        Returns:
            Trimmed list of messages.

        """
        messages = self.get_messages()

        if self._token_counter:
            return self._token_counter.trim_to_budget(
                messages,
                max_tokens,
                reserve_for_response=reserve_for_response,
            )

        # Fallback: keep last N messages
        if len(messages) > 20:
            # Keep system + last 19 messages
            return [messages[0], *messages[-19:]] if messages[0].get("role") == "system" else messages[-20:]

        return messages

    def get_last_n(self, n: int = 5) -> list[dict[str, str]]:
        """Get the last N messages (without system prompt).

        Args:
            n: Number of recent messages to return.

        Returns:
            List of recent messages.

        """
        with self._lock:
            return [
                {"role": msg["role"], "content": msg["content"]}
                for msg in self._messages[-n:]
            ]

    def clear(self) -> None:
        """Clear all message history (keeps system prompt)."""
        with self._lock:
            self._messages.clear()

    def count(self) -> int:
        """Return the number of messages (excluding system prompt)."""
        with self._lock:
            return len(self._messages)

    def total_tokens(self) -> int:
        """Estimate total tokens in the current conversation.

        Returns:
            Token count (0 if TokenCounter unavailable).

        """
        if not self._token_counter:
            return 0
        return self._token_counter.count_messages_tokens(self.get_messages())

    def get_summary(self) -> dict[str, Any]:
        """Return conversation summary stats."""
        with self._lock:
            user_count = sum(1 for m in self._messages if m["role"] == "user")
            assistant_count = sum(1 for m in self._messages if m["role"] == "assistant")

        return {
            "session_id": self.session_id,
            "total_messages": self.count(),
            "user_messages": user_count,
            "assistant_messages": assistant_count,
            "total_tokens": self.total_tokens(),
            "has_system_prompt": bool(self._system_prompt),
            "created_at": self._created_at,
        }
