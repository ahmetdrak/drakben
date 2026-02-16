# core/llm/output_models.py
# DRAKBEN — Pydantic Output Validation Models
# Guarantees structured LLM outputs with auto-retry on invalid JSON.
# Equivalent to LangChain's OutputFixingParser.

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Graceful Pydantic import
_PYDANTIC_AVAILABLE = False
try:
    from pydantic import BaseModel, ConfigDict, Field, ValidationError

    _PYDANTIC_AVAILABLE = True
except ImportError:
    logger.info("pydantic not installed — using dict-based validation fallback.")

    # Provide stub classes so code doesn't crash
    class BaseModel:  # type: ignore[no-redef]
        """Stub BaseModel when pydantic is not available."""

    class Field:  # type: ignore[no-redef]
        """Stub Field."""

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            # Stub: no-op when pydantic is not installed
            pass

    class ValidationError(Exception):  # type: ignore[no-redef]
        """Stub ValidationError."""

    class ConfigDict:  # type: ignore[no-redef]
        """Stub ConfigDict."""

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            # Stub: no-op when pydantic is not installed
            pass


# ─────────────────────────────── Pydantic Models ───────────────────────────────

if _PYDANTIC_AVAILABLE:

    class LLMAnalysisResponse(BaseModel):
        """Validated LLM analysis output — matches brain_reasoning.py JSON schema."""

        model_config = ConfigDict(extra="allow")

        intent: str = Field(default="chat", description="scan|exploit|chat")
        target_extracted: str | None = Field(default=None, description="Target domain/IP or null")
        confidence: float = Field(default=0.5, ge=0.0, le=1.0)
        response: str = Field(default="", description="Human-readable AI response")
        command: str | None = Field(default=None, description="Suggested command or null")
        steps: list[dict[str, Any]] = Field(default_factory=list, description="Action steps")
        risks: list[str] = Field(default_factory=list, description="Identified risks")

    class LLMChatResponse(BaseModel):
        """Simple chat response validation."""

        model_config = ConfigDict(extra="allow")

        response: str = Field(default="", description="Chat response text")
        intent: str = Field(default="chat")

    class ToolCallResponse(BaseModel):
        """Function calling response validation."""

        model_config = ConfigDict(extra="allow")

        tool_name: str = Field(description="Name of the tool to call")
        arguments: dict[str, Any] = Field(default_factory=dict, description="Tool arguments")

    class ToolCallsWrapper(BaseModel):
        """Wrapper for multiple tool calls."""

        model_config = ConfigDict(extra="allow")

        tool_calls: list[ToolCallResponse] = Field(default_factory=list)

else:
    # Fallback: plain dict types when Pydantic is unavailable
    LLMAnalysisResponse = dict  # type: ignore[assignment,misc]
    LLMChatResponse = dict  # type: ignore[assignment,misc]
    ToolCallResponse = dict  # type: ignore[assignment,misc]
    ToolCallsWrapper = dict  # type: ignore[assignment,misc]


# ─────────────────────────────── Validator Engine ──────────────────────────────

# Pre-compiled regex for JSON extraction
_RE_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```")
_RE_JSON_OBJECT = re.compile(r"\{[\s\S]*\}")


def _extract_json(text: str) -> dict[str, Any] | None:
    """Extract JSON dict from raw LLM text using multiple strategies."""
    if not text:
        return None

    # Strategy 1: Direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    # Strategy 2: Code block extraction
    match = _RE_JSON_BLOCK.search(text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 3: Greedy JSON object search
    match = _RE_JSON_OBJECT.search(text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return None


class LLMOutputValidator:
    """Validates and repairs LLM outputs using Pydantic models.

    Implements auto-retry: if the first LLM response is invalid JSON,
    sends a repair prompt asking the LLM to fix its output.

    Usage::

        validator = LLMOutputValidator(llm_client=client)
        result = validator.validate_response(raw_text, LLMAnalysisResponse)
        # result is a validated dict, or None if all attempts fail.

    """

    # Repair prompt template
    _REPAIR_PROMPT = (
        "Your previous response was invalid JSON. Fix it.\n"
        "Original response:\n{raw_response}\n\n"
        "Error: {error}\n\n"
        "Respond ONLY with valid JSON matching this schema:\n{schema}"
    )

    def __init__(self, llm_client: Any = None, *, max_retries: int = 2) -> None:
        self.llm_client = llm_client
        self.max_retries = max_retries
        self._stats = {"validations": 0, "successes": 0, "repairs": 0, "failures": 0}

    def validate_response(
        self,
        raw_response: str,
        model_class: type | None = None,
    ) -> dict[str, Any] | None:
        """Validate and parse LLM response against a Pydantic model.

        Args:
            raw_response: Raw text from LLM.
            model_class: Pydantic model class to validate against.
                          Defaults to LLMAnalysisResponse.

        Returns:
            Validated dict or None if all attempts fail.

        """
        self._stats["validations"] += 1

        if model_class is None:
            model_class = LLMAnalysisResponse if _PYDANTIC_AVAILABLE else dict

        # Step 1: Extract JSON
        data = _extract_json(raw_response)
        if data is None:
            return self._attempt_repair(raw_response, model_class, "No JSON found in response")

        # Step 2: Validate with Pydantic (if available)
        if _PYDANTIC_AVAILABLE and model_class is not dict:
            return self._validate_with_pydantic(data, raw_response, model_class)

        # Fallback: dict-based validation
        self._stats["successes"] += 1
        return data

    def _validate_with_pydantic(
        self,
        data: dict[str, Any],
        raw_response: str,
        model_class: type,
    ) -> dict[str, Any] | None:
        """Validate extracted JSON against Pydantic model."""
        try:
            validated = model_class.model_validate(data)
            self._stats["successes"] += 1
            return validated.model_dump()
        except ValidationError as exc:
            logger.debug("Pydantic validation failed: %s", exc.error_count())
            return self._attempt_repair(raw_response, model_class, str(exc))
        except (AttributeError, TypeError):
            # model_class might not have model_validate (fallback dict)
            self._stats["successes"] += 1
            return data

    def _attempt_repair(
        self,
        raw_response: str,
        model_class: type,
        error_msg: str,
    ) -> dict[str, Any] | None:
        """Ask the LLM to fix its broken output."""
        if not self.llm_client:
            self._stats["failures"] += 1
            return None

        # Build schema hint for repair prompt
        schema_hint = self._get_schema_hint(model_class)

        for attempt in range(self.max_retries):
            repair_prompt = self._REPAIR_PROMPT.format(
                raw_response=raw_response[:500],
                error=error_msg[:200],
                schema=schema_hint,
            )

            try:
                fixed_response = self.llm_client.query(
                    repair_prompt,
                    "You are a JSON repair assistant. Output ONLY valid JSON.",
                    timeout=15,
                )

                data = _extract_json(fixed_response)
                if data is None:
                    error_msg = f"Repair attempt {attempt + 1} produced no JSON"
                    continue

                # Validate repaired output
                if _PYDANTIC_AVAILABLE and model_class is not dict:
                    try:
                        validated = model_class.model_validate(data)
                        self._stats["repairs"] += 1
                        self._stats["successes"] += 1
                        logger.info("LLM output repaired on attempt %d", attempt + 1)
                        return validated.model_dump()
                    except ValidationError as exc:
                        error_msg = str(exc)
                        continue
                else:
                    self._stats["repairs"] += 1
                    self._stats["successes"] += 1
                    return data

            except Exception as exc:
                logger.debug("Repair attempt %d failed: %s", attempt + 1, exc)

        self._stats["failures"] += 1
        return None

    @staticmethod
    def _get_schema_hint(model_class: type) -> str:
        """Get JSON schema description from Pydantic model."""
        if _PYDANTIC_AVAILABLE and hasattr(model_class, "model_json_schema"):
            try:
                schema = model_class.model_json_schema()
                # Return only properties for conciseness
                props = schema.get("properties", {})
                return json.dumps(props, indent=2)[:500]
            except Exception:
                logger.debug("Failed to extract JSON schema from %s", model_class.__name__, exc_info=True)
        return '{"intent": "...", "response": "...", "steps": [], "risks": []}'

    def get_stats(self) -> dict[str, int]:
        """Return validation statistics."""
        return dict(self._stats)
