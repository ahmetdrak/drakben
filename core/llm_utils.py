"""LLM utility functions - shared across modules."""

import json
import re


def parse_llm_json_response(response: str) -> dict | None:
    """
    Parse JSON from LLM response with fallback strategies.

    Strategies:
    1. Direct JSON parse
    2. Extract JSON from markdown code blocks
    3. Regex search for JSON object

    Args:
        response: Raw LLM response string

    Returns:
        Parsed dict or None if parsing failed
    """
    if not response:
        return None

    # Strategy 1: Direct JSON parse
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from markdown code blocks
    # Pattern: ```json\n{...}\n```
    code_block_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", response)
    if code_block_match:
        try:
            return json.loads(code_block_match.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 3: Regex search for JSON object anywhere
    json_match = re.search(r"\{[\s\S]*\}", response)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    # All strategies failed
    return None


def format_llm_prompt(
    system_msg: str, user_msg: str, json_response: bool = False, language: str = "en"
) -> str:
    """
    Format a standardized LLM prompt with language instructions.

    Args:
        system_msg: System/context message
        user_msg: User query/instruction
        json_response: If True, adds JSON formatting instruction
        language: Output language ('en' or 'tr')

    Returns:
        Formatted prompt string
    """
    prompt = f"{system_msg}\n\n{user_msg}"

    if json_response:
        prompt += (
            "\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no explanations."
        )

    # Language instruction
    if language == "tr":
        prompt += "\n\nThink in English internally, but respond in Turkish (Türkçe)."

    return prompt
