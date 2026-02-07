# tests/test_llm_utils.py
"""Tests for core/llm_utils.py — parse_llm_json_response & format_llm_prompt."""


from core.llm_utils import format_llm_prompt, parse_llm_json_response

# ── parse_llm_json_response ───────────────────────────────────

class TestParseLlmJsonResponse:
    """Tests for all three parsing strategies + edge cases."""

    # Strategy 1: Direct JSON
    def test_direct_json(self) -> None:
        result = parse_llm_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_direct_json_nested(self) -> None:
        result = parse_llm_json_response('{"a": {"b": [1, 2]}}')
        assert result is not None
        assert result["a"]["b"] == [1, 2]

    # Strategy 2: Markdown code blocks
    def test_json_in_code_block(self) -> None:
        response = 'Here is the result:\n```json\n{"tool": "nmap"}\n```'
        result = parse_llm_json_response(response)
        assert result == {"tool": "nmap"}

    def test_json_in_code_block_no_lang(self) -> None:
        response = 'Result:\n```\n{"x": 1}\n```'
        result = parse_llm_json_response(response)
        assert result == {"x": 1}

    # Strategy 3: Regex extraction
    def test_json_embedded_in_text(self) -> None:
        response = 'The answer is {"action": "scan", "port": 80} and that is it.'
        result = parse_llm_json_response(response)
        assert result is not None
        assert result["action"] == "scan"

    # Edge cases
    def test_empty_string(self) -> None:
        assert parse_llm_json_response("") is None

    def test_none_equivalent(self) -> None:
        # Empty string check
        assert parse_llm_json_response("") is None

    def test_no_json_at_all(self) -> None:
        assert parse_llm_json_response("just plain text, no JSON") is None

    def test_invalid_json_everywhere(self) -> None:
        assert parse_llm_json_response("{invalid: json, no quotes}") is None

    def test_array_not_object(self) -> None:
        # parse_llm_json_response is designed for dicts; arrays may or may not pass
        result = parse_llm_json_response('[1, 2, 3]')
        # Strategy 1 returns the list (which is valid JSON)
        assert result == [1, 2, 3] or result is None

    def test_whitespace_json(self) -> None:
        result = parse_llm_json_response('  {  "key" : "val"  }  ')
        assert result == {"key": "val"}


# ── format_llm_prompt ─────────────────────────────────────────

class TestFormatLlmPrompt:
    """Tests for prompt formatting."""

    def test_basic(self) -> None:
        result = format_llm_prompt("You are a helper.", "What is 2+2?")
        assert "You are a helper." in result
        assert "What is 2+2?" in result

    def test_json_instruction(self) -> None:
        result = format_llm_prompt("sys", "usr", json_response=True)
        assert "JSON" in result

    def test_no_json_instruction(self) -> None:
        result = format_llm_prompt("sys", "usr", json_response=False)
        assert "JSON" not in result

    def test_turkish_language(self) -> None:
        result = format_llm_prompt("sys", "usr", language="tr")
        assert "Turkish" in result or "Türkçe" in result

    def test_english_no_language_instruction(self) -> None:
        result = format_llm_prompt("sys", "usr", language="en")
        assert "Turkish" not in result

    def test_combined_json_and_turkish(self) -> None:
        result = format_llm_prompt(
            "sys", "usr", json_response=True, language="tr",
        )
        assert "JSON" in result
        assert "Türkçe" in result
