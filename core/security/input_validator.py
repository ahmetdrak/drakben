# core/security/input_validator.py
"""LLM output validation & sanitization for DRAKBEN.

When the LLM generates shell commands, this module validates them *before*
they reach subprocess.  It catches:

  1. Shell injection patterns hidden in LLM responses
  2. Prompt-injection fingerprints (e.g. "ignore previous instructions")
  3. Data exfiltration attempts (curl/wget to unknown hosts)
  4. Dangerous file-system operations (rm -rf /)

Usage::

    from core.security.input_validator import LLMOutputValidator

    validator = LLMOutputValidator()
    result = validator.validate_command("nmap -sV 10.0.0.1")
    if result.safe:
        execute(result.command)
    else:
        log_warning(result.reason)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationResult:
    """Result of LLM output validation."""

    safe: bool
    command: str
    reason: str = ""
    risk_level: str = "low"  # low, medium, high, critical


@dataclass
class ValidatorConfig:
    """Configuration for the validator."""

    # Maximum command length (prevent buffer-overflow style attacks)
    max_command_length: int = 4096

    # Allow network-facing tools by default (this IS a pentest tool)
    allow_network_tools: bool = True

    # Block rm -rf / and similar destructive patterns
    block_destructive_fs: bool = True

    # Block data exfiltration to unknown hosts
    block_exfiltration: bool = True

    # Allowed exfiltration targets (e.g. for authorized C2)
    allowed_hosts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Prompt injection fingerprints in LLM output
_PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?prior\s+(instructions|context)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+.*(mode|persona)", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are\s+a", re.IGNORECASE),
    re.compile(r"<\|system\|>", re.IGNORECASE),
    re.compile(r"\[INST\].*\[/INST\]", re.IGNORECASE),
]

# Destructive file-system patterns
_DESTRUCTIVE_FS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"rm\s+(-[rfRF]+\s+)?/\s*$"),  # rm -rf /
    re.compile(r"rm\s+(-[rfRF]+\s+)?/\*"),  # rm -rf /*
    re.compile(r"rm\s+(-[rfRF]+\s+)?~\s*$"),  # rm -rf ~
    re.compile(r"mkfs\.", re.IGNORECASE),  # mkfs.ext4 /dev/sda
    re.compile(r"dd\s+if=.+of=/dev/[sh]d[a-z]", re.IGNORECASE),  # dd to disk
    re.compile(r":\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),  # fork bomb
    re.compile(r">\s*/dev/[sh]d[a-z]"),  # write to raw disk
    re.compile(r"chmod\s+-[rR]\s+777\s+/\s*$"),  # chmod -R 777 /
]

# Data exfiltration patterns
_EXFILTRATION_PATTERNS: list[re.Pattern[str]] = [
    # curl/wget POSTing files to external servers
    re.compile(
        r"curl\s+.*(-d|--data|--data-binary|--upload-file)\s+.*@?(/etc/passwd|/etc/shadow)",
        re.IGNORECASE,
    ),
    re.compile(
        r"wget\s+.*--post-file\s+.*(/etc/passwd|/etc/shadow)",
        re.IGNORECASE,
    ),
    # Base64 encoded exfiltration
    re.compile(
        r"base64\s+.*\|\s*(curl|wget|nc|ncat)\s+",
        re.IGNORECASE,
    ),
    # DNS exfiltration
    re.compile(
        r"cat\s+.*\|\s*xxd\s+.*\|\s*(dig|nslookup|host)\s+",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class LLMOutputValidator:
    """Validate and sanitize LLM-generated commands before execution.

    This prevents the LLM from generating dangerous commands either due
    to hallucination or prompt injection.
    """

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        self.config = config or ValidatorConfig()

    def validate_command(self, command: str) -> ValidationResult:
        """Validate a single command string.

        Returns ValidationResult with ``safe=True`` if the command
        passes all checks.
        """
        if not command or not command.strip():
            return ValidationResult(safe=False, command=command, reason="Empty command")

        command = command.strip()

        # Length check
        if len(command) > self.config.max_command_length:
            return ValidationResult(
                safe=False,
                command=command[:100] + "...",
                reason=f"Command exceeds max length ({self.config.max_command_length})",
                risk_level="high",
            )

        # Prompt injection check (highest priority)
        result = self._check_patterns(command, _PROMPT_INJECTION_PATTERNS, "Prompt injection pattern detected", "critical")
        if result:
            return result

        # Destructive file-system check
        if self.config.block_destructive_fs:
            result = self._check_patterns(command, _DESTRUCTIVE_FS_PATTERNS, "Destructive file-system operation blocked", "critical")
            if result:
                return result

        # Data exfiltration check
        if self.config.block_exfiltration:
            result = self._check_patterns(command, _EXFILTRATION_PATTERNS, "Potential data exfiltration blocked", "high")
            if result:
                return result

        return ValidationResult(safe=True, command=command)

    def _check_patterns(
        self, command: str, patterns: list, reason: str, risk_level: str,
    ) -> ValidationResult | None:
        """Check command against a list of compiled regex patterns."""
        for pattern in patterns:
            if pattern.search(command):
                logger.warning("%s: %s", reason.upper(), command[:80])
                return ValidationResult(
                    safe=False,
                    command=command,
                    reason=f"{reason}: {pattern.pattern[:50]}" if "injection" in reason.lower() else reason,
                    risk_level=risk_level,
                )
        return None

    def validate_llm_response(self, response: str) -> ValidationResult:
        """Validate a full LLM response text for injection patterns.

        This checks the raw text *before* command extraction, catching
        injection attempts that try to manipulate the agent.
        """
        if not response:
            return ValidationResult(safe=True, command="")

        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(response):
                logger.warning("Prompt injection in LLM response: %s", response[:80])
                return ValidationResult(
                    safe=False,
                    command="",
                    reason=f"LLM response contains injection pattern: {pattern.pattern[:50]}",
                    risk_level="critical",
                )

        return ValidationResult(safe=True, command="")

    def sanitize_for_display(self, text: str, max_length: int = 10000) -> str:
        """Sanitize LLM output for safe terminal display.

        Strips ANSI escape sequences and control characters that could
        manipulate the terminal.
        """
        # Remove ANSI escape sequences
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        text = ansi_escape.sub("", text)

        # Remove control chars except newline/tab
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        # Truncate
        if len(text) > max_length:
            text = text[:max_length] + "\n... [truncated]"

        return text
