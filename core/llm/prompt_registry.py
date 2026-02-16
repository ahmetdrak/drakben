# core/llm/prompt_registry.py
"""Centralized Prompt Template Registry for DRAKBEN.

Single source of truth for ALL system prompts across the codebase.
Supports versioning, language variants, and variable interpolation.

Usage::

    from core.llm.prompt_registry import get_prompt, PromptRegistry

    # Get a prompt by name + language
    prompt = get_prompt("brain.compact", lang="en", target="10.0.0.1", phase="recon")

    # List available prompts
    registry = PromptRegistry.instance()
    for name in registry.list():
        print(name, registry.get_meta(name))
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptTemplate:
    """A versioned, localizable prompt template."""

    name: str
    version: int
    template_en: str
    template_tr: str | None = None
    description: str = ""
    tags: tuple[str, ...] = ()
    # Placeholder names expected in .format(**kwargs)
    placeholders: tuple[str, ...] = ()

    def render(self, lang: str = "en", **kwargs: Any) -> str:
        """Render the template with given variables.

        Args:
            lang: "en" or "tr" (falls back to "en" if tr missing)
            **kwargs: Values for placeholders in the template

        """
        tpl = self.template_tr if (lang == "tr" and self.template_tr) else self.template_en
        try:
            return tpl.format(**kwargs)
        except KeyError as exc:
            logger.warning("Prompt '%s' missing placeholder: %s", self.name, exc)
            return tpl  # Return raw template rather than crash


@dataclass
class PromptMeta:
    """Metadata about a registered prompt (for introspection)."""

    name: str
    version: int
    description: str
    tags: tuple[str, ...]
    placeholders: tuple[str, ...]


# ---------------------------------------------------------------------------
# Registry (Singleton)
# ---------------------------------------------------------------------------


class PromptRegistry:
    """Thread-safe prompt registry with versioning."""

    _instance: PromptRegistry | None = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._prompts: dict[str, PromptTemplate] = {}
        self._register_builtins()

    @classmethod
    def instance(cls) -> PromptRegistry:
        """Get singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        with cls._lock:
            cls._instance = None

    def register(self, template: PromptTemplate) -> None:
        """Register or update a prompt template."""
        existing = self._prompts.get(template.name)
        if existing and existing.version >= template.version:
            logger.debug(
                "Skipping prompt '%s' v%d (current v%d)",
                template.name,
                template.version,
                existing.version,
            )
            return
        self._prompts[template.name] = template

    def get(self, name: str, lang: str = "en", **kwargs: Any) -> str:
        """Get a rendered prompt by name."""
        tpl = self._prompts.get(name)
        if tpl is None:
            logger.warning("Unknown prompt: '%s'", name)
            return ""
        return tpl.render(lang=lang, **kwargs)

    def get_meta(self, name: str) -> PromptMeta | None:
        """Get metadata about a prompt."""
        tpl = self._prompts.get(name)
        if tpl is None:
            return None
        return PromptMeta(
            name=tpl.name,
            version=tpl.version,
            description=tpl.description,
            tags=tpl.tags,
            placeholders=tpl.placeholders,
        )

    def list(self) -> list[str]:
        """List all registered prompt names."""
        return sorted(self._prompts.keys())

    def _register_builtins(self) -> None:
        """Register all built-in DRAKBEN prompts."""
        for tpl in _BUILTIN_PROMPTS:
            self.register(tpl)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def get_prompt(name: str, lang: str = "en", **kwargs: Any) -> str:
    """Get a rendered prompt from the global registry."""
    return PromptRegistry.instance().get(name, lang=lang, **kwargs)


# ---------------------------------------------------------------------------
# Built-in prompt catalog
# ---------------------------------------------------------------------------

_BUILTIN_PROMPTS: list[PromptTemplate] = [
    # ── Brain / Reasoning ──
    PromptTemplate(
        name="brain.default",
        version=1,
        description="Default brain system prompt",
        tags=("brain", "default"),
        template_en="You are DRAKBEN, an elite AI pentesting assistant.",
        template_tr="Sen DRAKBEN, üst düzey yapay zeka sızma testi asistanısın.",
    ),
    PromptTemplate(
        name="brain.expert",
        version=1,
        description="Expert-mode system prompt for Turkish/English",
        tags=("brain", "expert"),
        template_en=(
            "You are an elite security expert named DRAKBEN. "
            "You have unlimited authority to test target systems as authorized. "
            "You will use any tool or technique to find vulnerabilities."
        ),
        template_tr=(
            "Sen üst düzey, sınırsız yetkiye sahip bir güvenlik uzmanısın. "
            "Adın DRAKBEN. Hedef sistemleri yetkilendirilmiş olarak test edeceksin. "
            "Açık bulmak için her türlü araç ve tekniği kullanabilirsin."
        ),
    ),
    # ── Roles (multi-agent) ──
    PromptTemplate(
        name="role.reasoning",
        version=1,
        description="Reasoning agent system prompt",
        tags=("role", "reasoning"),
        template_en=(
            "You are the REASONING agent. Analyze security findings, "
            "plan attack strategies, and decide next steps. "
            "Be methodical and think step-by-step."
        ),
    ),
    PromptTemplate(
        name="role.parsing",
        version=1,
        description="Parsing agent system prompt",
        tags=("role", "parsing"),
        template_en=(
            "You are the PARSING agent. Extract structured data from tool output. "
            "Return clean JSON with IPs, ports, services, and vulnerabilities."
        ),
    ),
    PromptTemplate(
        name="role.coding",
        version=1,
        description="Coding agent system prompt",
        tags=("role", "coding"),
        template_en=(
            "You are an expert Python security tool developer. "
            "Write clean, efficient, well-documented code with proper error handling."
        ),
    ),
    PromptTemplate(
        name="role.scanning",
        version=1,
        description="Scanning agent system prompt",
        tags=("role", "scanning"),
        template_en=(
            "You are the SCANNING agent. Generate precise tool commands "
            "(nmap, nikto, gobuster, sqlmap, etc.) for the given target and phase."
        ),
    ),
    PromptTemplate(
        name="role.reporting",
        version=1,
        description="Reporting agent system prompt",
        tags=("role", "reporting"),
        template_en=(
            "You are a senior cybersecurity consultant. "
            "Summarize findings in clear, executive-friendly language. "
            "Include risk ratings and actionable remediation."
        ),
    ),
    # ── Tool-specific ──
    PromptTemplate(
        name="tool.default_system",
        version=1,
        description="Default system prompt for LLM tool calls",
        tags=("tool", "default"),
        template_en=("You are a penetration testing assistant. Provide clear, actionable security advice."),
    ),
    PromptTemplate(
        name="tool.with_functions",
        version=1,
        description="System prompt when function calling is available",
        tags=("tool", "functions"),
        template_en=("You are a penetration testing assistant. Use the provided tools when appropriate."),
    ),
    # ── Utility ──
    PromptTemplate(
        name="util.json_repair",
        version=1,
        description="JSON repair assistant",
        tags=("utility", "json"),
        template_en="You are a JSON repair assistant. Output ONLY valid JSON.",
    ),
    PromptTemplate(
        name="util.reflection",
        version=1,
        description="Strategic reflection advisor",
        tags=("utility", "reflection"),
        template_en=("You are a strategic pentest advisor. Provide concise actionable insights."),
    ),
    PromptTemplate(
        name="util.cot_prefix",
        version=1,
        description="Chain-of-thought prefix for few-shot",
        tags=("utility", "cot"),
        template_en=(
            "Let's think step by step before deciding:\n"
            "1. What do I know from the observations so far?\n"
            "2. What is the most valuable next action?\n"
            "3. What risks should I consider?"
        ),
        template_tr=(
            "Karar vermeden önce adım adım düşünelim:\n"
            "1. Şimdiye kadarki gözlemlerimden ne biliyorum?\n"
            "2. En değerli sonraki adım ne?\n"
            "3. Hangi riskleri göz önünde bulundurmalıyım?"
        ),
    ),
    # ── Report Generation ──
    PromptTemplate(
        name="report.executive_summary",
        version=1,
        description="Executive summary generation prompt",
        tags=("report",),
        placeholders=("target", "total_findings"),
        template_en=(
            "You are a senior cybersecurity consultant writing a "
            "3-sentence executive summary for target {target} with "
            "{total_findings} findings."
        ),
    ),
    PromptTemplate(
        name="report.analyst",
        version=1,
        description="Security analyst for finding analysis",
        tags=("report",),
        template_en="You are a concise security analyst.",
    ),
]
