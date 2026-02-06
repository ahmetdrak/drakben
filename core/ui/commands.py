# core/ui/commands.py
"""Centralized command registry for DRAKBEN UI.

This module provides a single source of truth for all commands,
eliminating duplication between menu.py and prompt_utils.py.
"""

from dataclasses import dataclass


@dataclass
class CommandInfo:
    """Information about a command."""

    name: str  # Command name (without /)
    description_en: str  # English description
    description_tr: str  # Turkish description
    category: str  # Category: core, pentest, util
    aliases: tuple[str, ...] = ()  # Alternative names


# ============================================================================
# CENTRAL COMMAND REGISTRY
# ============================================================================

COMMANDS: dict[str, CommandInfo] = {
    # Core commands
    "help": CommandInfo(
        name="help",
        description_en="Show help menu",
        description_tr="Yardım menüsünü göster",
        category="core",
        aliases=("?", "h"),
    ),
    "target": CommandInfo(
        name="target",
        description_en="Set target - /target <ip/domain>",
        description_tr="Hedef belirle - /target <ip/domain>",
        category="core",
    ),
    "untarget": CommandInfo(
        name="untarget",
        description_en="Clear current target",
        description_tr="Mevcut hedefi temizle",
        category="core",
    ),
    "exit": CommandInfo(
        name="exit",
        description_en="Exit DRAKBEN",
        description_tr="DRAKBEN'den çık",
        category="core",
        aliases=("quit", "q"),
    ),
    "clear": CommandInfo(
        name="clear",
        description_en="Clear screen",
        description_tr="Ekranı temizle",
        category="core",
        aliases=("cls",),
    ),
    # Language commands
    "tr": CommandInfo(
        name="tr",
        description_en="Switch to Turkish",
        description_tr="Türkçe'ye geç",
        category="core",
    ),
    "en": CommandInfo(
        name="en",
        description_en="Switch to English",
        description_tr="İngilizce'ye geç",
        category="core",
    ),
    # Pentest commands
    "scan": CommandInfo(
        name="scan",
        description_en="Start autonomous scan",
        description_tr="Otonom tarama başlat",
        category="pentest",
    ),
    "shell": CommandInfo(
        name="shell",
        description_en="Interactive shell / Execute command",
        description_tr="Interaktif kabuk / Komut çalıştır",
        category="pentest",
    ),
    "status": CommandInfo(
        name="status",
        description_en="Show system status",
        description_tr="Sistem durumunu göster",
        category="pentest",
    ),
    "report": CommandInfo(
        name="report",
        description_en="Generate pentest report",
        description_tr="Pentest raporu oluştur",
        category="pentest",
    ),
    "tools": CommandInfo(
        name="tools",
        description_en="List available tools",
        description_tr="Mevcut araçları listele",
        category="pentest",
    ),
    "research": CommandInfo(
        name="research",
        description_en="Research mode (CVE, exploits)",
        description_tr="Araştırma modu (CVE, exploit)",
        category="pentest",
    ),
    # Utility commands
    "llm": CommandInfo(
        name="llm",
        description_en="LLM configuration",
        description_tr="LLM yapılandırması",
        category="util",
    ),
    "config": CommandInfo(
        name="config",
        description_en="Show/edit configuration",
        description_tr="Yapılandırmayı göster/düzenle",
        category="util",
    ),
}

# Tool commands for completion
TOOL_COMMANDS: tuple[str, ...] = (
    "nmap",
    "nikto",
    "gobuster",
    "sqlmap",
    "hydra",
    "nuclei",
    "subfinder",
    "amass",
    "dirb",
    "wfuzz",
    "masscan",
    "ffuf",
    "whatweb",
    "wpscan",
)


def get_command_list(lang: str = "en") -> dict[str, str]:
    """Get command list with descriptions for specified language.

    Args:
        lang: Language code ('en' or 'tr')

    Returns:
        Dict of command -> description
    """
    result = {}
    for cmd_name, cmd_info in COMMANDS.items():
        desc = cmd_info.description_tr if lang == "tr" else cmd_info.description_en
        result[f"/{cmd_name}"] = desc
        # Add aliases
        for alias in cmd_info.aliases:
            result[f"/{alias}"] = desc
    return result


def get_commands_by_category(category: str, lang: str = "en") -> dict[str, str]:
    """Get commands filtered by category.

    Args:
        category: Category name (core, pentest, util)
        lang: Language code

    Returns:
        Dict of command -> description
    """
    result = {}
    for cmd_name, cmd_info in COMMANDS.items():
        if cmd_info.category == category:
            desc = cmd_info.description_tr if lang == "tr" else cmd_info.description_en
            result[f"/{cmd_name}"] = desc
    return result


def get_all_command_names() -> list[str]:
    """Get all command names including aliases (with / prefix).

    Returns:
        List of command names like ['/help', '/h', '/target', ...]
    """
    names = []
    for cmd_name, cmd_info in COMMANDS.items():
        names.append(f"/{cmd_name}")
        for alias in cmd_info.aliases:
            names.append(f"/{alias}")
    return names


def is_valid_command(cmd: str) -> bool:
    """Check if a command (with or without /) is valid.

    Args:
        cmd: Command string

    Returns:
        True if valid command
    """
    cmd_clean = cmd.lstrip("/").lower()

    # Check main commands
    if cmd_clean in COMMANDS:
        return True

    # Check aliases
    return any(cmd_clean in cmd_info.aliases for cmd_info in COMMANDS.values())


def resolve_alias(cmd: str) -> str:
    """Resolve command alias to main command name.

    Args:
        cmd: Command (with or without /)

    Returns:
        Main command name (without /)
    """
    cmd_clean = cmd.lstrip("/").lower()

    # Direct match
    if cmd_clean in COMMANDS:
        return cmd_clean

    # Alias match
    for cmd_name, cmd_info in COMMANDS.items():
        if cmd_clean in cmd_info.aliases:
            return cmd_name

    return cmd_clean
