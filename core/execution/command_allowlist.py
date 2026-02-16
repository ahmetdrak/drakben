"""Centralized command allowlist for DRAKBEN.

Replaces the bypassable denylist with a strict allowlist:
only known pentest-tool binaries may be executed via shell.

Three-layer defence:
    1. ``ALLOWED_BINARIES``  — primary binary must be in this set.
    2. ``NEVER_ALLOWED``     — always blocked, even if somehow added.
    3. ``_INJECTION_RE``     — regex catches injection patterns.
"""

from __future__ import annotations

import logging
import re
import shlex

logger = logging.getLogger(__name__)

# ── Tier 1: Core pentest tools (always allowed) ─────────────────────
ALLOWED_BINARIES: frozenset[str] = frozenset({
    # Recon
    "nmap", "gobuster", "ffuf", "amass", "subfinder",
    "feroxbuster", "whatweb", "enum4linux", "bloodhound-python",
    "masscan", "theharvester", "dig", "host", "whois", "dnsrecon",
    # Vuln scanning
    "nikto", "nuclei", "wpscan", "testssl.sh", "sslscan",
    # Exploitation
    "sqlmap", "hydra", "crackmapexec", "responder",
    "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
    "msfconsole", "msfvenom",
    # Post-exploit
    "mimikatz", "rubeus", "sharphound",
    # Utility (needed by tool templates)
    "tee", "grep", "cat", "head", "tail", "wc", "sort", "uniq",
    "curl", "wget",
    # System detection
    "which", "where", "wsl",
    # Network
    "ping", "traceroute", "tracert", "arp", "netstat", "ss",
})

# ── Tier 2: Dangerous binaries (never allowed) ──────────────────────
NEVER_ALLOWED: frozenset[str] = frozenset({
    "rm", "rmdir", "mkfs", "dd", "fdisk", "parted",
    "chmod", "chown", "chgrp",
    "useradd", "userdel", "passwd",
    "iptables", "ip6tables", "ufw",
    "systemctl", "service",
    "reboot", "shutdown", "halt", "poweroff", "init",
    "bash", "sh", "zsh", "fish", "csh", "dash",
    "python", "python3", "perl", "ruby", "node", "php",
    "nc", "ncat", "socat",
    "eval", "exec",
})

# ── Tier 3: Injection patterns (defence in depth) ───────────────────
_INJECTION_RE = re.compile(
    r"\$\(|`"  # command substitution
    r"|\$\{?IFS\}?"  # IFS tricks
    r"|;\s*rm\b"  # chained rm
    r"|\x00"  # null byte
    r"|<%|%>"  # template injection
    r"|\|\s*(?:bash|sh|python[23]?|perl|ruby|php)\b",  # pipe to interpreter
    re.IGNORECASE,
)


class CommandValidationError(Exception):
    """Raised when a command fails allowlist validation."""


def validate_command(command: str) -> None:
    """Validate *command* against the allowlist.

    Args:
        command: The shell command string to validate.

    Raises:
        CommandValidationError: If the command is blocked.
    """
    stripped = command.strip()
    if not stripped:
        msg = "Empty command"
        raise CommandValidationError(msg)

    # Extract primary binary (first token)
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        tokens = stripped.split()

    primary = (
        tokens[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if tokens
        else ""
    )

    # 1. Check NEVER_ALLOWED
    if primary in NEVER_ALLOWED:
        msg = f"Binary '{primary}' is explicitly blocked"
        raise CommandValidationError(msg)

    # 2. Check ALLOWED_BINARIES
    if primary not in ALLOWED_BINARIES:
        msg = (
            f"Binary '{primary}' is not in the allowlist. "
            f"Add it to ALLOWED_BINARIES if it's a legitimate pentest tool."
        )
        raise CommandValidationError(msg)

    # 3. Secondary: regex patterns
    match = _INJECTION_RE.search(stripped)
    if match:
        msg = f"Suspicious pattern detected: {match.group()!r}"
        raise CommandValidationError(msg)

    logger.debug("Command validated: %s", primary)


def is_command_allowed(command: str) -> tuple[bool, str]:
    """Non-raising variant.

    Args:
        command: The shell command string to validate.

    Returns:
        Tuple of (allowed, error_message). error_message is empty
        when the command is allowed.
    """
    try:
        validate_command(command)
    except CommandValidationError as exc:
        return False, str(exc)
    return True, ""
