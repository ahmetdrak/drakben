# core/execution/command_sanitizer.py
"""Command sanitization and security layer — Defence-in-Depth.

Architecture
------------
1. **Primary defence — Allowlist**: Only recognised pentesting tools are
   permitted.  Unknown binaries are rejected unless ``strict=False``.
2. **Secondary defence — Denylist**: Even allowed tools are checked against
   known-destructive patterns (e.g. ``rm -rf /``, encoded PowerShell).
3. **Injection guard**: Shell meta-characters are blocked unless the caller
   explicitly opts in with ``allow_shell=True``.
4. **Risk classification**: Each command gets a risk level that the execution
   engine can use to request human confirmation.
"""

from __future__ import annotations

import enum
import logging
import re
from typing import ClassVar

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when a security violation is detected."""


class SanitiserMode(enum.Enum):
    """Sanitiser operating mode.

    STRICT  – only allowlisted binaries may run (production default).
    PERMISSIVE – allowlist is advisory; denylist + injection guard still active.
    """

    STRICT = "strict"
    PERMISSIVE = "permissive"


class CommandSanitizer:
    """Defence-in-depth command sanitiser.

    Primary: allowlist of known-safe pentesting binaries.
    Secondary: denylist of destructive patterns.
    Tertiary: shell-injection pattern guard.
    """

    # ------------------------------------------------------------------
    # LAYER 1 — Allowlist (primary defence)
    # ------------------------------------------------------------------
    # Binaries a pentesting agent legitimately needs.  Only the first
    # token of the command (the binary name) is matched.
    ALLOWED_BINARIES: ClassVar[frozenset[str]] = frozenset(
        {
            # ── Recon / OSINT ──
            "nmap",
            "masscan",
            "rustscan",
            "unicornscan",
            "whois",
            "dig",
            "host",
            "nslookup",
            "dnsrecon",
            "dnsenum",
            "amass",
            "subfinder",
            "assetfinder",
            "findomain",
            "theHarvester",
            "recon-ng",
            "shodan",
            "whatweb",
            "wafw00f",
            "httpx",
            "httprobe",
            # ── Web Application ──
            "nikto",
            "dirb",
            "dirbuster",
            "gobuster",
            "feroxbuster",
            "ffuf",
            "wfuzz",
            "sqlmap",
            "commix",
            "xsstrike",
            "nuclei",
            "dalfox",
            "arjun",
            "paramspider",
            "burpsuite",
            "zap",
            "zaproxy",
            # ── Exploitation ──
            "msfconsole",
            "msfvenom",
            "searchsploit",
            "hydra",
            "medusa",
            "john",
            "hashcat",
            "responder",
            "impacket-smbexec",
            "impacket-wmiexec",
            "impacket-psexec",
            "crackmapexec",
            "netexec",
            "evil-winrm",
            "bloodhound",
            "sharphound",
            # ── Network / Transport ──
            "curl",
            "wget",
            "nc",
            "ncat",
            "netcat",
            "socat",
            "ssh",
            "scp",
            "sftp",
            "telnet",
            "ftp",
            "tcpdump",
            "tshark",
            "wireshark",
            "traceroute",
            "tracert",
            "ping",
            "arping",
            "hping3",
            "arp-scan",
            "ettercap",
            "bettercap",
            "mitmproxy",
            # ── Wireless ──
            "aircrack-ng",
            "airmon-ng",
            "airodump-ng",
            "aireplay-ng",
            "wifite",
            "kismet",
            "reaver",
            # ── Post-Exploitation ──
            "mimikatz",
            "lazagne",
            "seatbelt",
            "winpeas",
            "linpeas",
            "pspy",
            "chisel",
            "ligolo",
            # ── General utilities (safe) ──
            "cat",
            "head",
            "tail",
            "less",
            "more",
            "grep",
            "awk",
            "sed",
            "cut",
            "sort",
            "uniq",
            "wc",
            "tr",
            "find",
            "ls",
            "dir",
            "echo",
            "printf",
            "date",
            "id",
            "whoami",
            "uname",
            "hostname",
            "ifconfig",
            "ip",
            "netstat",
            "ss",
            "ps",
            "top",
            "file",
            "strings",
            "xxd",
            "hexdump",
            "base64",
            "openssl",
            "certutil",
            "python",
            "python3",
            "pip",
            "pip3",
            "ruby",
            "perl",
            "php",
            "node",
            "git",
            "svn",
            "docker",
            "kubectl",
            "systemctl",
            "service",
            "journalctl",
            "chmod",
            "chown",
            "mkdir",
            "cp",
            "mv",
            "touch",
            "tar",
            "gzip",
            "gunzip",
            "zip",
            "unzip",
            "mount",
            "umount",
            "df",
            "du",
            "free",
            # ── Windows equivalents ──
            "type",
            "where",
            "findstr",
            "icacls",
            "net",
            "sc",
            "wmic",
            "tasklist",
            "ipconfig",
            "nbtstat",
            "arp",
            "route",
            "pathping",
            "certutil.exe",
            "powershell",
            "cmd",
            "cmd.exe",
            "reg",
        }
    )

    # ------------------------------------------------------------------
    # LAYER 2 — Denylist (secondary defence, catches misuse of allowed tools)
    # ------------------------------------------------------------------

    # Patterns that indicate shell injection attempts
    SHELL_INJECTION_PATTERNS: ClassVar[list[str]] = [
        r";",  # Command separator
        r"\|",  # Pipe
        r"&&",  # AND operator
        r"\|\|",  # OR operator
        r"&",  # Background execution or redirect
        r"`[^`]*`",  # Command substitution with backticks
        r"\$\([^)]+\)",  # Command substitution with $()
        r">",  # Redirection
        r"<",  # Input redirection
    ]

    # Commands that are completely forbidden (substring match)
    FORBIDDEN_COMMANDS: ClassVar[list[str]] = [
        # Linux Destructive
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf ~/*",
        "mkfs",
        "dd if=/dev/zero",
        "dd if=/dev/random",
        ":(){ :|:& };:",  # Fork bomb
        "chmod -R 777 /",
        "chown -R",
        "wget -O- | sh",
        "curl | sh",
        "curl | bash",
        "wget -O- | bash",
        # Windows Destructive
        "format c:",
        "format d:",
        "rd /s /q",
        "rd /s/q",
        "del /f /s /q",
        "del /f/s/q",
        "powershell -enc",
        "powershell -encodedcommand",
        "reg delete",
        "bcdedit /delete",
        "vssadmin delete shadows",
        "wbadmin delete catalog",
        "cipher /w",
        "drop database",
        # System State
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "init 0",
        "init 6",
        # Sensitive file access
        "cat /etc/shadow",
        "cat /etc/passwd",
        "cat /etc/sudoers",
        "type C:\\Windows\\System32\\config\\SAM",
        "type C:\\Windows\\System32\\config\\SYSTEM",
    ]

    # Commands that require explicit confirmation
    HIGH_RISK_PATTERNS: ClassVar[list[str]] = [
        r"rm\s+-[rf]+",
        r"chmod\s+[0-7]{3,4}\s+/(etc|bin|usr|var|boot|sbin)",
        r"chown\s+.*?\s+/(etc|bin|usr|var|boot|sbin)",
        r"mv\s+.*?\s+/(etc|bin|usr|var|boot|sbin)",
        r">\s*/(etc|bin|usr|var|boot|sbin)",
        r"sudo\s+",
        r"su\s+",
        # Windows High Risk
        r"net\s+user\s+.*?\s+/add",
        r"net\s+localgroup\s+.*?\s+/add",
        r"taskkill\s+/f",
        r"attrib\s+\+h",
        r"sc\s+delete",
        r"reg\s+add",
    ]

    # Regex patterns for more complex forbidden commands
    FORBIDDEN_REGEX: ClassVar[list[str]] = [
        r"powershell.*-e(nc|ncod|ncoded)",
        r"format\s+[a-z]:",
        r"rd\s+/s\s+/q",
        r"del\s+/f\s+/s\s+/q",
        r"reg\s+delete\s+HKLM",
        r"net\s+user\s+.*\s+/add",
        r"rm\s+-[rf]+\s+\*",
        r"chmod\s+(?:-R\s+)?777",
        r"chown\s+(?:-R\s+)?root:root",
    ]

    # ------------------------------------------------------------------
    # Default mode — can be overridden per call or globally
    # ------------------------------------------------------------------
    _mode: ClassVar[SanitiserMode] = SanitiserMode.STRICT

    @classmethod
    def set_mode(cls, mode: SanitiserMode) -> None:
        """Set global sanitiser mode."""
        cls._mode = mode

    @classmethod
    def get_mode(cls) -> SanitiserMode:
        """Return current sanitiser mode."""
        return cls._mode

    # ------------------------------------------------------------------
    # Allowlist helpers
    # ------------------------------------------------------------------

    @classmethod
    def _extract_binary(cls, command: str) -> str:
        """Extract the binary name from a command string.

        Handles: ``sudo nmap ...``, ``/usr/bin/nmap ...``, ``python3 -m ...``
        """
        parts = command.strip().split()
        if not parts:
            return ""

        # Skip common prefixes that don't change the real binary
        idx = 0
        skip_prefixes = {"sudo", "su", "-c", "env", "nice", "timeout", "strace"}
        while idx < len(parts) and parts[idx].lower() in skip_prefixes:
            idx += 1
        if idx >= len(parts):
            return parts[0].lower()

        binary = parts[idx]
        # Strip path: /usr/bin/nmap → nmap, C:\Windows\...\cmd.exe → cmd.exe
        binary = binary.rsplit("/", maxsplit=1)[-1]
        binary = binary.rsplit("\\", maxsplit=1)[-1]
        return binary.lower()

    @classmethod
    def is_allowed_binary(cls, command: str) -> bool:
        """Check if the binary in *command* is on the allowlist."""
        binary = cls._extract_binary(command)
        if not binary:
            return False
        # Match with and without .exe suffix
        return binary in cls.ALLOWED_BINARIES or binary.removesuffix(".exe") in cls.ALLOWED_BINARIES

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    @classmethod
    def sanitize(
        cls,
        command: str,
        allow_shell: bool = False,
        *,
        mode: SanitiserMode | None = None,
    ) -> str:
        """Sanitize command for safe execution.

        Defence-in-Depth layers:
        1. Allowlist check (STRICT mode rejects unknown binaries)
        2. Denylist — forbidden substring + regex patterns
        3. Shell injection pattern guard

        Args:
            command: The command to sanitize
            allow_shell: Whether shell meta-characters are allowed
            mode: Override global mode for this call

        Returns:
            The validated command string

        Raises:
            SecurityError: If command fails any security check

        """
        effective_mode = mode or cls._mode
        command_lower: str = command.lower().strip()

        # ── Layer 1: Allowlist ──
        if effective_mode is SanitiserMode.STRICT and not cls.is_allowed_binary(command):
            binary = cls._extract_binary(command)
            msg = (
                f"Blocked: '{binary}' is not in the allowlist. "
                f"Use set_mode(SanitiserMode.PERMISSIVE) or add "
                f"the binary to ALLOWED_BINARIES."
            )
            logger.warning("Allowlist rejection: %s", binary)
            raise SecurityError(msg)

        # ── Layer 2: Denylist (substring) ──
        for forbidden in cls.FORBIDDEN_COMMANDS:
            if forbidden.lower() in command_lower:
                msg = f"Forbidden command detected: {forbidden}"
                raise SecurityError(msg)

        # ── Layer 2b: Denylist (regex) ──
        for pattern in cls.FORBIDDEN_REGEX:
            if re.search(pattern, command, re.IGNORECASE):
                msg = f"Forbidden command pattern detected: {pattern}"
                raise SecurityError(msg)

        # ── Layer 3: Shell injection guard ──
        if not allow_shell:
            for pattern in cls.SHELL_INJECTION_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    msg = f"Potential shell injection detected: pattern '{pattern}'"
                    raise SecurityError(msg)

        return command

    @classmethod
    def requires_confirmation(cls, command: str) -> tuple[bool, str]:
        """Check if command requires user confirmation before execution.

        Returns:
            Tuple of (requires_confirmation: bool, reason: str)

        """
        command_lower: str = command.lower().strip()

        # Check for high-risk patterns
        for pattern in cls.HIGH_RISK_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return True, f"High-risk pattern detected: {pattern}"

        # Check for sudo/su
        if "sudo " in command_lower or command_lower.startswith("su "):
            return True, "Elevated privilege command"

        # Check for network operations that could be dangerous
        if any(x in command_lower for x in ["curl", "wget", "nc ", "netcat"]):
            if any(y in command_lower for y in ["| sh", "| bash", "-O-", "exec"]):
                return True, "Network command with execution"

        # Check for file modifications in sensitive areas
        if any(x in command for x in ["/etc/", "/usr/", "/bin/", "/sbin/"]):
            if any(y in command_lower for y in ["rm ", "mv ", "cp ", "> ", ">>"]):
                return True, "File modification in system directory"

        return False, ""

    @classmethod
    def is_high_risk(cls, command: str) -> bool:
        """Check if command is high-risk and needs confirmation."""
        return any(re.search(pattern, command, re.IGNORECASE) for pattern in cls.HIGH_RISK_PATTERNS)

    @classmethod
    def get_risk_level(cls, command: str) -> str:
        """Get risk level of a command.

        Returns:
            'low', 'medium', 'high', or 'critical'

        """
        command_lower: str = command.lower()

        # Check for forbidden (critical)
        for forbidden in cls.FORBIDDEN_COMMANDS:
            if forbidden.lower() in command_lower:
                return "critical"

        # Check for high-risk patterns
        if cls.is_high_risk(command):
            return "high"

        # Check for medium-risk commands
        medium_risk: list[str] = [
            "curl",
            "wget",
            "nc",
            "netcat",
            "ncat",
            "python -c",
            "perl -e",
            "ruby -e",
        ]
        if any(cmd in command_lower for cmd in medium_risk):
            return "medium"

        return "low"
