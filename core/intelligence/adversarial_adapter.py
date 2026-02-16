# core/intelligence/adversarial_adapter.py
# DRAKBEN — Adversarial Adaptation Engine
#
# Problem: When a WAF blocks requests, IDS detects scans, or tools get
#          connection resets — the agent just retries the same way.
# Solution: Detect defense signatures in tool output and automatically
#          switch to evasion techniques.
#
# Detects:
#   - WAF responses (403, "blocked", CloudFlare challenges)
#   - IDS/IPS (connection resets, timeouts, rate limiting)
#   - Honeypots (too many open ports, fake banners)
#   - Anti-brute-force (lockouts, CAPTCHAs)
#
# Adapts by:
#   - Switching to stealth timing (T1/T2 for nmap)
#   - Fragmenting packets
#   - Rotating source ports
#   - Using WAF bypass payloads
#   - Adding delays between requests

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class DefenseType(Enum):
    """Types of active defense detected."""

    WAF = "waf"
    IDS = "ids"
    RATE_LIMIT = "rate_limit"
    HONEYPOT = "honeypot"
    ANTI_BRUTEFORCE = "anti_bruteforce"
    FIREWALL = "firewall"
    NONE = "none"


class StealthLevel(Enum):
    """Stealth escalation levels."""

    NORMAL = 0  # Default — no evasion
    LOW = 1  # Slow down, add random delays
    MEDIUM = 2  # Fragmentation, source port rotation
    HIGH = 3  # Full evasion: decoy, timing, encoding
    PARANOID = 4  # Maximum stealth: single packet at a time


@dataclass
class DefenseSignature:
    """A detected defense mechanism."""

    defense_type: DefenseType
    confidence: float = 0.0  # 0-1
    evidence: list[str] = field(default_factory=list)
    product: str = ""  # "CloudFlare", "ModSecurity", etc.
    first_seen: float = field(default_factory=time.time)
    hit_count: int = 1


@dataclass
class EvasionStrategy:
    """A specific evasion technique to apply."""

    name: str
    description: str
    tool_modifications: dict[str, Any] = field(default_factory=dict)
    delay_seconds: float = 0.0
    priority: int = 0  # Higher = apply first


class AdversarialAdapter:
    """Detects active defenses and adapts scanning strategy.

    Usage::

        adapter = AdversarialAdapter()
        adapter.analyze_output("nmap", nmap_output)

        if adapter.is_defended():
            evasions = adapter.get_evasion_strategy("nmap")
            # Apply evasions to next scan

    """

    # ── Detection patterns ──

    _WAF_PATTERNS = [
        (re.compile(r"cloudflare", re.IGNORECASE), "CloudFlare"),
        (re.compile(r"akamai", re.IGNORECASE), "Akamai"),
        (re.compile(r"imperva|incapsula", re.IGNORECASE), "Imperva"),
        (re.compile(r"mod_security|modsecurity", re.IGNORECASE), "ModSecurity"),
        (re.compile(r"f5\s*big-?ip", re.IGNORECASE), "F5 BIG-IP"),
        (re.compile(r"aws\s*waf|amazon", re.IGNORECASE), "AWS WAF"),
        (re.compile(r"sucuri", re.IGNORECASE), "Sucuri"),
        (re.compile(r"barracuda", re.IGNORECASE), "Barracuda"),
        (re.compile(r"fortiweb|fortigate", re.IGNORECASE), "Fortinet"),
        (re.compile(r"palo\s*alto", re.IGNORECASE), "Palo Alto"),
    ]

    _BLOCKED_PATTERNS = [
        re.compile(r"403\s*forbidden", re.IGNORECASE),
        re.compile(r"access\s*denied", re.IGNORECASE),
        re.compile(r"blocked\s*by", re.IGNORECASE),
        re.compile(r"request\s*blocked", re.IGNORECASE),
        re.compile(r"security\s*policy", re.IGNORECASE),
        re.compile(r"please\s*complete\s*the\s*captcha", re.IGNORECASE),
        re.compile(r"challenge-form", re.IGNORECASE),
        re.compile(r"rate\s*limit", re.IGNORECASE),
    ]

    _IDS_PATTERNS = [
        re.compile(r"connection\s*reset", re.IGNORECASE),
        re.compile(r"filtered", re.IGNORECASE),
        re.compile(r"host\s*seems?\s*down", re.IGNORECASE),
        re.compile(r"no\s*route\s*to\s*host", re.IGNORECASE),
        re.compile(r"timed?\s*out", re.IGNORECASE),
        re.compile(r"tcp\s*reset", re.IGNORECASE),
    ]

    _HONEYPOT_INDICATORS = [
        "too_many_open_ports",  # >100 ports open suspiciously
        "fake_banners",  # Mixing incompatible services
        "instant_response",  # Zero-latency responses
    ]

    def __init__(self) -> None:
        self._detections: dict[DefenseType, DefenseSignature] = {}
        self._stealth_level = StealthLevel.NORMAL
        self._tool_history: list[dict[str, Any]] = []
        self._consecutive_blocks = 0
        self._stats = {
            "outputs_analyzed": 0,
            "defenses_detected": 0,
            "evasions_applied": 0,
            "stealth_escalations": 0,
        }

    # ─────────────────────── Public API ───────────────────────

    def analyze_output(
        self,
        tool_name: str,
        output: str,
        *,
        exit_code: int | None = None,
    ) -> list[DefenseSignature]:
        """Analyze tool output for defense signatures.

        Args:
            tool_name: Tool that produced the output.
            output: Raw stdout from the tool.
            exit_code: Tool exit code (non-zero may indicate blocking).

        Returns:
            List of new defense signatures detected.

        """
        self._stats["outputs_analyzed"] += 1
        new_detections: list[DefenseSignature] = []

        # WAF detection
        waf = self._detect_waf(output)
        if waf:
            new_detections.append(waf)

        # IDS/Firewall detection
        ids = self._detect_ids(output, exit_code)
        if ids:
            new_detections.append(ids)

        # Rate limiting detection
        rate = self._detect_rate_limit(output)
        if rate:
            new_detections.append(rate)

        # Honeypot detection
        honeypot = self._detect_honeypot(output, tool_name)
        if honeypot:
            new_detections.append(honeypot)

        # Anti-brute-force detection
        anti_bf = self._detect_anti_bruteforce(output)
        if anti_bf:
            new_detections.append(anti_bf)

        # Track consecutive blocks for stealth escalation
        if new_detections:
            self._consecutive_blocks += 1
            self._stats["defenses_detected"] += len(new_detections)
            self._auto_escalate_stealth()
        else:
            self._consecutive_blocks = max(0, self._consecutive_blocks - 1)

        # Record in history
        self._tool_history.append(
            {
                "tool": tool_name,
                "blocked": bool(new_detections),
                "defenses": [d.defense_type.value for d in new_detections],
                "timestamp": time.time(),
            }
        )
        if len(self._tool_history) > 100:
            self._tool_history = self._tool_history[-100:]

        return new_detections

    def is_defended(self) -> bool:
        """Check if any active defense has been detected."""
        return len(self._detections) > 0

    def get_stealth_level(self) -> StealthLevel:
        """Get current stealth level."""
        return self._stealth_level

    def get_evasion_strategy(self, tool_name: str) -> list[EvasionStrategy]:
        """Get specific evasion strategies for a tool.

        Args:
            tool_name: Tool to generate evasions for.

        Returns:
            List of EvasionStrategy objects to apply.

        """
        strategies: list[EvasionStrategy] = []
        tool_lower = tool_name.lower()

        for defense_type, sig in self._detections.items():
            new_strats = self._generate_evasion(defense_type, sig, tool_lower)
            strategies.extend(new_strats)

        # Add stealth-level-based modifications
        strategies.extend(self._stealth_level_strategies(tool_lower))

        # Sort by priority
        strategies.sort(key=lambda s: -s.priority)
        self._stats["evasions_applied"] += len(strategies)
        return strategies

    def get_tool_args_modifier(self, tool_name: str) -> dict[str, Any]:
        """Get combined tool argument modifications for evasion.

        Returns a dict of extra args/params to apply to the tool.
        """
        strategies = self.get_evasion_strategy(tool_name)
        combined: dict[str, Any] = {}
        max_delay = 0.0

        for strat in strategies:
            combined.update(strat.tool_modifications)
            max_delay = max(max_delay, strat.delay_seconds)

        if max_delay > 0:
            combined["_delay_seconds"] = max_delay

        return combined

    def get_defense_summary(self) -> str:
        """Get a human-readable summary of detected defenses."""
        if not self._detections:
            return "No active defenses detected."

        lines = [f"⚔️ Active Defenses (Stealth Level: {self._stealth_level.name}):"]
        for dtype, sig in self._detections.items():
            product = f" ({sig.product})" if sig.product else ""
            lines.append(
                f"  - {dtype.value.upper()}{product}: confidence={sig.confidence:.0%}, hits={sig.hit_count}",
            )
            if sig.evidence:
                lines.append(f"    Evidence: {sig.evidence[0][:80]}")

        return "\n".join(lines)

    def get_stats(self) -> dict[str, Any]:
        """Return adapter statistics."""
        return {
            **self._stats,
            "stealth_level": self._stealth_level.name,
            "active_defenses": len(self._detections),
            "consecutive_blocks": self._consecutive_blocks,
        }

    # ─────────────────── Detection Methods ───────────────────

    def _detect_waf(self, output: str) -> DefenseSignature | None:
        """Detect WAF from tool output."""
        product = ""
        evidence: list[str] = []

        # Named WAF detection
        for pattern, waf_name in self._WAF_PATTERNS:
            if pattern.search(output):
                product = waf_name
                evidence.append(f"WAF signature: {waf_name}")

        # Generic blocking patterns
        for pattern in self._BLOCKED_PATTERNS:
            match = pattern.search(output)
            if match:
                evidence.append(match.group(0)[:80])

        if not evidence:
            return None

        sig = DefenseSignature(
            defense_type=DefenseType.WAF,
            confidence=min(1.0, 0.3 * len(evidence)),
            evidence=evidence[:5],
            product=product,
        )

        # Merge with existing
        existing = self._detections.get(DefenseType.WAF)
        if existing:
            existing.hit_count += 1
            existing.confidence = min(1.0, existing.confidence + 0.1)
            for e in evidence:
                if e not in existing.evidence:
                    existing.evidence.append(e)
            return existing

        self._detections[DefenseType.WAF] = sig
        return sig

    def _detect_ids(
        self,
        output: str,
        exit_code: int | None,
    ) -> DefenseSignature | None:
        """Detect IDS/IPS/firewall from tool output."""
        evidence: list[str] = []

        for pattern in self._IDS_PATTERNS:
            matches = pattern.findall(output)
            if matches:
                evidence.append(f"{pattern.pattern}: {len(matches)} occurrences")

        # High percentage of filtered ports
        filtered_count = output.lower().count("filtered")
        total_ports = output.count("/tcp") + output.count("/udp")
        if total_ports > 5 and filtered_count > total_ports * 0.7:
            evidence.append(f"{filtered_count}/{total_ports} ports filtered — likely firewall")

        # Non-zero exit with timeout indicators
        if exit_code and exit_code != 0 and "timeout" in output.lower():
            evidence.append(f"Tool exit code {exit_code} with timeout")

        if not evidence:
            return None

        sig = DefenseSignature(
            defense_type=DefenseType.IDS,
            confidence=min(1.0, 0.25 * len(evidence)),
            evidence=evidence[:5],
        )

        existing = self._detections.get(DefenseType.IDS)
        if existing:
            existing.hit_count += 1
            existing.confidence = min(1.0, existing.confidence + 0.1)
            return existing

        self._detections[DefenseType.IDS] = sig
        return sig

    def _detect_rate_limit(self, output: str) -> DefenseSignature | None:
        """Detect rate limiting."""
        evidence: list[str] = []

        rate_patterns = [
            re.compile(r"rate\s*limit", re.IGNORECASE),
            re.compile(r"too\s*many\s*requests", re.IGNORECASE),
            re.compile(r"429", re.IGNORECASE),
            re.compile(r"slow\s*down", re.IGNORECASE),
            re.compile(r"throttl", re.IGNORECASE),
        ]

        for pattern in rate_patterns:
            if pattern.search(output):
                evidence.append(f"Rate limit indicator: {pattern.pattern}")

        if not evidence:
            return None

        sig = DefenseSignature(
            defense_type=DefenseType.RATE_LIMIT,
            confidence=min(1.0, 0.4 * len(evidence)),
            evidence=evidence[:5],
        )

        existing = self._detections.get(DefenseType.RATE_LIMIT)
        if existing:
            existing.hit_count += 1
            existing.confidence = min(1.0, existing.confidence + 0.15)
            return existing

        self._detections[DefenseType.RATE_LIMIT] = sig
        return sig

    def _detect_honeypot(self, output: str, tool_name: str) -> DefenseSignature | None:
        """Detect honeypot indicators."""
        evidence: list[str] = []

        # Too many open ports (suspicious)
        if "nmap" in tool_name.lower():
            open_ports = re.findall(r"\d+/tcp\s+open", output)
            if len(open_ports) > 100:
                evidence.append(f"Suspiciously many open ports: {len(open_ports)}")

            # Incompatible service mix (Windows + Linux services together)
            services_lower = output.lower()
            has_windows = any(s in services_lower for s in ("microsoft-ds", "ms-wbt-server", "msrpc"))
            has_linux = any(s in services_lower for s in ("openssh", "vsftpd", "proftpd"))
            if has_windows and has_linux and len(open_ports) > 20:
                evidence.append("Mixed Windows+Linux services with many ports — possible honeypot")

        if not evidence:
            return None

        sig = DefenseSignature(
            defense_type=DefenseType.HONEYPOT,
            confidence=min(1.0, 0.4 * len(evidence)),
            evidence=evidence,
        )

        existing = self._detections.get(DefenseType.HONEYPOT)
        if existing:
            existing.hit_count += 1
            return existing

        self._detections[DefenseType.HONEYPOT] = sig
        return sig

    def _detect_anti_bruteforce(self, output: str) -> DefenseSignature | None:
        """Detect anti-brute-force mechanisms."""
        evidence: list[str] = []

        patterns = [
            re.compile(r"account\s*lock", re.IGNORECASE),
            re.compile(r"captcha", re.IGNORECASE),
            re.compile(r"too\s*many\s*(failed|login)", re.IGNORECASE),
            re.compile(r"temporarily\s*blocked", re.IGNORECASE),
            re.compile(r"wait\s*\d+\s*seconds?", re.IGNORECASE),
        ]

        for pattern in patterns:
            if pattern.search(output):
                evidence.append(f"Anti-brute-force: {pattern.pattern}")

        if not evidence:
            return None

        sig = DefenseSignature(
            defense_type=DefenseType.ANTI_BRUTEFORCE,
            confidence=min(1.0, 0.5 * len(evidence)),
            evidence=evidence[:5],
        )

        existing = self._detections.get(DefenseType.ANTI_BRUTEFORCE)
        if existing:
            existing.hit_count += 1
            return existing

        self._detections[DefenseType.ANTI_BRUTEFORCE] = sig
        return sig

    # ─────────────────── Evasion Generation ───────────────────

    def _auto_escalate_stealth(self) -> None:
        """Automatically escalate stealth level based on detection count."""
        if self._consecutive_blocks >= 5:
            new_level = StealthLevel.PARANOID
        elif self._consecutive_blocks >= 3:
            new_level = StealthLevel.HIGH
        elif self._consecutive_blocks >= 2:
            new_level = StealthLevel.MEDIUM
        elif self._consecutive_blocks >= 1:
            new_level = StealthLevel.LOW
        else:
            new_level = StealthLevel.NORMAL

        if new_level.value > self._stealth_level.value:
            logger.info(
                "Stealth escalation: %s → %s (consecutive blocks: %d)",
                self._stealth_level.name,
                new_level.name,
                self._consecutive_blocks,
            )
            self._stealth_level = new_level
            self._stats["stealth_escalations"] += 1

    def _generate_evasion(
        self,
        defense_type: DefenseType,
        sig: DefenseSignature,
        tool: str,
    ) -> list[EvasionStrategy]:
        """Generate evasion strategies for a specific defense type."""
        strategies: list[EvasionStrategy] = []

        if defense_type == DefenseType.WAF:
            strategies.extend(self._waf_evasion(sig, tool))
        elif defense_type == DefenseType.IDS:
            strategies.extend(self._ids_evasion(sig, tool))
        elif defense_type == DefenseType.RATE_LIMIT:
            strategies.extend(self._rate_limit_evasion(tool))
        elif defense_type == DefenseType.HONEYPOT:
            strategies.append(
                EvasionStrategy(
                    name="honeypot_caution",
                    description="Possible honeypot detected — limit interaction depth",
                    tool_modifications={"_max_depth": 2},
                    priority=10,
                )
            )
        elif defense_type == DefenseType.ANTI_BRUTEFORCE:
            strategies.extend(self._anti_bf_evasion(tool))

        return strategies

    def _waf_evasion(self, sig: DefenseSignature, tool: str) -> list[EvasionStrategy]:
        """WAF evasion strategies."""
        strategies = []

        if "nmap" in tool:
            strategies.append(
                EvasionStrategy(
                    name="nmap_fragment",
                    description="Fragment packets to bypass WAF inspection",
                    tool_modifications={"extra_args": "-f --mtu 24"},
                    priority=8,
                )
            )

        if tool in ("nikto", "gobuster", "ffuf", "sqlmap"):
            strategies.append(
                EvasionStrategy(
                    name="user_agent_rotate",
                    description="Rotate User-Agent to evade WAF fingerprinting",
                    tool_modifications={"_rotate_user_agent": True},
                    delay_seconds=1.5,
                    priority=7,
                )
            )

        if "sqlmap" in tool:
            tamper_scripts = {
                "ModSecurity": "space2comment,between,randomcase",
                "CloudFlare": "charencode,space2plus,between",
                "AWS WAF": "space2randomblank,charencode",
                "Imperva": "space2comment,randomcase,charencode",
            }
            tamper = tamper_scripts.get(sig.product, "space2comment,randomcase")
            strategies.append(
                EvasionStrategy(
                    name="sqlmap_tamper",
                    description=f"SQLMap tamper scripts for {sig.product or 'generic WAF'}",
                    tool_modifications={"extra_args": f"--tamper={tamper} --random-agent"},
                    delay_seconds=2.0,
                    priority=9,
                )
            )

        if "nuclei" in tool:
            strategies.append(
                EvasionStrategy(
                    name="nuclei_rate_limit",
                    description="Reduce nuclei request rate for WAF bypass",
                    tool_modifications={"extra_args": "-rl 10 -c 2"},
                    delay_seconds=1.0,
                    priority=6,
                )
            )

        return strategies

    def _ids_evasion(self, _sig: DefenseSignature, tool: str) -> list[EvasionStrategy]:
        """IDS/IPS evasion strategies."""
        strategies = []

        if "nmap" in tool:
            strategies.append(
                EvasionStrategy(
                    name="nmap_stealth_timing",
                    description="Use T1 timing to slow scan below IDS threshold",
                    tool_modifications={"extra_args": "-T1 -Pn --max-retries 1"},
                    priority=9,
                )
            )
            strategies.append(
                EvasionStrategy(
                    name="nmap_decoy",
                    description="Add decoy IPs to confuse IDS source tracking",
                    tool_modifications={"extra_args": "-D RND:5"},
                    priority=7,
                )
            )
            strategies.append(
                EvasionStrategy(
                    name="nmap_source_port",
                    description="Use DNS source port to bypass firewall rules",
                    tool_modifications={"extra_args": "--source-port 53"},
                    priority=6,
                )
            )

        if tool in ("gobuster", "ffuf", "nikto"):
            strategies.append(
                EvasionStrategy(
                    name="web_slow_scan",
                    description="Add delays between web requests",
                    delay_seconds=3.0,
                    priority=8,
                )
            )

        return strategies

    def _rate_limit_evasion(self, _tool: str) -> list[EvasionStrategy]:
        """Rate limit evasion."""
        return [
            EvasionStrategy(
                name="rate_limit_delay",
                description="Add significant delay between requests",
                delay_seconds=5.0,
                tool_modifications={"_throttle": True},
                priority=10,
            ),
        ]

    def _anti_bf_evasion(self, tool: str) -> list[EvasionStrategy]:
        """Anti-brute-force evasion."""
        strategies = []
        if "hydra" in tool:
            strategies.append(
                EvasionStrategy(
                    name="hydra_slow",
                    description="Reduce parallel tasks and add wait between attempts",
                    tool_modifications={"extra_args": "-t 1 -W 10"},
                    delay_seconds=5.0,
                    priority=9,
                )
            )
        return strategies

    def _stealth_level_strategies(self, tool: str) -> list[EvasionStrategy]:
        """Generate stealth-level-based strategies."""
        level = self._stealth_level
        if level == StealthLevel.NORMAL:
            return []

        strategies = []

        if level.value >= StealthLevel.LOW.value:
            strategies.append(
                EvasionStrategy(
                    name="stealth_delay",
                    description=f"Stealth level {level.name}: inter-request delay",
                    delay_seconds={
                        StealthLevel.LOW: 1.0,
                        StealthLevel.MEDIUM: 3.0,
                        StealthLevel.HIGH: 5.0,
                        StealthLevel.PARANOID: 10.0,
                    }.get(level, 1.0),
                    priority=5,
                )
            )

        if level.value >= StealthLevel.MEDIUM.value and "nmap" in tool:
            timing = {
                StealthLevel.MEDIUM: "-T2",
                StealthLevel.HIGH: "-T1",
                StealthLevel.PARANOID: "-T0",
            }.get(level, "-T2")
            strategies.append(
                EvasionStrategy(
                    name="nmap_timing",
                    description=f"Nmap timing: {timing}",
                    tool_modifications={"extra_args": timing},
                    priority=4,
                )
            )

        return strategies
