"""Minimal tool output parsers (stubs).

These are lightweight, safe parsers that convert common scanner output
into simple Python dictionaries suitable for the `state` observation layer.
They are intentionally conservative and must be replaced by production
parsers that fully validate and normalize tool outputs.
"""

import json
import logging
import os
import re
from typing import Dict, List

logger = logging.getLogger(__name__)

# Try to import OpenRouterClient for formatting hints (not strict dependency)
try:
    from core.llm_utils import format_llm_prompt, parse_llm_json_response
except ImportError:
    pass

PATTERNS_FILE = "config/adaptive_parsers.json"


class DynamicPatternManager:
    """Manages learned regex patterns for tools"""

    def __init__(self):
        self.patterns = self._load()

    def _load(self) -> Dict[str, List[str]]:
        if os.path.exists(PATTERNS_FILE):
            try:
                with open(PATTERNS_FILE, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save(self):
        if not os.path.exists("config"):
            os.makedirs("config")
        with open(PATTERNS_FILE, "w") as f:
            json.dump(self.patterns, f, indent=2)

    def get_patterns(self, tool: str) -> List[str]:
        return self.patterns.get(tool, [])

    def add_pattern(self, tool: str, regex: str):
        if tool not in self.patterns:
            self.patterns[tool] = []
        if regex not in self.patterns[tool]:
            self.patterns[tool].append(regex)
            self.save()


_pattern_manager = DynamicPatternManager()


def parse_nmap_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse nmap output with Hybrid approach:
    1. Dynamic Regexes (Learned)
    2. Static Regex (Hardcoded)
    3. LLM Fallback (Smart) + LEARNING
    """
    services: List[Dict] = []

    # 0. Try Dynamic Regexes
    for pattern in _pattern_manager.get_patterns("nmap"):
        try:
            for line in output.splitlines():
                m = re.search(pattern, line)
                if m:
                    # Expecting groups: 1=port, 2=proto, 3=service
                    # Or named groups if LLM was smart
                    try:
                        port = int(m.group(1))
                        proto = m.group(2) if len(m.groups()) >= 2 else "tcp"
                        service = m.group(3) if len(m.groups()) >= 3 else "unknown"
                        services.append(
                            {"port": port, "proto": proto, "service": service}
                        )
                    except Exception:
                        pass
        except Exception:
            pass

    # 2. LLM Fallback + LEARNING
    if not services and len(output) > 50 and llm_client:
        try:
            prompt = format_llm_prompt(
                system_msg="You are a log parser. Extract open ports and services.",
                user_msg=f"Parse this nmap output into JSON list [{{'port': int, 'proto': 'tcp', 'service': 'name'}}]:\n\n{output[:2000]}",
                json_response=True,
            )
            response = llm_client.query(prompt)
            parsed = parse_llm_json_response(response)
            if isinstance(parsed, list) and parsed:
                # 🧠 LEARNING MOMENT
                # Ask LLM for a regex that would match this
                try:
                    learn_prompt = format_llm_prompt(
                        system_msg="You are a Regex Expert.",
                        user_msg="Give me a Python regex to capture (port, protocol, service) from lines like this in the Nmap output above. Return JUST the regex string. Use capturing groups (\\d+) etc.",
                    )
                    regex_response = (
                        llm_client.query(learn_prompt).strip().strip("`\"'/")
                    )
                    # Validate regex
                    re.compile(regex_response)
                    _pattern_manager.add_pattern("nmap", regex_response)
                    logger.info(f"Learned new Nmap regex: {regex_response}")
                except Exception:
                    pass
                return parsed
        except Exception as e:
            logger.error(f"LLM Parsing error: {e}")

    return services


def parse_sqlmap_output(output: str, llm_client=None) -> List[Dict]:
    vulns: List[Dict] = []
    # Similar learning logic could be applied here...
    # Keeping it simple for now to avoid code bloat risk

    # 1. Try Static Regex
    for line in output.splitlines():
        if "is injectable" in line.lower():
            pm = re.search(r"parameter\s+'?(\w+)'?", line, re.I)
            param = pm.group(1) if pm else "unknown"
            vulns.append(
                {"parameter": param, "technique": "sqli", "payload": "<redacted>"}
            )

    # 2. LLM Fallback
    if not vulns and "vulnerable" in output.lower() and llm_client:
        try:
            prompt = format_llm_prompt(
                system_msg="You are a security log parser. Extract SQL injection details.",
                user_msg=f"Parse this sqlmap output into JSON list [{{'parameter': 'name', 'technique': 'type', 'payload': 'string'}}]:\n\n{output[:2000]}",
                json_response=True,
            )
            response = llm_client.query(prompt)
            parsed = parse_llm_json_response(response)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass

    return vulns
