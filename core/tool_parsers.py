"""Minimal tool output parsers (stubs).

These are lightweight, safe parsers that convert common scanner output
into simple Python dictionaries suitable for the `state` observation layer.
They are intentionally conservative and must be replaced by production
parsers that fully validate and normalize tool outputs.
"""
from typing import List, Dict
import re


def parse_nmap_output(output: str) -> List[Dict]:
    """Parse a small subset of nmap grepable-like output.

    Returns a list of service dicts: {"port": int, "proto": str, "service": str}
    This is intentionally simple and robust against varied formats.
    """
    services: List[Dict] = []
    # lines like: "80/tcp open  http"
    for line in output.splitlines():
        m = re.search(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
        if m:
            port = int(m.group(1))
            proto = m.group(2)
            service = m.group(3)
            services.append({"port": port, "proto": proto, "service": service})
    return services


def parse_sqlmap_output(output: str) -> List[Dict]:
    """Parse a minimal sqlmap-like output to extract discovered injection points.

    Returns a list of vuln dicts: {"parameter": str, "technique": str, "payload": str}
    """
    vulns: List[Dict] = []
    # Very small heuristic: lines containing 'parameter' and 'is injectable'
    for line in output.splitlines():
        if "is injectable" in line.lower():
            # attempt to capture parameter name
            pm = re.search(r"parameter\s+'?(\w+)'?", line, re.I)
            param = pm.group(1) if pm else "unknown"
            vulns.append({"parameter": param, "technique": "sqli", "payload": "<redacted>"})
    return vulns
