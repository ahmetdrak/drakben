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
    2. LLM Fallback (Smart) + LEARNING
    """
    if not output:
        return []

    # 1. Dynamic Regex Parsing
    services = _parse_nmap_with_regex(output)
    if services:
        return services

    # 2. LLM Fallback + LEARNING
    if len(output) > 50 and llm_client:
        return _parse_nmap_with_llm(output, llm_client)

    return []

def _parse_nmap_with_regex(output: str) -> List[Dict]:
    """Try to parse nmap output using known regex patterns"""
    services = []
    for pattern in _pattern_manager.get_patterns("nmap"):
        try:
            services.extend(_apply_regex_pattern(output, pattern))
        except Exception:
            continue
    return services

def _apply_regex_pattern(output: str, pattern: str) -> List[Dict]:
    """Apply a single regex pattern to nmap output"""
    matches = []
    for line in output.splitlines():
        m = re.search(pattern, line)
        if m:
            try:
                matches.append({
                    "port": int(m.group(1)),
                    "proto": m.group(2) if len(m.groups()) >= 2 else "tcp",
                    "service": m.group(3) if len(m.groups()) >= 3 else "unknown"
                })
            except (IndexError, ValueError):
                pass
    return matches

def _parse_nmap_with_llm(output: str, llm_client) -> List[Dict]:
    """Fallback to LLM parsing and improved learning"""
    try:
        prompt = format_llm_prompt(
            system_msg="You are a log parser. Extract open ports and services.",
            user_msg=f"Parse this nmap output into JSON list [{{'port': int, 'proto': 'tcp', 'service': 'name'}}]:\n\n{output[:25000]}",
            json_response=True,
        )
        response = llm_client.query(prompt)
        parsed = parse_llm_json_response(response)
        
        if isinstance(parsed, list) and parsed:
            _try_learn_regex(output, llm_client)
            return parsed
            
    except Exception as e:
        logger.error(f"LLM Parsing error: {e}")
    
    return []

def _try_learn_regex(output: str, llm_client):
    """Attempt to learn a new regex from successful LLM parse"""
    try:
        learn_prompt = format_llm_prompt(
            system_msg="You are a Regex Expert.",
            user_msg="Give me a Python regex to capture (port, protocol, service) from lines like this in the Nmap output above. Return JUST the regex string. Use capturing groups (\\d+) etc.",
        )
        regex_response = llm_client.query(learn_prompt).strip().strip("`\"'/")
        
        # Validate regex
        re.compile(regex_response)
        _pattern_manager.add_pattern("nmap", regex_response)
        logger.info(f"Learned new Nmap regex: {regex_response}")
    except Exception:
        pass


def parse_sqlmap_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse SQLMap output with deep inspection.
    Extracts: Parameter, Type, Title, Payload
    """
    vulns: List[Dict] = []
    
    # Static Regex Patterns for SQLMap
    # Pattern to capture vulnerability blocks
    # Parameter: id (GET)
    #     Type: boolean-based blind
    #     Title: AND boolean-based blind - WHERE or HAVING clause
    #     Payload: id=1 AND 8814=8814
    
    current_param = None
    
    lines = output.splitlines()
    for i, line in enumerate(lines):
        # Detect parameter
        m_param = re.search(r"Parameter:\s+(.+)\s+\((.+)\)", line)
        if m_param:
            current_param = f"{m_param.group(1)} ({m_param.group(2)})"
            continue
            
        if current_param and "Type:" in line:
            # Look ahead for Title and Payload
            vuln_type = line.split("Type:")[1].strip()
            title = "Unknown"
            payload = "Unknown"
            
            # Simple lookahead for next few lines
            for j in range(1, 5):
                if i + j >= len(lines): break
                next_line = lines[i+j]
                if "Title:" in next_line:
                    title = next_line.split("Title:")[1].strip()
                if "Payload:" in next_line:
                    payload = next_line.split("Payload:")[1].strip()
                    break # Payload usually ends the block
            
            vulns.append({
                "tool": "sqlmap",
                "parameter": current_param,
                "type": vuln_type,
                "title": title,
                "payload": payload
            })

    # LLM Fallback only if regex failed but vulnerability suspected
    if not vulns and ("vulnerable" in output.lower() or "sql injection" in output.lower()) and llm_client:
        try:
            prompt = format_llm_prompt(
                system_msg="You are a security log parser. Extract SQL injection details.",
                user_msg=f"Parse this sqlmap output into JSON list [{{'parameter': 'name', 'type': 'type', 'payload': 'string'}}]:\n\n{output[:10000]}",
                json_response=True,
            )
            response = llm_client.query(prompt)
            parsed = parse_llm_json_response(response)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass

    return vulns

def parse_nikto_output(output: str) -> List[Dict]:
    """
    Parse Nikto scan results.
    Extracts: OSVDB, Path, Description
    """
    vulns = []
    # Nikto format: + OSVDB-3092: /admin/: This might be interesting...
    
    regex = r"\+ OSVDB-(\d+):\s+([^:]+):\s+(.+)"
    
    for line in output.splitlines():
        m = re.search(regex, line)
        if m:
            vulns.append({
                "tool": "nikto",
                "osvdb": m.group(1),
                "path": m.group(2).strip(),
                "description": m.group(3).strip()
            })
            continue
            
        # Generic Nikto items usually start with "+ "
        if line.strip().startswith("+ ") and "OSVDB" not in line:
             vulns.append({
                "tool": "nikto",
                "type": "info",
                "description": line.strip()[2:]
            })
            
    return vulns


def normalize_error_message(stdout: str, stderr: str, exit_code: int) -> str:
    """
    Standardize error messages across different tools.
    """
    combined = (stdout + "\n" + stderr).lower()
    
    if "connection refused" in combined:
        return "Connection Refused: Target is likely down or port is closed."
    if "timed out" in combined or "timeout" in combined:
        return "Operation Timed Out: Network latency or firewall blocking."
    if "host seems down" in combined:
        return "Host Unreachable: ICMP blocked or host down."
    if "command not found" in combined or "not recognized" in combined:
        return "Tool Missing: The required tool is not installed."
    if "permission denied" in combined:
        return "Permission Denied: Run as root/administrator."
        
    if exit_code != 0:
        if stderr.strip():
            return f"Tool Execution Failed: {stderr.strip()[:200]}"
        return f"Unknown Error (Exit Code: {exit_code})"
        
    return ""
