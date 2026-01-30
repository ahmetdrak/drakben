# core/tool_parsers.py
# Tool output parsers with LLM fallback support

import logging
import re
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


def parse_nmap_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse nmap output to extract open ports and services.
    Falls back to LLM parsing if regex fails.

    Returns:
        List of dicts with keys: port, proto, service, version, state
    """
    results = []

    # Try regex parsing first
    # Pattern for: PORT/PROTO STATE SERVICE VERSION
    port_pattern = re.compile(
        r"(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?"
    )

    for line in output.split("\n"):
        match = port_pattern.search(line)
        if match:
            results.append(
                {
                    "port": int(match.group(1)),
                    "proto": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "version": match.group(5) or "",
                }
            )

    # If regex found results, return them
    if results:
        logger.debug(f"Parsed {len(results)} ports from nmap output")
        return results

    # Fallback to LLM if available and output seems to contain data
    if llm_client and len(output) > 50:
        logger.info("Falling back to LLM for nmap parsing")
        try:
            prompt = f"""Parse this nmap output and extract open ports.
Return JSON array with objects having: port, proto, service, version, state

Output:
{output[:3000]}

Response (JSON only):"""

            response = llm_client.query(prompt, timeout=15)

            # Try to extract JSON from response
            import json

            json_match = re.search(r"\[.*\]", response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                if isinstance(parsed, list):
                    return parsed
        except Exception as e:
            logger.warning(f"LLM parsing failed: {e}")

    # Return empty if nothing found
    logger.warning("Could not parse nmap output")
    return []


def parse_sqlmap_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse sqlmap output to extract SQL injection vulnerabilities.

    Returns:
        List of dicts with keys: parameter, type, title, payload
    """
    if not _has_sqlmap_vulnerability(output):
        return _try_llm_parse_sqlmap(output, llm_client)

    results = _parse_sqlmap_vulnerabilities(output)
    if results:
        logger.debug(f"Parsed {len(results)} SQLi vulnerabilities")
        return results

    return _try_llm_parse_sqlmap(output, llm_client)


def _has_sqlmap_vulnerability(output: str) -> bool:
    """Check if output contains vulnerability indicators"""
    output_lower = output.lower()
    return "is vulnerable" in output_lower or "sqlmap identified" in output_lower


def _parse_sqlmap_vulnerabilities(output: str) -> List[Dict]:
    """Parse vulnerability blocks from sqlmap output"""
    results = []
    current_vuln = {}

    for line in output.split("\n"):
        line = line.strip()
        current_vuln = _process_sqlmap_line(line, current_vuln, results)

    if current_vuln:
        results.append(current_vuln)
    return results


def _process_sqlmap_line(line: str, current_vuln: Dict, results: List[Dict]) -> Dict:
    """Process a single line of sqlmap output"""
    param_match = re.search(r"Parameter:\s*#?(\S+)", line)
    if param_match:
        if current_vuln:
            results.append(current_vuln)
        return {"parameter": param_match.group(1)}

    if not current_vuln:
        return current_vuln

    type_match = re.search(r"Type:\s*(.+)", line)
    if type_match:
        current_vuln["type"] = type_match.group(1).strip()

    title_match = re.search(r"Title:\s*(.+)", line)
    if title_match:
        current_vuln["title"] = title_match.group(1).strip()

    payload_match = re.search(r"Payload:\s*(.+)", line)
    if payload_match:
        current_vuln["payload"] = payload_match.group(1).strip()

    return current_vuln


def _try_llm_parse_sqlmap(output: str, llm_client) -> List[Dict]:
    """Try LLM fallback for sqlmap parsing"""
    if not llm_client or "vulnerable" not in output.lower():
        return []

    logger.info("Falling back to LLM for sqlmap parsing")
    try:
        prompt = f"""Parse this sqlmap output and extract SQL injection vulnerabilities.
Return JSON array with objects having: parameter, type, title, payload

Output:
{output[:3000]}

Response (JSON only):"""

        response = llm_client.query(prompt, timeout=15)
        return _extract_json_from_llm_response(response)
    except Exception as e:
        logger.warning(f"LLM parsing failed: {e}")
        return []


def _extract_json_from_llm_response(response: str) -> List[Dict]:
    """Extract JSON array from LLM response"""
    import json

    json_match = re.search(r"\[.*\]", response, re.DOTALL)
    if json_match:
        parsed = json.loads(json_match.group())
        if isinstance(parsed, list):
            return parsed
    return []


def parse_nikto_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse nikto output to extract web vulnerabilities.

    Returns:
        List of dicts with keys: vulnerability, path, method, description
    """
    results = []
    vuln_pattern = re.compile(r"\+\s*(OSVDB-\d+)?:?\s*(/\S*)?\s*:?\s*(.+)")

    for line in output.split("\n"):
        line = line.strip()
        if _should_skip_nikto_line(line):
            continue

        match = vuln_pattern.search(line)
        if match:
            vuln = _build_nikto_vulnerability(match)
            results.append(vuln)

    if results:
        logger.debug(f"Parsed {len(results)} web vulnerabilities from nikto")
    return results


def _should_skip_nikto_line(line: str) -> bool:
    """Check if nikto line should be skipped"""
    return (
        line.startswith("- Nikto")
        or line.startswith("+ Target")
        or not line.startswith("+")
    )


def _build_nikto_vulnerability(match: re.Match) -> Dict:
    """Build vulnerability dict from nikto match"""
    vuln = {
        "vulnerability": match.group(1) or "Unknown",
        "path": match.group(2) or "/",
        "description": match.group(3).strip() if match.group(3) else "",
    }
    vuln["severity"] = _determine_nikto_severity(vuln["description"])
    return vuln


def _determine_nikto_severity(description: str) -> str:
    """Determine severity based on description keywords"""
    desc_lower = description.lower()
    if any(x in desc_lower for x in ["remote", "execute", "injection", "xss", "sqli"]):
        return "HIGH"
    elif any(x in desc_lower for x in ["disclosure", "directory", "listing"]):
        return "MEDIUM"
    return "LOW"


def parse_gobuster_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse gobuster output to extract discovered paths.

    Returns:
        List of dicts with keys: path, status, size
    """
    results = []

    # Gobuster pattern: /path (Status: 200) [Size: 1234]
    pattern = re.compile(r"(/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]")

    for line in output.split("\n"):
        match = pattern.search(line)
        if match:
            results.append(
                {
                    "path": match.group(1),
                    "status": int(match.group(2)),
                    "size": int(match.group(3)),
                }
            )

    return results


def parse_hydra_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse hydra output to extract cracked credentials.

    Returns:
        List of dicts with keys: host, port, service, login, password
    """
    results = []

    # Hydra pattern: [port][service] host: login: password
    pattern = re.compile(
        r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)"
    )

    for line in output.split("\n"):
        match = pattern.search(line)
        if match:
            results.append(
                {
                    "port": int(match.group(1)),
                    "service": match.group(2),
                    "host": match.group(3),
                    "login": match.group(4),
                    "password": match.group(5),
                }
            )

    return results


def normalize_error_message(stdout: str, stderr: str, exit_code: int) -> str:
    """
    Normalize error messages from tool output.
    Extracts meaningful error information for logging and display.

    Returns:
        A clean, human-readable error message
    """
    combined = f"{stdout}\n{stderr}".strip()
    combined_lower = combined.lower()

    # Check error categories in priority order
    result = (
        _normalize_connection_error(combined_lower)
        or _normalize_permission_error(combined_lower)
        or _normalize_tool_error(combined_lower)
        or _normalize_timeout_error(combined_lower)
        or _normalize_rate_limit_error(combined_lower)
        or _normalize_firewall_error(combined_lower)
        or _normalize_generic_error(combined, exit_code)
        or ""
    )
    return result


def _normalize_connection_error(combined_lower: str) -> Optional[str]:
    """Normalize connection-related errors"""
    if "connection refused" in combined_lower:
        return "Connection refused - target may be down or port closed"
    if "connection reset" in combined_lower:
        return "Connection reset by peer - possible firewall"
    if "no route to host" in combined_lower:
        return "No route to host - network unreachable"
    if "name or service not known" in combined_lower:
        return "DNS resolution failed - hostname not found"
    return None


def _normalize_permission_error(combined_lower: str) -> Optional[str]:
    """Normalize permission-related errors"""
    if "permission denied" in combined_lower:
        return "Permission denied - try running with sudo"
    if "operation not permitted" in combined_lower:
        return "Operation not permitted - insufficient privileges"
    return None


def _normalize_tool_error(combined_lower: str) -> Optional[str]:
    """Normalize tool/command errors"""
    if "command not found" in combined_lower or "not recognized" in combined_lower:
        return "Command not found - tool may not be installed"
    return None


def _normalize_timeout_error(combined_lower: str) -> Optional[str]:
    """Normalize timeout errors"""
    if "timed out" in combined_lower or "timeout" in combined_lower:
        return "Operation timed out - target may be slow or unreachable"
    return None


def _normalize_rate_limit_error(combined_lower: str) -> Optional[str]:
    """Normalize rate limiting errors"""
    if "too many" in combined_lower or "rate limit" in combined_lower:
        return "Rate limited - too many requests"
    return None


def _normalize_firewall_error(combined_lower: str) -> Optional[str]:
    """Normalize firewall/WAF errors"""
    if "blocked" in combined_lower or "forbidden" in combined_lower:
        return "Request blocked - possible WAF or firewall"
    return None


def _normalize_generic_error(combined: str, exit_code: int) -> Optional[str]:
    """Normalize generic errors based on exit code"""
    if exit_code != 0:
        for line in combined.split("\n"):
            line = line.strip()
            if line and ("error" in line.lower() or "fail" in line.lower()):
                return line[:200]
        return f"Command failed with exit code {exit_code}"
    return None


def parse_tool_output(tool_name: str, output: str, llm_client=None) -> List[Dict]:
    """
    Generic entry point for parsing tool output.
    Selects the correct parser strategy based on tool name.
    """
    parser_func = PARSERS.get(tool_name.lower())

    if parser_func:
        try:
            # Check if parser accepts llm_client parameter
            import inspect

            sig = inspect.signature(parser_func)
            if "llm_client" in sig.parameters:
                return parser_func(output, llm_client)
            else:
                return parser_func(output)
        except Exception as e:
            logger.error(f"Parser error for {tool_name}: {e}")
            return []

    # Default/Fallback parser for unknown tools


def _smart_truncate(
    content: str, keywords_or_len: Any = None, max_length: int = 2000
) -> str:
    """
    Truncate string intelligently.
    Supports:
    - _smart_truncate(text, 100) -> truncates to 100 chars
    - _smart_truncate(text, ["error", "fail"]) -> keeps lines with keywords
    """
    if not keywords_or_len:
        return content[:max_length]

    keywords = []
    limit = max_length

    # Handle polymorphic arguments
    if isinstance(keywords_or_len, int):
        limit = keywords_or_len
    elif isinstance(keywords_or_len, list):
        keywords = keywords_or_len

    if len(content) <= limit and not keywords:
        return content

    lines = content.split("\n")

    # Logic for keyword-based filtering
    if keywords:
        result = _filter_lines_by_keywords(lines, keywords, limit)
        if len(result) > limit:
            return result[:limit] + "\n...[Truncated]"
        return result

    # Standard length truncation
    return content[:limit].rsplit(" ", 1)[0] + "..."


def _filter_lines_by_keywords(
    lines: List[str], keywords: List[str], max_lines: int = 50
) -> str:
    """Helper for _smart_truncate to filter lines based on keywords"""
    kept_lines = []
    # Keep context header
    kept_lines.extend(lines[:5])

    # Scan for keywords in middle
    count = 0
    for line in lines[5:-5]:
        if any(k in line for k in keywords):
            kept_lines.append(line)
            count += 1
            if count > max_lines:  # Safety cap
                break

    # Keep context footer
    if len(lines) > 10:
        kept_lines.extend(lines[-5:])

    return "\n".join(kept_lines)


# Strategy Pattern for Parsers - MUST be after function definitions
PARSERS = {
    "nmap": parse_nmap_output,
    "nmap_port_scan": parse_nmap_output,
    "nmap_service_scan": parse_nmap_output,
    "nmap_vuln_scan": parse_nmap_output,
    "sqlmap": parse_sqlmap_output,
    "sqlmap_scan": parse_sqlmap_output,
    "sqlmap_exploit": parse_sqlmap_output,
    "nikto": parse_nikto_output,
    "nikto_web_scan": parse_nikto_output,
    "gobuster": parse_gobuster_output,
    "hydra": parse_hydra_output,
}
