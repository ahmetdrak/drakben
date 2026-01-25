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
            results.append({
                "port": int(match.group(1)),
                "proto": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5) or ""
            })
    
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
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
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
    results = []
    
    # Patterns for sqlmap output
    vuln_patterns = [
        # Parameter X is vulnerable
        re.compile(r"Parameter:\s*(\S+)\s*\(.*?(GET|POST|COOKIE)", re.IGNORECASE),
        # Type: boolean-based blind
        re.compile(r"Type:\s*(.+)", re.IGNORECASE),
        # Title: AND boolean-based blind
        re.compile(r"Title:\s*(.+)", re.IGNORECASE),
        # Payload: id=1 AND ...
        re.compile(r"Payload:\s*(.+)", re.IGNORECASE),
    ]
    
    # Look for vulnerability blocks
    if "is vulnerable" in output.lower() or "sqlmap identified" in output.lower():
        current_vuln = {}
        
        for line in output.split("\n"):
            line = line.strip()
            
            # Parameter line
            param_match = re.search(r"Parameter:\s*[#]?(\S+)", line)
            if param_match:
                if current_vuln:
                    results.append(current_vuln)
                current_vuln = {"parameter": param_match.group(1)}
            
            # Type line
            type_match = re.search(r"Type:\s*(.+)", line)
            if type_match and current_vuln:
                current_vuln["type"] = type_match.group(1).strip()
            
            # Title line
            title_match = re.search(r"Title:\s*(.+)", line)
            if title_match and current_vuln:
                current_vuln["title"] = title_match.group(1).strip()
            
            # Payload line
            payload_match = re.search(r"Payload:\s*(.+)", line)
            if payload_match and current_vuln:
                current_vuln["payload"] = payload_match.group(1).strip()
        
        # Don't forget the last one
        if current_vuln:
            results.append(current_vuln)
    
    if results:
        logger.debug(f"Parsed {len(results)} SQLi vulnerabilities")
        return results
    
    # LLM fallback
    if llm_client and "vulnerable" in output.lower():
        logger.info("Falling back to LLM for sqlmap parsing")
        try:
            prompt = f"""Parse this sqlmap output and extract SQL injection vulnerabilities.
Return JSON array with objects having: parameter, type, title, payload

Output:
{output[:3000]}

Response (JSON only):"""
            
            response = llm_client.query(prompt, timeout=15)
            
            import json
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                if isinstance(parsed, list):
                    return parsed
        except Exception as e:
            logger.warning(f"LLM parsing failed: {e}")
    
    return []


def parse_nikto_output(output: str, llm_client=None) -> List[Dict]:
    """
    Parse nikto output to extract web vulnerabilities.
    
    Returns:
        List of dicts with keys: vulnerability, path, method, description
    """
    results = []
    
    # Nikto output patterns
    # + OSVDB-XXXX: /path: Description
    # + /path: Description
    vuln_pattern = re.compile(
        r"\+\s*(OSVDB-\d+)?:?\s*(/\S*)?\s*:?\s*(.+)"
    )
    
    for line in output.split("\n"):
        line = line.strip()
        
        # Skip info lines
        if line.startswith("- Nikto") or line.startswith("+ Target") or not line.startswith("+"):
            continue
        
        match = vuln_pattern.search(line)
        if match:
            vuln = {
                "vulnerability": match.group(1) or "Unknown",
                "path": match.group(2) or "/",
                "description": match.group(3).strip() if match.group(3) else ""
            }
            
            # Determine severity based on keywords
            desc_lower = vuln["description"].lower()
            if any(x in desc_lower for x in ["remote", "execute", "injection", "xss", "sqli"]):
                vuln["severity"] = "HIGH"
            elif any(x in desc_lower for x in ["disclosure", "directory", "listing"]):
                vuln["severity"] = "MEDIUM"
            else:
                vuln["severity"] = "LOW"
            
            results.append(vuln)
    
    if results:
        logger.debug(f"Parsed {len(results)} web vulnerabilities from nikto")
        return results
    
    return []


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
            results.append({
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3))
            })
    
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
            results.append({
                "port": int(match.group(1)),
                "service": match.group(2),
                "host": match.group(3),
                "login": match.group(4),
                "password": match.group(5)
            })
    
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
    
    # Check for common error patterns and return normalized message
    
    # Connection errors
    if "connection refused" in combined_lower:
        return "Connection refused - target may be down or port closed"
    if "connection reset" in combined_lower:
        return "Connection reset by peer - possible firewall"
    if "no route to host" in combined_lower:
        return "No route to host - network unreachable"
    if "name or service not known" in combined_lower:
        return "DNS resolution failed - hostname not found"
    
    # Permission errors
    if "permission denied" in combined_lower:
        return "Permission denied - try running with sudo"
    if "operation not permitted" in combined_lower:
        return "Operation not permitted - insufficient privileges"
    
    # Tool errors
    if "command not found" in combined_lower or "not recognized" in combined_lower:
        return "Command not found - tool may not be installed"
    
    # Timeout
    if "timed out" in combined_lower or "timeout" in combined_lower:
        return "Operation timed out - target may be slow or unreachable"
    
    # Rate limiting
    if "too many" in combined_lower or "rate limit" in combined_lower:
        return "Rate limited - too many requests"
    
    # WAF/Firewall
    if "blocked" in combined_lower or "forbidden" in combined_lower:
        return "Request blocked - possible WAF or firewall"
    
    # Generic error based on exit code
    if exit_code != 0:
        # Try to extract first meaningful error line
        for line in combined.split("\n"):
            line = line.strip()
            if line and ("error" in line.lower() or "fail" in line.lower()):
                return line[:200]  # Limit length
        
        return f"Command failed with exit code {exit_code}"
    
    return ""


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
            if 'llm_client' in sig.parameters:
                return parser_func(output, llm_client)
            else:
                return parser_func(output)
        except Exception as e:
            logger.error(f"Parser error for {tool_name}: {e}")
            return []
    
    # Default/Fallback parser for unknown tools
    logger.warning(f"No specific parser for {tool_name}, returning raw output wrapper")
    return [{"raw_output": output[:500]}]


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
