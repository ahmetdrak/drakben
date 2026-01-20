# modules/ai_bridge.py
# DRAKBEN AI Bridge Modülü - LLM Entegreli Analiz ve Öneri Motoru

import asyncio
import json
from typing import Dict, Any, Optional

# LLM Client import
try:
    from llm.openrouter_client import OpenRouterClient
    LLM_AVAILABLE = True
except ImportError:
    OpenRouterClient = None
    LLM_AVAILABLE = False


# Global LLM client instance
_llm_client: Optional[OpenRouterClient] = None


def get_llm_client() -> Optional[OpenRouterClient]:
    """Get or create LLM client"""
    global _llm_client
    if _llm_client is None and LLM_AVAILABLE:
        _llm_client = OpenRouterClient()
    return _llm_client


# -------------------------
# Recon Analizi
# -------------------------
async def analyze_recon_output(recon_result: Dict) -> Dict:
    """
    Recon çıktısını AI ile analiz eder.
    LLM varsa gerçek analiz, yoksa rule-based.
    """
    client = get_llm_client()
    
    if client:
        # Try LLM analysis
        try:
            prompt = f"""Analyze this reconnaissance data and provide security recommendations:

Target: {recon_result.get('target', 'Unknown')}
Title: {recon_result.get('title', 'N/A')}
CMS: {recon_result.get('cms', 'Unknown')}
Open Ports: {recon_result.get('open_ports', [])}
Services: {recon_result.get('services', [])}
Forms found: {len(recon_result.get('forms', []))}

Provide response in JSON format:
{{
    "risk_level": "low|medium|high|critical",
    "recommended_tests": ["test1", "test2"],
    "vulnerabilities_possible": ["vuln1", "vuln2"],
    "priority_actions": ["action1", "action2"],
    "summary": "Brief security assessment"
}}"""
            
            system_prompt = "You are a penetration testing expert. Analyze recon data and suggest security tests. Respond in JSON only."
            response = client.query(prompt, system_prompt)
            
            # Try to parse JSON
            if not response.startswith("["):  # Not an error
                try:
                    return json.loads(response)
                except json.JSONDecodeError:
                    # Extract JSON from response
                    import re
                    json_match = re.search(r'\{[\s\S]*\}', response)
                    if json_match:
                        return json.loads(json_match.group())
        except Exception as e:
            pass  # Fallback to rule-based
    
    # Rule-based fallback
    return _analyze_recon_rule_based(recon_result)


def _analyze_recon_rule_based(recon_result: Dict) -> Dict:
    """Rule-based recon analysis (fallback)"""
    advice = {
        "risk_level": "low",
        "recommended_tests": [],
        "vulnerabilities_possible": [],
        "priority_actions": []
    }
    
    # CMS-specific recommendations
    cms = recon_result.get("cms")
    if cms == "WordPress":
        advice["recommended_tests"].extend([
            "WordPress plugin enumeration (wpscan)",
            "XML-RPC brute force test",
            "wp-config.php exposure check"
        ])
        advice["risk_level"] = "medium"
        advice["vulnerabilities_possible"].append("WordPress plugin vulnerabilities")
    elif cms == "Joomla":
        advice["recommended_tests"].append("Joomla component scan")
    elif cms == "Drupal":
        advice["recommended_tests"].append("Drupalgeddon vulnerability check")
    
    # Form-based tests
    if recon_result.get("forms"):
        advice["recommended_tests"].extend([
            "SQL Injection testing",
            "XSS testing",
            "CSRF testing"
        ])
        advice["vulnerabilities_possible"].append("Form-based injection attacks")
    
    # DNS-based tests
    if recon_result.get("dns_records", {}).get("MX"):
        advice["recommended_tests"].append("Email spoofing test (SPF/DKIM/DMARC)")
    
    # Service-specific
    services = recon_result.get("services", [])
    for svc in services:
        service_name = svc.get("service", "") if isinstance(svc, dict) else str(svc)
        if "ssh" in service_name.lower():
            advice["recommended_tests"].append("SSH brute force (hydra)")
        if "ftp" in service_name.lower():
            advice["recommended_tests"].append("FTP anonymous login check")
        if "mysql" in service_name.lower() or "mssql" in service_name.lower():
            advice["recommended_tests"].append("Database enumeration")
            advice["risk_level"] = "high"
    
    return advice


# -------------------------
# Exploit Analizi
# -------------------------
async def analyze_exploit_output(exploit_result: Dict) -> Dict:
    """
    Exploit çıktısını AI ile analiz eder.
    """
    client = get_llm_client()
    
    if client:
        try:
            prompt = f"""Analyze this exploit test result:

Type: {exploit_result.get('type', 'Unknown')}
Vulnerable: {exploit_result.get('vulnerable', False)}
Output: {str(exploit_result.get('stdout', ''))[:500]}

Suggest next steps in JSON:
{{
    "exploitation_successful": true/false,
    "next_payloads": ["payload1", "payload2"],
    "privilege_escalation": ["method1", "method2"],
    "data_extraction": ["target1", "target2"],
    "recommendations": ["rec1", "rec2"]
}}"""
            
            response = client.query(prompt, "You are an exploit analyst. Respond in JSON only.")
            
            if not response.startswith("["):
                try:
                    return json.loads(response)
                except:
                    import re
                    json_match = re.search(r'\{[\s\S]*\}', response)
                    if json_match:
                        return json.loads(json_match.group())
        except:
            pass
    
    # Fallback
    return _analyze_exploit_rule_based(exploit_result)


def _analyze_exploit_rule_based(exploit_result: Dict) -> Dict:
    """Rule-based exploit analysis"""
    advice = {
        "exploitation_successful": False,
        "next_payloads": [],
        "privilege_escalation": [],
        "recommendations": []
    }
    
    exploit_type = exploit_result.get("type", "")
    stdout = str(exploit_result.get("stdout", "")).lower()
    
    if exploit_type == "SQLi" and ("vulnerable" in stdout or exploit_result.get("vulnerable")):
        advice["exploitation_successful"] = True
        advice["next_payloads"].extend([
            "SQLi data extraction (--dump)",
            "Database user enumeration",
            "File read via LOAD_FILE()"
        ])
        advice["privilege_escalation"].append("SQLi to OS shell (--os-shell)")
    
    if exploit_type == "XSS" and exploit_result.get("vulnerable"):
        advice["exploitation_successful"] = True
        advice["next_payloads"].extend([
            "Session hijacking payload",
            "Cookie theft payload",
            "Keylogger injection"
        ])
    
    if exploit_type == "LFI" and exploit_result.get("vulnerable"):
        advice["exploitation_successful"] = True
        advice["next_payloads"].extend([
            "Log poisoning for RCE",
            "/etc/shadow read attempt",
            "PHP wrapper exploitation"
        ])
    
    return advice


# -------------------------
# Payload Analizi
# -------------------------
async def analyze_payload_output(payload_result: Dict) -> Dict:
    """
    Payload çıktısını AI ile analiz eder.
    """
    client = get_llm_client()
    
    if client:
        try:
            prompt = f"""Analyze this payload execution result:

Type: {payload_result.get('type', 'Unknown')}
Success: {payload_result.get('success', False)}

Suggest post-exploitation steps in JSON:
{{
    "shell_obtained": true/false,
    "post_exploitation": ["step1", "step2"],
    "persistence": ["method1", "method2"],
    "lateral_movement": ["target1", "target2"],
    "data_exfiltration": ["method1", "method2"]
}}"""
            
            response = client.query(prompt, "You are a post-exploitation expert. Respond in JSON only.")
            
            if not response.startswith("["):
                try:
                    return json.loads(response)
                except:
                    import re
                    json_match = re.search(r'\{[\s\S]*\}', response)
                    if json_match:
                        return json.loads(json_match.group())
        except:
            pass
    
    # Fallback
    return _analyze_payload_rule_based(payload_result)


def _analyze_payload_rule_based(payload_result: Dict) -> Dict:
    """Rule-based payload analysis"""
    advice = {
        "shell_obtained": False,
        "post_exploitation": [],
        "persistence": [],
        "lateral_movement": []
    }
    
    if payload_result.get("type") == "ReverseShell" and payload_result.get("success"):
        advice["shell_obtained"] = True
        advice["post_exploitation"].extend([
            "Privilege escalation enumeration",
            "User and group enumeration",
            "Network mapping",
            "Credential harvesting"
        ])
        advice["persistence"].extend([
            "Cron job backdoor",
            "SSH key injection",
            ".bashrc persistence"
        ])
        advice["lateral_movement"].append("Internal network scan")
    
    if payload_result.get("type") == "BindShell" and payload_result.get("success"):
        advice["shell_obtained"] = True
        advice["post_exploitation"].append("Pivoting into internal network")
    
    return advice


# -------------------------
# Report Analizi
# -------------------------
async def analyze_report_output(report_result: Dict) -> Dict:
    """
    Tüm zincir çıktısını AI ile özetler.
    """
    client = get_llm_client()
    
    if client:
        try:
            prompt = f"""Summarize this penetration test in JSON:

Recon: {report_result.get('recon', {})}
Exploit: {report_result.get('exploit', {})}
Payload: {report_result.get('payload', {})}

{{
    "overall_risk": "low|medium|high|critical",
    "executive_summary": "Brief summary for management",
    "key_findings": ["finding1", "finding2"],
    "critical_vulnerabilities": ["vuln1", "vuln2"],
    "recommended_actions": ["action1", "action2"],
    "remediation_priority": ["high_priority1", "medium_priority1"]
}}"""
            
            response = client.query(prompt, "You are a security consultant writing a pentest report. Respond in JSON only.")
            
            if not response.startswith("["):
                try:
                    return json.loads(response)
                except:
                    import re
                    json_match = re.search(r'\{[\s\S]*\}', response)
                    if json_match:
                        return json.loads(json_match.group())
        except:
            pass
    
    # Fallback
    return _analyze_report_rule_based(report_result)


def _analyze_report_rule_based(report_result: Dict) -> Dict:
    """Rule-based report analysis"""
    summary = {
        "overall_risk": "Medium",
        "key_findings": [],
        "recommended_actions": [],
        "remediation_priority": []
    }
    
    recon = report_result.get("recon", {})
    exploit = report_result.get("exploit", {})
    payload = report_result.get("payload", {})
    
    # Assess risk based on findings
    if recon.get("cms") == "WordPress":
        summary["overall_risk"] = "High"
        summary["key_findings"].append("WordPress CMS detected - common attack target")
        summary["recommended_actions"].append("Update WordPress and all plugins")
    
    if exploit.get("type") == "SQLi" and exploit.get("vulnerable"):
        summary["overall_risk"] = "Critical"
        summary["key_findings"].append("SQL Injection vulnerability confirmed")
        summary["recommended_actions"].append("Implement parameterized queries immediately")
        summary["remediation_priority"].append("SQL Injection fix - CRITICAL")
    
    if payload.get("success"):
        summary["overall_risk"] = "Critical"
        summary["key_findings"].append("Remote code execution achieved")
        summary["recommended_actions"].extend([
            "Incident response required",
            "Audit all systems for compromise"
        ])
    
    return summary


# -------------------------
# Direct Chat
# -------------------------
async def chat(message: str) -> str:
    """
    Direct chat with LLM for general questions.
    """
    client = get_llm_client()
    
    if client:
        return client.query(message)
    
    return "[Offline Mode] LLM bağlantısı yok. config/api.env dosyasını kontrol edin."


# -------------------------
# Command Suggestion
# -------------------------
async def suggest_command(intent: str, target: str = None, context: Dict = None) -> Dict:
    """
    Intent'e göre komut önerisi al.
    """
    client = get_llm_client()
    
    if client:
        try:
            prompt = f"""Suggest a penetration testing command for:

Intent: {intent}
Target: {target or 'Not specified'}
Context: {context or {}}

Respond in JSON:
{{
    "command": "shell command to run",
    "tool": "tool name",
    "description": "what the command does",
    "risk_level": "low|medium|high",
    "alternatives": ["alt_cmd1", "alt_cmd2"]
}}"""
            
            response = client.query(prompt, "You are a penetration testing command expert. Respond in JSON only.")
            
            if not response.startswith("["):
                try:
                    return json.loads(response)
                except:
                    import re
                    json_match = re.search(r'\{[\s\S]*\}', response)
                    if json_match:
                        return json.loads(json_match.group())
        except:
            pass
    
    # Fallback command suggestions
    commands = {
        "scan": {"command": f"nmap -sV -T4 {target}" if target else "nmap -sV <target>", "tool": "nmap"},
        "vuln": {"command": f"nmap --script=vuln {target}" if target else "nmap --script=vuln <target>", "tool": "nmap"},
        "web": {"command": f"nikto -h {target}" if target else "nikto -h <target>", "tool": "nikto"},
        "sqli": {"command": f"sqlmap -u '{target}' --batch" if target else "sqlmap -u '<url>' --batch", "tool": "sqlmap"},
    }
    
    return commands.get(intent, {"command": None, "error": "Unknown intent"})

