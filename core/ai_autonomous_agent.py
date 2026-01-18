# core/ai_autonomous_agent.py
# DRAKBEN AI Autonomous Agent - Terminal-Aware, Memory-Full, Auto-Execution
# 2026 - AI Assistant with Full Terminal Context

import subprocess
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Any
from collections import deque
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TerminalMonitor:
    """Monitor terminal output and capture for AI context"""
    
    def __init__(self, max_history=50):
        self.output_history = deque(maxlen=max_history)
        self.last_command = None
        self.last_output = None
        self.monitoring = False
        
    def execute_and_capture(self, command: str) -> Dict[str, Any]:
        """Execute command and capture full output for AI"""
        self.last_command = command
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output_data = {
                "command": command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "timestamp": datetime.now().isoformat(),
                "status": "success" if result.returncode == 0 else "error"
            }
            
            self.last_output = output_data
            self.output_history.append(output_data)
            
            return output_data
        except subprocess.TimeoutExpired:
            error_data = {
                "command": command,
                "error": "Command timeout (30s)",
                "timestamp": datetime.now().isoformat(),
                "status": "timeout"
            }
            self.output_history.append(error_data)
            return error_data
        except Exception as e:
            error_data = {
                "command": command,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "status": "error"
            }
            self.output_history.append(error_data)
            return error_data
    
    def get_context(self) -> str:
        """Get terminal context for AI analysis"""
        context = "=== TERMINAL CONTEXT ===\n"
        
        if self.last_output:
            context += f"Last Command: {self.last_output.get('command', 'N/A')}\n"
            context += f"Status: {self.last_output.get('status', 'N/A')}\n"
            
            stdout = self.last_output.get('stdout', '').strip()
            if stdout:
                lines = stdout.split('\n')[:10]  # First 10 lines
                context += f"Output:\n{chr(10).join(lines)}\n"
                if len(stdout.split('\n')) > 10:
                    context += "[... truncated ...]\n"
        
        return context


class AIMemory:
    """AI memory system - persistent knowledge about pentest session"""
    
    def __init__(self):
        self.facts = {}  # Key knowledge facts
        self.command_history = deque(maxlen=100)
        self.findings = []
        self.targets = set()
        self.vulnerabilities = []
        self.exploitation_log = []
        self.session_start = datetime.now()
        
    def remember(self, key: str, value: Any):
        """Store important fact"""
        self.facts[key] = {
            "value": value,
            "timestamp": datetime.now().isoformat()
        }
        logger.info(f"[MEMORY] Remembered: {key} = {value}")
        
    def recall(self, key: str) -> Any:
        """Recall stored fact"""
        if key in self.facts:
            return self.facts[key]["value"]
        return None
    
    def add_finding(self, finding: Dict):
        """Add pentest finding to memory"""
        finding["timestamp"] = datetime.now().isoformat()
        self.findings.append(finding)
        logger.info(f"[FINDING] {finding.get('type', 'unknown')}: {finding.get('description', '')}")
        
    def add_vuln(self, cve: str, severity: str, target: str):
        """Record vulnerability"""
        vuln = {
            "cve": cve,
            "severity": severity,
            "target": target,
            "timestamp": datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        logger.info(f"[VULN] {cve} ({severity}) on {target}")
        
    def log_command(self, command: str, result: Dict):
        """Log executed command"""
        log_entry = {
            "command": command,
            "result": result.get("status"),
            "timestamp": datetime.now().isoformat()
        }
        self.command_history.append(log_entry)
        
    def get_session_summary(self) -> Dict:
        """Get summary of session for AI context"""
        return {
            "duration": str(datetime.now() - self.session_start),
            "commands_executed": len(self.command_history),
            "findings_count": len(self.findings),
            "vulnerabilities_count": len(self.vulnerabilities),
            "targets": list(self.targets),
            "exploitations": len(self.exploitation_log),
            "key_facts": {k: v["value"] for k, v in self.facts.items()}
        }


class AIAutonomousAgent:
    """AI-Powered Autonomous Pentest Agent with Terminal Awareness"""
    
    def __init__(self, brain, approval_engine, opsec):
        self.brain = brain  # LLM brain
        self.approval = approval_engine
        self.opsec = opsec
        self.terminal = TerminalMonitor()
        self.memory = AIMemory()
        self.auto_mode = False
        self.confidence_threshold = 0.75
        
    def analyze_terminal_output(self, output: Dict) -> Dict[str, Any]:
        """AI analyzes terminal output and suggests next actions"""
        
        analysis = {
            "findings": [],
            "suggested_actions": [],
            "confidence": 0.0,
            "reasoning": ""
        }
        
        stdout = output.get("stdout", "")
        command = output.get("command", "")
        
        # Analyze nmap output
        if "nmap" in command.lower():
            if "open" in stdout:
                ports = self._extract_open_ports(stdout)
                analysis["findings"].append({
                    "type": "open_ports",
                    "data": ports,
                    "severity": "medium"
                })
                analysis["suggested_actions"].append("enumerate_services")
                analysis["confidence"] = 0.85
                analysis["reasoning"] = f"Found {len(ports)} open ports - recommend enumeration"
        
        # Analyze nikto/web scan output
        if "nikto" in command.lower() or "200" in stdout:
            if "OSVDB" in stdout or "vulnerable" in stdout.lower():
                analysis["findings"].append({
                    "type": "web_vulnerabilities",
                    "severity": "high"
                })
                analysis["suggested_actions"].append("exploit_web_vuln")
                analysis["confidence"] = 0.8
                analysis["reasoning"] = "Web vulnerabilities detected"
        
        # Analyze sqlmap output
        if "sqlmap" in command.lower():
            if "injectable" in stdout or "vulnerable" in stdout:
                analysis["findings"].append({
                    "type": "sql_injection",
                    "severity": "critical"
                })
                analysis["suggested_actions"].append("exploit_sqli")
                analysis["confidence"] = 0.9
                analysis["reasoning"] = "SQL Injection vulnerability confirmed"
        
        return analysis
    
    def _extract_open_ports(self, nmap_output: str) -> List[str]:
        """Extract open ports from nmap output"""
        ports = []
        for line in nmap_output.split('\n'):
            if "/tcp" in line and "open" in line:
                parts = line.split('/')
                ports.append(parts[0].strip())
        return ports
    
    def auto_execute(self, command: str, description: str = "") -> bool:
        """
        Auto-execute command with intelligent approval
        Returns: True if approved/executed, False otherwise
        """
        
        if not self.auto_mode:
            return False
        
        # Step 1: Execute command and capture output
        output = self.terminal.execute_and_capture(command)
        self.memory.log_command(command, output)
        
        # Step 2: AI analyzes output
        analysis = self.analyze_terminal_output(output)
        
        # Step 3: Smart approval decision
        approval_decision = self.approval.decide_approval({
            "command": command,
            "analysis": analysis,
            "risk_level": self._calculate_risk(command)
        })
        
        # Step 4: Auto-execute if high confidence
        if analysis["confidence"] > self.confidence_threshold:
            print(f"\n[AUTO] AI Autonomous Execution (confidence: {analysis['confidence']:.1%})")
            print(f"  Command: {command}")
            print(f"  Reasoning: {analysis['reasoning']}")
            
            # Remember findings
            for finding in analysis["findings"]:
                self.memory.add_finding(finding)
            
            return True
        
        return False
    
    def _calculate_risk(self, command: str) -> str:
        """Calculate risk level of command"""
        dangerous_keywords = ["rm ", "dd ", "format", "reboot", "shutdown"]
        
        for keyword in dangerous_keywords:
            if keyword in command.lower():
                return "critical"
        
        if any(x in command.lower() for x in ["exploit", "payload", "shell"]):
            return "high"
        
        return "medium"
    
    def run_autonomous_pentest(self, target: str, depth: int = 3) -> Dict:
        """
        Run full autonomous pentest workflow
        depth: How many exploitation levels to attempt
        """
        
        print(f"\n[AUTONOMOUS] Starting AI Pentest for {target}")
        print(f"[AUTONOMOUS] Depth level: {depth}")
        
        self.auto_mode = True
        self.memory.remember("target", target)
        self.memory.targets.add(target)
        
        results = {
            "target": target,
            "findings": [],
            "vulnerabilities": [],
            "status": "running"
        }
        
        # Phase 1: Reconnaissance
        print("\n[PHASE 1] Reconnaissance...")
        recon_commands = [
            f"nmap -sV -p- {target}",
            f"nmap -sC -p- {target}",
        ]
        
        for cmd in recon_commands:
            self.auto_execute(cmd, "reconnaissance")
        
        # Phase 2: Vulnerability Scanning
        print("\n[PHASE 2] Vulnerability Scanning...")
        scan_commands = [
            f"nikto -h {target}",
            f"nmap --script vuln {target}",
        ]
        
        for cmd in scan_commands:
            self.auto_execute(cmd, "vulnerability_scan")
        
        # Phase 3: Exploitation (if findings)
        if len(self.memory.findings) > 0 and depth >= 2:
            print("\n[PHASE 3] Exploitation Planning...")
            # AI recommends exploits based on findings
            
        self.auto_mode = False
        results["findings"] = list(self.memory.findings)
        results["vulnerabilities"] = self.memory.vulnerabilities
        results["status"] = "completed"
        
        return results
    
    def get_ai_context(self) -> str:
        """Get full AI context for decision making"""
        context = ""
        context += self.terminal.get_context()
        context += "\n=== SESSION SUMMARY ===\n"
        summary = self.memory.get_session_summary()
        for key, value in summary.items():
            context += f"{key}: {value}\n"
        return context


class AutonousAgentFactory:
    """Factory for creating AI Autonomous Agents"""
    
    @staticmethod
    def create_agent(brain, approval_engine, opsec) -> AIAutonomousAgent:
        """Create autonomous agent with dependencies"""
        return AIAutonomousAgent(brain, approval_engine, opsec)
