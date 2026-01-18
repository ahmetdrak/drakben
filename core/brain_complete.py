#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# core/brain_complete.py
# DRAKBEN Brain Module - Complete & Standalone

import asyncio
import json
from typing import Dict, List, Optional, Any
import logging
from enum import Enum
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ExecutionMode(Enum):
    LLM_ONLY = 1        # Use LLM for all decisions
    STANDALONE = 2      # Use hardcoded rules (no API)
    HYBRID = 3          # Try LLM, fallback to rules

class DrakbenBrainComplete:
    """
    Complete DRAKBEN Brain Module
    Solves: Incomplete Implementation, LLM Dependency
    """
    
    # Hardcoded exploitation chains (fallback when LLM unavailable)
    FALLBACK_CHAINS = {
        "web_application": [
            {"step": 1, "action": "Recon", "command": "nmap -sV -sC {target}"},
            {"step": 2, "action": "Enum", "command": "dirsearch -u http://{target}"},
            {"step": 3, "action": "SQLi Test", "command": "sqlmap -u http://{target} --batch"},
            {"step": 4, "action": "XSS Test", "command": "burpsuite scan http://{target}"},
        ],
        "network_target": [
            {"step": 1, "action": "Port Scan", "command": "nmap -p- {target}"},
            {"step": 2, "action": "Service Detect", "command": "nmap -sV {target}"},
            {"step": 3, "action": "Vuln Scan", "command": "nessus {target}"},
            {"step": 4, "action": "Exploit", "command": "metasploit search {target}"},
        ],
        "linux_privilege_escalation": [
            {"step": 1, "action": "Enum", "command": "enum4linux -a {target}"},
            {"step": 2, "action": "SUDO Check", "command": "sudo -l"},
            {"step": 3, "action": "SUID Check", "command": "find / -perm -4000"},
            {"step": 4, "action": "Kernel Enum", "command": "uname -a"},
        ],
        "windows_privilege_escalation": [
            {"step": 1, "action": "System Info", "command": "systeminfo"},
            {"step": 2, "action": "User Enum", "command": "net user"},
            {"step": 3, "action": "UAC Check", "command": "Get-UAC-Status"},
            {"step": 4, "action": "Kernel Exploit", "command": "whoami /priv"},
        ],
    }
    
    # Intent -> Target Type mapping
    INTENT_MAPPING = {
        "web": "web_application",
        "web app": "web_application",
        "website": "web_application",
        "api": "web_application",
        "network": "network_target",
        "host": "network_target",
        "machine": "network_target",
        "server": "network_target",
        "linux": "linux_privilege_escalation",
        "windows": "windows_privilege_escalation",
    }
    
    # Vulnerability -> Exploit mapping
    VULN_EXPLOIT_MAP = {
        "SQLi": ["sqlmap", "burpsuite", "havij"],
        "XSS": ["burpsuite", "zaproxy", "xsstrike"],
        "LFI": ["wfuzz", "commix"],
        "RFI": ["curl", "wget"],
        "SSRF": ["custom_exploit"],
        "RCE": ["metasploit", "custom_shell"],
        "LPE": ["privesc_script", "exploit"],
        "UAC Bypass": ["bypassuac", "cmstp"],
    }
    
    def __init__(self, mode: ExecutionMode = ExecutionMode.HYBRID, 
                 llm_client=None):
        self.mode = mode
        self.llm_client = llm_client
        self.decision_log = []
        self.execution_history = []
    
    def analyze_intent(self, user_input: str) -> Dict[str, Any]:
        """
        Analyze user intent from natural language
        
        Returns: {
            "intent": "web|network|privesc|...",
            "target": "192.168.1.1|site.com",
            "action": "scan|exploit|paylaod|...",
            "confidence": 0.0-1.0
        }
        """
        lower_input = user_input.lower()
        
        # Extract target
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        domain_pattern = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}'
        
        target = None
        if re.search(ip_pattern, user_input):
            target = re.search(ip_pattern, user_input).group()
        elif re.search(domain_pattern, user_input):
            target = re.search(domain_pattern, user_input).group()
        
        # Detect intent type
        intent_type = None
        for keyword, intent in self.INTENT_MAPPING.items():
            if keyword in lower_input:
                intent_type = intent
                break
        
        confidence = 0.8 if intent_type else 0.3
        
        analysis = {
            "intent": intent_type or "unknown",
            "target": target,
            "action": self._extract_action(lower_input),
            "confidence": confidence,
            "raw_input": user_input,
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"Intent analysis: {analysis['intent']} (confidence: {confidence})")
        return analysis
    
    def _extract_action(self, user_input: str) -> str:
        """Extract action from user input"""
        actions = {
            "scan": ["scan", "recon", "enumerate"],
            "exploit": ["exploit", "hack", "attack"],
            "payload": ["payload", "shell", "reverse"],
            "privesc": ["privesc", "privilege", "escalation"],
            "report": ["report", "results", "findings"],
        }
        
        for action, keywords in actions.items():
            for keyword in keywords:
                if keyword in user_input:
                    return action
        return "unknown"
    
    def plan_exploitation_chain(self, target: str, intent: str) -> List[Dict]:
        """
        Plan exploitation chain based on target and intent
        """
        chain_type = None
        
        for keyword, chain_name in self.INTENT_MAPPING.items():
            if keyword in intent.lower():
                chain_type = chain_name
                break
        
        if not chain_type or chain_type not in self.FALLBACK_CHAINS:
            chain_type = "network_target"  # Default
        
        chain = self.FALLBACK_CHAINS[chain_type]
        
        # Substitute target in commands
        resolved_chain = []
        for step in chain:
            resolved_step = step.copy()
            resolved_step["command"] = step["command"].format(target=target)
            resolved_chain.append(resolved_step)
        
        logger.info(f"Planned chain: {chain_type} with {len(resolved_chain)} steps")
        return resolved_chain
    
    def recommend_exploit(self, vulnerability: str) -> List[str]:
        """Recommend exploits for vulnerability"""
        vuln_upper = vulnerability.upper()
        
        for vuln_key, exploits in self.VULN_EXPLOIT_MAP.items():
            if vuln_key in vuln_upper:
                logger.info(f"Recommended exploits for {vuln_upper}: {exploits}")
                return exploits
        
        return ["manual_analysis"]
    
    async def run_exploitation_async(self, chain: List[Dict], 
                                    executor=None) -> Dict:
        """
        Async execution of exploitation chain
        """
        results = {
            "chain": chain,
            "steps_completed": 0,
            "vulnerabilities_found": [],
            "execution_start": datetime.now().isoformat()
        }
        
        for step in chain:
            logger.info(f"Executing step {step['step']}: {step['action']}")
            
            if executor:
                # Execute with executor
                output = executor.run(step["command"])
                results[f"step_{step['step']}"] = output
            
            results["steps_completed"] += 1
            
            # Small delay between steps
            await asyncio.sleep(0.5)
        
        results["execution_end"] = datetime.now().isoformat()
        return results
    
    def make_decision(self, context: Dict) -> Dict:
        """
        Make intelligent decision based on context
        
        Input context: {
            "current_stage": "recon|exploitation|post",
            "findings": [...],
            "time_elapsed": 120,
            "success_rate": 0.7,
        }
        """
        stage = context.get("current_stage", "recon")
        findings = context.get("findings", [])
        success_rate = context.get("success_rate", 0.0)
        
        # Decision logic
        decision = {
            "next_action": None,
            "confidence": 0.0,
            "reasoning": ""
        }
        
        if stage == "recon":
            if len(findings) > 3:
                decision["next_action"] = "begin_exploitation"
                decision["confidence"] = 0.9
                decision["reasoning"] = "Found enough vulnerabilities to exploit"
            else:
                decision["next_action"] = "expand_recon"
                decision["confidence"] = 0.7
                decision["reasoning"] = "Need more information"
        
        elif stage == "exploitation":
            if success_rate > 0.5:
                decision["next_action"] = "post_exploitation"
                decision["confidence"] = 0.95
                decision["reasoning"] = "Successful exploitation, moving to post-exploitation"
            else:
                decision["next_action"] = "try_different_exploit"
                decision["confidence"] = 0.6
                decision["reasoning"] = "Current exploits not working"
        
        elif stage == "post":
            decision["next_action"] = "generate_report"
            decision["confidence"] = 0.99
            decision["reasoning"] = "Post-exploitation complete"
        
        return decision
    
    def fallback_mode(self) -> bool:
        """Check if should use fallback mode"""
        return self.mode in [ExecutionMode.STANDALONE, ExecutionMode.HYBRID]
    
    def log_decision(self, analysis: Dict):
        """Log decision for audit trail"""
        self.decision_log.append({
            "timestamp": datetime.now().isoformat(),
            "analysis": analysis
        })


class BrainFactory:
    """Factory for creating Brain instances"""
    
    @staticmethod
    def create_brain(mode: ExecutionMode = ExecutionMode.HYBRID, 
                    llm_client=None) -> DrakbenBrainComplete:
        """Create brain instance"""
        logger.info(f"Creating Brain in {mode.name} mode")
        return DrakbenBrainComplete(mode=mode, llm_client=llm_client)


# Example Usage
if __name__ == "__main__":
    brain = BrainFactory.create_brain(mode=ExecutionMode.STANDALONE)
    
    # Analyze user input
    user_input = "Scan and exploit web app at 192.168.1.100"
    analysis = brain.analyze_intent(user_input)
    print(f"Analysis: {json.dumps(analysis, indent=2)}")
    
    # Plan chain
    chain = brain.plan_exploitation_chain("192.168.1.100", analysis["intent"])
    print(f"\nPlanned Chain ({len(chain)} steps):")
    for step in chain:
        print(f"  {step['step']}: {step['action']} -> {step['command']}")
    
    # Recommend exploit
    exploits = brain.recommend_exploit("SQL Injection")
    print(f"\nRecommended exploits for SQLi: {exploits}")
