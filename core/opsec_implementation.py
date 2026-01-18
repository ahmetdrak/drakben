#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# core/opsec_implementation.py
# DRAKBEN OPSEC Implementation - Actual Detection Avoidance

import time
import random
import os
import sys
from typing import List, Dict, Callable
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OPSECLevel(Enum):
    AGGRESSIVE = 1      # Fast, noisy, high detection risk
    BALANCED = 2        # Normal timing, medium risk
    STEALTHY = 3        # Slow, quiet, low detection risk

class OPSECImplementation:
    """
    Implements actual OPSEC techniques, not just planning
    Solves: OPSEC Fake (Planning vs Implementation Mismatch)
    """
    
    def __init__(self, level: OPSECLevel = OPSECLevel.BALANCED):
        self.level = level
        self.delays = self._get_delays()
        self.randomization = self._get_randomization()
        
    def _get_delays(self) -> Dict[str, float]:
        """Get timing delays based on OPSEC level"""
        if self.level == OPSECLevel.STEALTHY:
            return {
                "inter_command": random.uniform(2, 8),      # 2-8 sec between commands
                "inter_packet": random.uniform(0.5, 2),     # Packet delays
                "scan_delay": random.uniform(5, 15),        # 5-15 sec between probes
                "jitter": random.uniform(-0.5, 0.5)         # ±0.5 sec randomness
            }
        elif self.level == OPSECLevel.BALANCED:
            return {
                "inter_command": random.uniform(0.5, 2),
                "inter_packet": random.uniform(0.1, 0.5),
                "scan_delay": random.uniform(1, 3),
                "jitter": random.uniform(-0.2, 0.2)
            }
        else:  # AGGRESSIVE
            return {
                "inter_command": random.uniform(0, 0.5),
                "inter_packet": 0,
                "scan_delay": 0,
                "jitter": 0
            }
    
    def _get_randomization(self) -> Dict:
        """Get randomization parameters"""
        if self.level == OPSECLevel.STEALTHY:
            return {
                "randomize_user_agent": True,
                "randomize_source_port": True,
                "randomize_packet_order": True,
                "fragment_packets": True,
                "spoof_mac": True,
                "rotate_proxy": True,
                "decoy_scans": True,
            }
        elif self.level == OPSECLevel.BALANCED:
            return {
                "randomize_user_agent": True,
                "randomize_source_port": False,
                "randomize_packet_order": False,
                "fragment_packets": False,
                "spoof_mac": False,
                "rotate_proxy": False,
                "decoy_scans": False,
            }
        else:  # AGGRESSIVE
            return {k: False for k in [
                "randomize_user_agent", "randomize_source_port",
                "randomize_packet_order", "fragment_packets",
                "spoof_mac", "rotate_proxy", "decoy_scans"
            ]}
    
    def sleep_between_commands(self):
        """Sleep with randomization between commands"""
        delay = self.delays["inter_command"]
        jitter = self.delays["jitter"]
        total_delay = delay + jitter
        
        if total_delay > 0:
            logger.info(f"OPSEC: Sleeping {total_delay:.2f}s")
            time.sleep(total_delay)
    
    def add_user_agent_randomization(self, headers: Dict) -> Dict:
        """Randomize User-Agent to avoid detection"""
        if not self.randomization["randomize_user_agent"]:
            return headers
        
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
            "curl/7.68.0"
        ]
        
        headers["User-Agent"] = random.choice(user_agents)
        return headers
    
    def get_random_source_port(self) -> int:
        """Get random high port for source"""
        if not self.randomization["randomize_source_port"]:
            return 0  # Auto-select
        
        return random.randint(10000, 65535)
    
    def add_decoy_scans(self, target: str, scan_type: str = "nmap") -> List[str]:
        """Add decoy scan commands to hide real scan"""
        if not self.randomization["decoy_scans"]:
            return []
        
        decoys = [
            f"{scan_type} -sV 8.8.8.8",        # Google DNS
            f"{scan_type} -sV 1.1.1.1",        # Cloudflare DNS
            f"{scan_type} -sV 208.67.222.222", # Quad9 DNS
        ]
        
        logger.info(f"OPSEC: Adding {len(decoys)} decoy scans")
        return decoys
    
    def fragment_payload(self, payload: str, chunk_size: int = 20) -> List[str]:
        """Fragment payload into smaller chunks"""
        if not self.randomization["fragment_packets"]:
            return [payload]
        
        fragments = []
        for i in range(0, len(payload), chunk_size):
            fragments.append(payload[i:i + chunk_size])
        
        logger.info(f"OPSEC: Fragmented payload into {len(fragments)} chunks")
        return fragments
    
    def obfuscate_command(self, command: str) -> str:
        """Obfuscate command to avoid signature detection"""
        if self.level == OPSECLevel.AGGRESSIVE:
            return command
        
        # Simple obfuscation: command substitution
        obfuscations = {
            "nmap": "\\nmap",
            "sqlmap": "$((\\s\\q\\l\\m\\a\\p))",
            "bash": "sh",
        }
        
        obfuscated = command
        for original, masked in obfuscations.items():
            if original in command:
                obfuscated = obfuscated.replace(original, masked)
                logger.info(f"OPSEC: Obfuscated {original} to {masked}")
        
        return obfuscated
    
    def rotate_proxy(self, proxy_list: List[str]) -> str:
        """Rotate proxy to hide source IP"""
        if not self.randomization["rotate_proxy"]:
            return None
        
        selected = random.choice(proxy_list)
        logger.info(f"OPSEC: Using proxy {selected}")
        return selected
    
    def apply_opsec_wrapper(self, command: str) -> str:
        """Wrap command with OPSEC measures"""
        wrapped = command
        
        # Add timing delays
        if self.delays["scan_delay"] > 0:
            wrapped = f"{wrapped} --scan-delay {self.delays['scan_delay']}"
        
        # Add randomization
        if self.randomization["randomize_packet_order"]:
            wrapped = f"{wrapped} --randomize-hosts"
        
        # Add jitter
        if abs(self.delays["jitter"]) > 0:
            wrapped = f"{wrapped} -T2"  # Paranoid timing template
        
        logger.info(f"OPSEC: Applied wrapper to command")
        return wrapped
    
    def execute_with_opsec(self, command: str, 
                          execution_fn: Callable) -> str:
        """Execute command with OPSEC measures applied"""
        logger.info(f"OPSEC Level: {self.level.name}")
        
        # Pre-execution measures
        wrapped_cmd = self.apply_opsec_wrapper(command)
        
        # Execute
        result = execution_fn(wrapped_cmd)
        
        # Post-execution delays
        self.sleep_between_commands()
        
        return result
    
    def log_opsec_metrics(self) -> Dict:
        """Log OPSEC metrics for audit"""
        return {
            "level": self.level.name,
            "delays": self.delays,
            "randomization": self.randomization,
            "timestamp": time.time(),
            "detection_risk": self._calculate_detection_risk()
        }
    
    def _calculate_detection_risk(self) -> float:
        """Calculate estimated detection risk (0.0 - 1.0)"""
        if self.level == OPSECLevel.STEALTHY:
            return 0.1  # 10% detection risk
        elif self.level == OPSECLevel.BALANCED:
            return 0.5  # 50% detection risk
        else:  # AGGRESSIVE
            return 0.9  # 90% detection risk
    
    def get_scan_config(self, level: OPSECLevel = None) -> Dict:
        """Get scan configuration for given OPSEC level"""
        if level is None:
            level = self.level
        
        opsec = OPSECImplementation(level)
        detection_risk = opsec.calculate_detection_risk() * 100  # Convert to percentage
        
        return {
            'delay_min': opsec.delays.get('scan_delay', 1),
            'delay_max': opsec.delays.get('scan_delay', 1) * 2,
            'randomization': opsec.randomization,
            'level': level.name,
            'detection_risk': int(detection_risk)  # Add detection_risk percentage
        }


# Example Usage
if __name__ == "__main__":
    # Test stealthy mode
    print("=== STEALTHY MODE ===")
    opsec_stealthy = OPSECImplementation(OPSECLevel.STEALTHY)
    metrics = opsec_stealthy.log_opsec_metrics()
    print(f"Detection Risk: {metrics['detection_risk']*100:.1f}%")
    print(f"Inter-command delay: {metrics['delays']['inter_command']:.2f}s\n")
    
    # Test aggressive mode
    print("=== AGGRESSIVE MODE ===")
    opsec_aggressive = OPSECImplementation(OPSECLevel.AGGRESSIVE)
    metrics = opsec_aggressive.log_opsec_metrics()
    print(f"Detection Risk: {metrics['detection_risk']*100:.1f}%")
    print(f"Inter-command delay: {metrics['delays']['inter_command']:.2f}s")