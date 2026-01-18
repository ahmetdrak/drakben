# core/advanced_chain_builder.py
# Advanced Chain Builder - Stratejiye Göre Zincir Oluşturma (Stealthy/Aggressive)

class AdvancedChainBuilder:
    """
    OPSEC stratejisine göre (stealth/aggressive) pentest zinciri oluştur
    """
    
    def __init__(self):
        self.strategies = {
            "stealthy": {
                "desc": "Sessiz - Detection risk düşük, yavaş",
                "detection_risk": "low",
                "speed": "slow",
                "noisiness": "quiet"
            },
            "balanced": {
                "desc": "Dengelenmiş - Normal pentest",
                "detection_risk": "medium",
                "speed": "medium",
                "noisiness": "normal"
            },
            "aggressive": {
                "desc": "Agresif - Hızlı, detection risk yüksek",
                "detection_risk": "high",
                "speed": "fast",
                "noisiness": "loud"
            }
        }
    
    def build_chain(self, goal: str, strategy: str = "balanced", target: str = "unknown") -> list:
        """
        Strateji bazında zincir oluştur
        """
        goal = goal.lower()
        chain = []
        
        if strategy not in self.strategies:
            strategy = "balanced"
        
        strat = self.strategies[strategy]
        
        # ===== RECON PHASE =====
        if strategy == "stealthy":
            chain.append({
                "step": len(chain) + 1,
                "phase": "RECON",
                "action": "Passive Recon",
                "suggestion": f"whois {target}",
                "risk": "none",
                "evasion": "passive",
                "notes": "WHOIS query - No logging"
            })
            chain.append({
                "step": len(chain) + 1,
                "phase": "RECON",
                "action": "DNS Lookup",
                "suggestion": f"nslookup {target}",
                "risk": "low",
                "evasion": "passive"
            })
        
        elif strategy == "aggressive":
            chain.append({
                "step": len(chain) + 1,
                "phase": "RECON",
                "action": "Aggressive Scan",
                "suggestion": f"nmap -sS -p- -A -T4 {target}",
                "risk": "high",
                "evasion": "none",
                "notes": "Full scan - Heavy logging"
            })
        
        else:  # balanced
            chain.append({
                "step": len(chain) + 1,
                "phase": "RECON",
                "action": "Port Scan",
                "suggestion": f"nmap -sV -p- {target}",
                "risk": "medium",
                "evasion": "standard"
            })
        
        # ===== WEB PHASE =====
        if "web" in goal:
            if strategy == "stealthy":
                chain.append({
                    "step": len(chain) + 1,
                    "phase": "ENUMERATION",
                    "action": "Slow Web Scan",
                    "suggestion": f"nikto -h http://{target} -T 5 -o /dev/null",
                    "risk": "low",
                    "evasion": "rate_limiting",
                    "notes": "Slow scan - avoids WAF"
                })
            else:
                chain.append({
                    "step": len(chain) + 1,
                    "phase": "ENUMERATION",
                    "action": "Web Enumeration",
                    "suggestion": f"dirsearch -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
                    "risk": "medium" if strategy == "balanced" else "high",
                    "evasion": "user-agent-rotation" if strategy == "stealthy" else "none"
                })
        
        # ===== EXPLOITATION PHASE =====
        if "exploit" in goal:
            if strategy == "stealthy":
                chain.append({
                    "step": len(chain) + 1,
                    "phase": "EXPLOITATION",
                    "action": "Targeted Exploit",
                    "suggestion": "Manual verification required",
                    "risk": "medium",
                    "evasion": "custom_payload",
                    "notes": "Uses custom obfuscated payloads"
                })
            else:
                chain.append({
                    "step": len(chain) + 1,
                    "phase": "EXPLOITATION",
                    "action": "SQL Injection Test",
                    "suggestion": f"sqlmap -u 'http://{target}/search?q=test' --batch",
                    "risk": "high",
                    "evasion": "none"
                })
        
        return chain
    
    def add_evasion_techniques(self, command: str, strategy: str) -> str:
        """Evasion teknikler ekle"""
        if strategy == "stealthy":
            # User-Agent spoofing
            command = command.replace("nmap", "nmap -sS --scan-delay 500ms")
            # Add decoys
            if "-sS" in command:
                command = command.replace("-sS", "-sS -D RND:5")
            return command
        
        return command
