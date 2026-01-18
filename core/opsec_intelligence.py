class OPSECIntelligence:
    @staticmethod
    def analyze(command: str) -> dict:
        risk = {
            "noise": "low",
            "detection": "low",
            "artifacts": "none",
            "notes": [],
            "evasion_suggestions": [],
            "stealth_score": 100  # 0-100, higher is stealthier
        }

        cmd = command.lower()

        # Scanning detection
        if any(x in cmd for x in ["nmap -a", "-t5", "masscan"]):
            risk["noise"] = "high"
            risk["detection"] = "high"
            risk["stealth_score"] -= 40
            risk["notes"].append("Yüksek ağ gürültüsü üretir")
            risk["evasion_suggestions"].append("--scan-delay 5s kullan")
            risk["evasion_suggestions"].append("-T2 veya -T1 timing ile yavaşlat")

        # Web scanners
        if any(x in cmd for x in ["nikto", "sqlmap", "dirsearch"]):
            risk["detection"] = "medium"
            risk["stealth_score"] -= 30
            risk["notes"].append("IDS/IPS tetikleyebilir")
            risk["evasion_suggestions"].append("User-Agent değiştir")
            risk["evasion_suggestions"].append("Rate limiting uygula (--delay)")

        # File operations
        if any(x in cmd for x in ["wget", "curl", "nc", "bash", "sh"]):
            risk["artifacts"] = "disk"
            risk["stealth_score"] -= 20
            risk["notes"].append("Disk üzerinde iz bırakabilir")
            risk["evasion_suggestions"].append("/tmp veya in-memory execution kullan")

        # Reverse shells
        if "reverse" in cmd or "shell" in cmd:
            risk["detection"] = "high"
            risk["stealth_score"] -= 35
            risk["notes"].append("Reverse bağlantı tespit edilebilir")
            risk["evasion_suggestions"].append("HTTPS/SSL tünelleme kullan")
            risk["evasion_suggestions"].append("Domain fronting veya CDN üzerinden bağlan")

        # 2024-2025 Advanced Detection Patterns
        if "powershell" in cmd:
            risk["detection"] = "medium"
            risk["stealth_score"] -= 25
            risk["notes"].append("PowerShell execution logged (Event ID 4104)")
            risk["evasion_suggestions"].append("AMSI/ETW bypass kullan")
            risk["evasion_suggestions"].append("Obfuscation + base64 encoding")

        if "mimikatz" in cmd or "lsass" in cmd:
            risk["detection"] = "critical"
            risk["stealth_score"] -= 50
            risk["notes"].append("Credential dumping - EDR alarm")
            risk["evasion_suggestions"].append("Process injection kullan")
            risk["evasion_suggestions"].append("Reflective DLL loading")

        if "docker" in cmd and ("run" in cmd or "exec" in cmd):
            risk["detection"] = "medium"
            risk["stealth_score"] -= 20
            risk["notes"].append("Container operations logged")
            risk["evasion_suggestions"].append("Audit log disable veya rotation")

        # Cloud operations
        if any(x in cmd for x in ["aws", "azure", "gcp", "kubectl"]):
            risk["detection"] = "medium"
            risk["stealth_score"] -= 25
            risk["notes"].append("Cloud API calls logged (CloudTrail/Azure Monitor)")
            risk["evasion_suggestions"].append("Stolen credentials kullan")
            risk["evasion_suggestions"].append("API throttling ile normal görün")

        # Lateral movement
        if any(x in cmd for x in ["psexec", "wmiexec", "smbexec", "ssh"]):
            risk["detection"] = "high"
            risk["stealth_score"] -= 30
            risk["notes"].append("Lateral movement detected")
            risk["evasion_suggestions"].append("Living-off-the-land binaries kullan")

        return risk
    
    @staticmethod
    def get_evasion_techniques_2024_2025():
        """Modern evasion techniques for 2024-2025"""
        return {
            "network": [
                "Domain fronting via CDN",
                "DNS tunneling (iodine, dnscat2)",
                "HTTPS/TLS encryption",
                "Slow/low scanning (-T1, --scan-delay)",
                "Decoy scanning (-D)",
                "Fragmented packets",
                "Randomized source ports"
            ],
            "execution": [
                "AMSI bypass (memory patching)",
                "ETW bypass (provider disabling)",
                "Fileless execution (in-memory)",
                "LOLBins (certutil, bitsadmin, mshta)",
                "Process injection (hollowing, doppelganging)",
                "Reflective DLL loading",
                "Parent process spoofing"
            ],
            "persistence": [
                "Scheduled tasks with LOLBins",
                "WMI event subscriptions",
                "Registry run keys (obfuscated)",
                "COM hijacking",
                "Service creation (hidden)"
            ],
            "credential_access": [
                "LSASS direct system calls (no APIs)",
                "Token impersonation",
                "DCSync without Mimikatz",
                "Kerberoasting with native tools"
            ],
            "defense_evasion": [
                "Disable Windows Defender (via registry)",
                "Timestomping (file timestamp manipulation)",
                "Code signing with stolen certs",
                "DLL side-loading",
                "Process masquerading"
            ],
            "cloud_evasion": [
                "API throttling (blend with normal traffic)",
                "Stolen/temporary credentials",
                "Disable logging services",
                "Log deletion/rotation",
                "Region hopping"
            ]
        }
    
    @staticmethod
    def suggest_stealth_alternatives(command: str) -> list:
        """Suggest stealthier alternatives for risky commands"""
        alternatives = []
        cmd = command.lower()
        
        if "nmap" in cmd and "-t" not in cmd:
            alternatives.append("nmap -T1 --scan-delay 5s (yavaş tarama)")
            alternatives.append("masscan --rate 100 (rate limiting)")
        
        if "sqlmap" in cmd:
            alternatives.append("sqlmap --delay=3 --random-agent (yavaş + rastgele UA)")
            alternatives.append("Manual SQL injection (daha az log)")
        
        if "powershell" in cmd and "encoded" not in cmd:
            alternatives.append("powershell -EncodedCommand (obfuscate)")
            alternatives.append("AMSI bypass + fileless execution")
        
        if "ssh" in cmd or "psexec" in cmd:
            alternatives.append("WMI kullan (daha az log)")
            alternatives.append("Scheduled task ile lateral movement")
        
        if "wget" in cmd or "curl" in cmd:
            alternatives.append("certutil -urlcache (LOLBin)")
            alternatives.append("bitsadmin /transfer (native tool)")
        
        return alternatives if alternatives else ["Komut zaten stealth, öneri yok"]
