class OPSECIntelligence:
    @staticmethod
    def analyze(command: str) -> dict:
        risk = {
            "noise": "low",
            "detection": "low",
            "artifacts": "none",
            "notes": []
        }

        cmd = command.lower()

        if any(x in cmd for x in ["nmap -a", "-t5", "masscan"]):
            risk["noise"] = "high"
            risk["detection"] = "high"
            risk["notes"].append("Yüksek ağ gürültüsü üretir")

        if any(x in cmd for x in ["nikto", "sqlmap", "dirsearch"]):
            risk["detection"] = "medium"
            risk["notes"].append("IDS/IPS tetikleyebilir")

        if any(x in cmd for x in ["wget", "curl", "nc", "bash", "sh"]):
            risk["artifacts"] = "disk"
            risk["notes"].append("Disk üzerinde iz bırakabilir")

        if "reverse" in cmd or "shell" in cmd:
            risk["detection"] = "high"
            risk["notes"].append("Reverse bağlantı tespit edilebilir")

        return risk
