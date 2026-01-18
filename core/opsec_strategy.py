# core/opsec_strategy.py
# DRAKBEN OPSEC Strategy - Sessiz vs Agresif Tarama Seçimi

class OPSECStrategy:
    """
    Tarama stratejisini belirler ve komutları optimize eder
    """
    
    STRATEGIES = {
        "stealth": {
            "name": "🤫 Sessiz Tarama (Stealth)",
            "description": "Detection avoidance - Yavaş, gizli, IDS/WAF bypass",
            "nmap_args": "-sS -Pn -f --scan-delay 5s -T2",
            "nikto_args": "-no-404 -maxtime 3600 -Tuning 9",
            "sqlmap_args": "--technique=T --delay=2 --randomAgent --crawlDepth=1",
            "noise_level": "very_low",
            "detection_risk": 5,
            "speed": "slow",
        },
        "balanced": {
            "name": "⚖️ Dengeli Tarama (Balanced)",
            "description": "Normal hız, orta risk - Gerçek pentest senaryoları",
            "nmap_args": "-sV -sC -p- --max-retries 2 -T3",
            "nikto_args": "-C all",
            "sqlmap_args": "--technique=BEUST --level=3 --risk=2",
            "noise_level": "medium",
            "detection_risk": 50,
            "speed": "normal",
        },
        "aggressive": {
            "name": "🔥 Agresif Tarama (Aggressive)",
            "description": "Maksimum hız, yüksek risk - Çabuk sonuç",
            "nmap_args": "-A -p- -T4 --max-retries 1",
            "nikto_args": "-C all -F",
            "sqlmap_args": "--technique=BEUST --level=5 --risk=3",
            "noise_level": "high",
            "detection_risk": 95,
            "speed": "fast",
        }
    }
    
    @staticmethod
    def select_strategy(user_choice=None):
        """Stratejiy seç ve döndür"""
        if user_choice and user_choice in OPSECStrategy.STRATEGIES:
            return OPSECStrategy.STRATEGIES[user_choice]
        return OPSECStrategy.STRATEGIES["balanced"]  # Default
    
    @staticmethod
    def get_tool_options(strategy: str, tool: str) -> str:
        """Stratejiye göre tool argümanlarını döndür"""
        strat = OPSECStrategy.STRATEGIES.get(strategy, OPSECStrategy.STRATEGIES["balanced"])
        key = f"{tool}_args"
        return strat.get(key, "")
    
    @staticmethod
    def display_strategies():
        """Tüm stratejileri göster"""
        print("\n🛡 OPSEC STRATEJILERI:\n")
        for key, strat in OPSECStrategy.STRATEGIES.items():
            print(f"[{key.upper()}] {strat['name']}")
            print(f"    📝 {strat['description']}")
            print(f"    ⚠️  Detection Risk: {strat['detection_risk']}%")
            print(f"    ⏱️  Speed: {strat['speed']}")
            print()
