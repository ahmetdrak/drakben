class IntentAnalyzer:
    """
    Kullanıcının niyetini belirler:
    - chat
    - generate_command
    - execute_command
    """

    @staticmethod
    def analyze(user_input: str) -> str:
        text = user_input.lower().strip()

        # Açık çalıştırma niyeti
        if text.startswith("/") or text in ["çalıştır", "uygula", "bunu çalıştır"]:
            return "execute_command"

        # Komut / payload / pentest isteği
        keywords = [
            "nmap", "payload", "exploit", "scan",
            "sessiz", "stealth", "reverse shell",
            "sqlmap", "dirsearch", "nikto"
        ]

        if any(k in text for k in keywords):
            return "generate_command"

        # Varsayılan
        return "chat"
