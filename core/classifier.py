import re

class InputClassifier:
    COMMAND_PATTERNS = [
        r"^/",
        r"\b(ls|cd|pwd|cat|whoami|id)\b",
        r"\b(nmap|sqlmap|nikto|dirsearch|ffuf|hydra)\b",
        r"\b(bash|sh|nc|netcat|python|perl)\b",
        r"[|><;&]"
    ]

    @staticmethod
    def classify(text: str) -> str:
        text = text.strip()

        if not text:
            return "empty"

        # Slash ile başlıyorsa kesin komut
        if text.startswith("/"):
            return "command"

        # Komut pattern eşleşmesi
        for pattern in InputClassifier.COMMAND_PATTERNS:
            if re.search(pattern, text):
                return "command"

        # Tek kelime ama riskli
        if len(text.split()) == 1:
            return "ambiguous"

        return "chat"
