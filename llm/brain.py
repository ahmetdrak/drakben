# llm/brain.py
# DrakbenBrain - Pentest AI Core

from llm.openrouter_client import OpenRouterClient

class DrakbenBrain:
    def __init__(self):
        # OpenRouter entegrasyonu
        self.client = OpenRouterClient()
        # Hafıza veya zincir için placeholder
        self.last_chain = None

    def think(self, user_input: str):
        """
        Kullanıcı girdisini analiz eder.
        - Eğer zincir planlanırsa chain döner.
        - Eğer zincir yoksa OpenRouter'dan fallback cevabı alınır.
        """
        analysis = {
            "intent": "unknown",
            "chain": None,
            "reply": None
        }

        # Basit örnek: komut kelimeleri zincir tetikler
        if any(word in user_input.lower() for word in ["tara", "scan", "exploit", "payload"]):
            # Burada ChainPlanner kullanılabilir
            analysis["intent"] = "pentest_command"
            analysis["chain"] = [
                {"step": 1, "command": f"nmap -A {user_input}", "output": None},
                {"step": 2, "command": f"nikto -h {user_input}", "output": None}
            ]
            self.last_chain = analysis["chain"]
        else:
            # Zincir yoksa → OpenRouter fallback
            reply = self.client.query(user_input)
            analysis["reply"] = reply

        return analysis

    def continue_chain(self):
        """Son zinciri devam ettirir."""
        return self.last_chain
