# llm/brain.py
# DrakbenBrain - Pentest AI Core

from llm.openrouter_client import OpenRouterClient

class DrakbenBrain:
    def __init__(self):
        # OpenRouter entegrasyonu
        self.client = OpenRouterClient()
        # Hafıza veya zincir için placeholder
        self.last_chain = None
        # Fallback cevaplar (API key yoksa)
        self.fallback_responses = {
            "scan": "Hedef taraması için: nmap -sV -p- target_ip",
            "exploit": "Exploit seçmek için mevcut zaaflara bak: cve.mitre.org",
            "payload": "Payload üretimi için msfvenom kullan: msfvenom -p windows/shell_reverse_tcp",
            "help": "Komutlar: scan [target], exploit [cve], payload [type]"
        }

    def think(self, user_input: str):
        """
        Kullanıcı girdisini analiz eder.
        - Eğer zincir planlanırsa chain döner.
        - Eğer zincir yoksa fallback veya OpenRouter cevabı alınır.
        """
        analysis = {
            "intent": "unknown",
            "chain": None,
            "reply": None
        }

        # Basit örnek: komut kelimeleri zincir tetikler
        pentest_keywords = ["tara", "scan", "exploit", "payload", "nmap", "sqlmap", "nikto"]
        if any(word in user_input.lower() for word in pentest_keywords):
            # Burada ChainPlanner kullanılabilir
            analysis["intent"] = "pentest_command"
            analysis["chain"] = [
                {"step": 1, "action": "Recon", "suggestion": f"nmap -sV -p- {user_input}", "output": None, "notes": "AI tarafından önerilen scan"},
                {"step": 2, "action": "Enumeration", "suggestion": f"nikto -h {user_input}", "output": None, "notes": "AI tarafından önerilen web enum"}
            ]
            self.last_chain = analysis["chain"]
        else:
            # Zincir yoksa → OpenRouter fallback (hatalı API key toleransı)
            try:
                reply = self.client.query(user_input)
                if "hatası" not in reply.lower():
                    analysis["reply"] = reply
                else:
                    # API hatası → fallback kelime match
                    analysis["reply"] = self._fallback_reply(user_input)
            except Exception as e:
                # Bağlantı hatası → fallback
                analysis["reply"] = self._fallback_reply(user_input)

        return analysis

    def _fallback_reply(self, user_input: str) -> str:
        """API yoksa fallback cevaplar döner."""
        user_lower = user_input.lower()
        for keyword, response in self.fallback_responses.items():
            if keyword in user_lower:
                return f"[Fallback Mode] {response}"
        return "🤖 Bunu öğrenmek için daha fazla bilgi gerekli. API key kontrol et veya spesifik komut kullan."

    def continue_chain(self):
        """Son zinciri devam ettirir."""
        return self.last_chain
