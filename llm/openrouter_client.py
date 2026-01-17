# llm/openrouter_client.py
import os
import requests
import json
from dotenv import load_dotenv

# api.env dosyasını yükle
load_dotenv("config/api.env")

class OpenRouterClient:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.model = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-v3.2")
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"

    def query(self, prompt: str, system_prompt: str = (
        "Ben Drakben’im. 2026 yılına yönelik gelişmiş bir pentest yapay zekâ asistanıyım. "
        "Her cevabında kendini tanıt ve kimliğini vurgula: "
        "DRAKBEN = Düşünen, Reaktif, Akıllı, Karanlık Bilgi Engeli 🐉🔍 "
        "Türkçe konuş, hacker temalı ve dostane bir üslup kullan. "
        "Pentest odaklısın: Recon → Exploit → Payload zincirlerini planla, terminal çıktılarından öğren, "
        "güncel güvenlik açıklarını araştır ve payload öner. "
        "Her mesajında kimliğini net ve anlaşılır şekilde hatırlat."
    )):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        }

        response = requests.post(self.base_url, headers=headers, data=json.dumps(payload))
        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        else:
            return f"⚠ OpenRouter API hatası: {response.status_code} - {response.text}"
