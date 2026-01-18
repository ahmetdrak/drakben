# llm/openrouter_client.py
import os
import sys
import json
import requests
from pathlib import Path

# Çevre değişkenlerini yükle
try:
    from dotenv import load_dotenv
    load_dotenv("config/api.env")
except ImportError:
    pass  # dotenv yoksa, sadece OS env'i kullan

class OpenRouterClient:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        if not self.api_key and sys.stdin.isatty():
            # Prompt user once for API key to enable cloud mode (optional)
            try:
                print("[Optional] OpenRouter API key gir (boş bırakırsan offline devam):", end=" ")
                user_key = input().strip()
                if user_key:
                    self.api_key = user_key
                    # Persist to config/api.env for next runs
                    config_dir = Path("config")
                    config_dir.mkdir(exist_ok=True)
                    api_env = config_dir / "api.env"
                    # Avoid duplicating the key if file exists
                    lines = []
                    if api_env.exists():
                        with api_env.open("r", encoding="utf-8", errors="ignore") as f:
                            lines = [ln.rstrip("\n") for ln in f.readlines()]
                    # Replace existing key line or append new
                    found = False
                    new_lines = []
                    for ln in lines:
                        if ln.startswith("OPENROUTER_API_KEY="):
                            new_lines.append(f"OPENROUTER_API_KEY={user_key}")
                            found = True
                        else:
                            new_lines.append(ln)
                    if not found:
                        new_lines.append(f"OPENROUTER_API_KEY={user_key}")
                    with api_env.open("w", encoding="utf-8") as f:
                        f.write("\n".join([ln for ln in new_lines if ln.strip()]))
                        f.write("\n")
            except Exception:
                # Fail silently to keep offline mode working
                pass
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
