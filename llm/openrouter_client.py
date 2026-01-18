# llm/openrouter_client.py
# Multi-Provider LLM Client - OpenRouter, Ollama, OpenAI, Custom
import os
import sys
import json
import requests
from pathlib import Path

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv("config/api.env")
except ImportError:
    pass  # dotenv not installed, use OS env


class OpenRouterClient:
    """
    Multi-provider LLM client supporting:
    - OpenRouter (100+ models including free ones)
    - Ollama (local LLMs)
    - OpenAI Direct
    - Custom OpenAI-compatible APIs
    """
    
    def __init__(self):
        self.provider = self._detect_provider()
        self._setup_provider()
    
    def _detect_provider(self) -> str:
        """Auto-detect which LLM provider to use"""
        if os.getenv("LOCAL_LLM_URL"):
            return "ollama"
        elif os.getenv("OPENAI_API_KEY") and not os.getenv("OPENROUTER_API_KEY"):
            return "openai"
        elif os.getenv("CUSTOM_API_URL"):
            return "custom"
        else:
            return "openrouter"
    
    def _setup_provider(self):
        """Setup provider-specific configuration"""
        if self.provider == "ollama":
            self.base_url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/api/generate")
            self.model = os.getenv("LOCAL_LLM_MODEL", "llama3.1")
            self.api_key = None
        elif self.provider == "openai":
            self.base_url = "https://api.openai.com/v1/chat/completions"
            self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            self.api_key = os.getenv("OPENAI_API_KEY")
        elif self.provider == "custom":
            self.base_url = os.getenv("CUSTOM_API_URL")
            self.model = os.getenv("CUSTOM_MODEL", "default")
            self.api_key = os.getenv("CUSTOM_API_KEY")
        else:  # openrouter (default)
            self.base_url = "https://openrouter.ai/api/v1/chat/completions"
            self.model = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")
            self.api_key = os.getenv("OPENROUTER_API_KEY")
            
            # Interactive API key prompt if not set
            if not self.api_key and sys.stdin.isatty():
                self._prompt_for_api_key()
    
    def _prompt_for_api_key(self):
        """Prompt user for API key interactively"""
        try:
            print("[Optional] OpenRouter API key gir (bos birakirsan offline devam):", end=" ")
            user_key = input().strip()
            if user_key:
                self.api_key = user_key
                self._save_api_key(user_key)
        except Exception:
            pass  # Fail silently for offline mode
    
    def _save_api_key(self, key: str):
        """Save API key to config file"""
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        api_env = config_dir / "api.env"
        
        lines = []
        if api_env.exists():
            with api_env.open("r", encoding="utf-8", errors="ignore") as f:
                lines = [ln.rstrip("\n") for ln in f.readlines()]
        
        # Update or add key
        found = False
        new_lines = []
        for ln in lines:
            if ln.startswith("OPENROUTER_API_KEY="):
                new_lines.append(f"OPENROUTER_API_KEY={key}")
                found = True
            else:
                new_lines.append(ln)
        if not found:
            new_lines.append(f"OPENROUTER_API_KEY={key}")
        
        with api_env.open("w", encoding="utf-8") as f:
            f.write("\n".join([ln for ln in new_lines if ln.strip()]))
            f.write("\n")

    def query(self, prompt: str, system_prompt: str = None) -> str:
        """Query the LLM with automatic provider routing"""
        
        if system_prompt is None:
            system_prompt = (
                "Ben Drakben'im. 2026 yilina yonelik gelismis bir pentest yapay zeka asistaniyim. "
                "DRAKBEN = Dusunen, Reaktif, Akilli, Karanlik Bilgi Engeli. "
                "Turkce konusurum, pentest odakliyim: Recon -> Exploit -> Payload zincirlerini planlarim."
            )
        
        if self.provider == "ollama":
            return self._query_ollama(prompt, system_prompt)
        else:
            return self._query_openai_compatible(prompt, system_prompt)
    
    def _query_ollama(self, prompt: str, system_prompt: str) -> str:
        """Query local Ollama instance"""
        try:
            payload = {
                "model": self.model,
                "prompt": f"{system_prompt}\n\nUser: {prompt}\n\nAssistant:",
                "stream": False
            }
            response = requests.post(self.base_url, json=payload, timeout=60)
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                return f"[Ollama Error] {response.status_code}: {response.text[:100]}"
        except requests.exceptions.ConnectionError:
            return "[Offline] Ollama baglantisi yok. 'ollama serve' calistirin."
        except Exception as e:
            return f"[Ollama Error] {str(e)}"
    
    def _query_openai_compatible(self, prompt: str, system_prompt: str) -> str:
        """Query OpenAI-compatible API (OpenRouter, OpenAI, Custom)"""
        if not self.api_key:
            return "[Offline Mode] API key yok. Fallback modunda calisiyorum."
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Add OpenRouter-specific headers
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/ahmetdrak/drakben"
            headers["X-Title"] = "DRAKBEN Pentest AI"
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        }
        
        try:
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            elif response.status_code == 401:
                return "[Auth Error] API key gecersiz. .env dosyasini kontrol edin."
            elif response.status_code == 429:
                return "[Rate Limit] Cok fazla istek. Biraz bekleyin."
            else:
                return f"[API Error] {response.status_code}: {response.text[:100]}"
        except requests.exceptions.Timeout:
            return "[Timeout] API yanit vermedi. Tekrar deneyin."
        except requests.exceptions.ConnectionError:
            return "[Offline] Internet baglantisi yok."
        except Exception as e:
            return f"[Error] {str(e)}"
    
    def get_provider_info(self) -> dict:
        """Return current provider configuration"""
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "has_api_key": bool(self.api_key)
        }
    
    def test_connection(self) -> bool:
        """Test if the LLM connection is working"""
        try:
            result = self.query("Merhaba, calisiyor musun?")
            return "[Error]" not in result and "[Offline]" not in result
        except Exception:
            return False
