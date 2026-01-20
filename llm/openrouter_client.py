# llm/openrouter_client.py
# Multi-Provider LLM Client - OpenRouter, Ollama, OpenAI, Custom
import os
from pathlib import Path

import requests

# Load environment variables - proje kokunden
try:
    from dotenv import load_dotenv
    # Proje kokunu bul
    _this_file = Path(__file__).resolve()
    _project_root = _this_file.parent.parent
    _env_file = _project_root / "config" / "api.env"
    if _env_file.exists():
        load_dotenv(_env_file)
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
            self.model = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
            self.api_key = os.getenv("OPENROUTER_API_KEY")
    
    def query(self, prompt: str, system_prompt: str = None) -> str:
        """Query the LLM with automatic provider routing"""
        
        if system_prompt is None:
            system_prompt = "You are a penetration testing assistant. Provide clear, actionable security advice."
        
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
            return "[Offline Mode] No API key configured."
        
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
                return "[Auth Error] Invalid API key. Check config/api.env"
            elif response.status_code == 429:
                return "[Rate Limit] Too many requests. Wait and retry."
            else:
                return f"[API Error] {response.status_code}: {response.text[:100]}"
        except requests.exceptions.Timeout:
            return "[Timeout] API did not respond. Retry."
        except requests.exceptions.ConnectionError:
            return "[Offline] No internet connection."
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
            result = self.query("Hello")
            return "[Error]" not in result and "[Offline]" not in result
        except Exception:
            return False
