"""
DRAKBEN Local LLM Adapter
Author: @drak_ben
Description: Interface for Local LLMs (Ollama, LM Studio, etc.)
"""

import logging

import requests

logger = logging.getLogger(__name__)


class LocalLLMProvider:
    """
    Client for local inference engines (Ollama compatible).
    """

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.available = self._check_availability()

    def _check_availability(self) -> bool:
        """Check if local LLM service is reachable"""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=1)
            return resp.status_code == 200
        except Exception:
            return False

    def chat_completion(
        self,
        messages: list[dict[str, str]],
        model: str = "llama3",
        temperature: float = 0.7,
    ) -> str | None:
        """
        Send chat request to local LLM.

        Args:
            messages: List of message dicts (role, content)
            model: Model name

        Returns:
            Response string or None
        """
        if not self.available:
            logger.warning("Local LLM not available")
            return None

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }

        try:
            resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=60)
            if resp.status_code == 200:
                return resp.json().get("message", {}).get("content", "")
            else:
                logger.error(f"LLM Error: {resp.status_code} - {resp.text}")
                return None
        except Exception as e:
            logger.error(f"LLM Connection Failed: {e}")
            return None

    def list_models(self) -> list[str]:
        """Get list of available local models"""
        if not self.available:
            return []
        try:
            resp = requests.get(f"{self.base_url}/api/tags")
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []
