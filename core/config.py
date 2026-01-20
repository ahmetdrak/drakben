# core/config.py
# Configuration & Session Management

import os
import json
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
from dotenv import load_dotenv


@dataclass
class DrakbenConfig:
    """DRAKBEN configuration"""
    # LLM Settings
    llm_provider: str = "auto"  # auto, openrouter, ollama, openai
    openrouter_api_key: Optional[str] = None
    openrouter_model: str = "meta-llama/llama-3.1-8b-instruct:free"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"

    # Setup
    llm_setup_complete: bool = False
    
    # UI Settings
    language: str = "tr"  # tr, en
    use_colors: bool = True
    verbose: bool = False
    
    # Security
    auto_approve: bool = False  # First command needs approval
    approved_once: bool = False
    
    # Session
    target: Optional[str] = None
    session_dir: str = "sessions"
    log_dir: str = "logs"
    
    # Tools
    tools_available: Dict[str, bool] = None
    
    def __post_init__(self):
        if self.tools_available is None:
            self.tools_available = {}


class ConfigManager:
    """Manage configuration and sessions"""
    
    def __init__(self, config_file: str = "config/settings.json"):
        self.config_file = Path(config_file)
        self.config = self.load_config()
        self._load_env()
    
    def _load_env(self):
        """Load API keys from .env"""
        env_file = Path("config/api.env")
        if env_file.exists():
            load_dotenv(env_file)
        
        # Override with environment variables
        if os.getenv("OPENROUTER_API_KEY"):
            self.config.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        if os.getenv("OPENAI_API_KEY"):
            self.config.openai_api_key = os.getenv("OPENAI_API_KEY")
        if os.getenv("LOCAL_LLM_URL"):
            self.config.ollama_url = os.getenv("LOCAL_LLM_URL")
        if os.getenv("LOCAL_LLM_MODEL"):
            self.config.ollama_model = os.getenv("LOCAL_LLM_MODEL")

        # Mark setup complete if any provider is configured
        if any([
            os.getenv("OPENROUTER_API_KEY"),
            os.getenv("OPENAI_API_KEY"),
            os.getenv("LOCAL_LLM_URL"),
            os.getenv("LOCAL_LLM_MODEL")
        ]):
            self.config.llm_setup_complete = True

    def _read_env_file(self) -> Dict[str, str]:
        """Read api.env into a dict"""
        env_path = Path("config/api.env")
        values: Dict[str, str] = {}

        if not env_path.exists():
            return values

        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

        return values

    def _write_env_file(self, values: Dict[str, str]):
        """Write api.env from a dict"""
        env_path = Path("config/api.env")
        env_path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "# LLM Configuration",
            "",
            f"OPENROUTER_API_KEY={values.get('OPENROUTER_API_KEY', '')}",
            f"OPENROUTER_MODEL={values.get('OPENROUTER_MODEL', 'meta-llama/llama-3.1-8b-instruct:free')}",
            "",
            f"OPENAI_API_KEY={values.get('OPENAI_API_KEY', '')}",
            f"OPENAI_MODEL={values.get('OPENAI_MODEL', 'gpt-4o-mini')}",
            "",
            f"LOCAL_LLM_URL={values.get('LOCAL_LLM_URL', 'http://localhost:11434')}",
            f"LOCAL_LLM_MODEL={values.get('LOCAL_LLM_MODEL', 'llama3.1')}",
            "",
            "# Leave keys empty to stay in offline mode"
        ]

        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def prompt_llm_setup_if_needed(self):
        """Ask for optional LLM setup on first run (only if api.env is missing or empty)"""
        if self.config.llm_setup_complete:
            return

        env_path = Path("config/api.env")
        existing = self._read_env_file()

        if env_path.exists() and any([
            existing.get("OPENROUTER_API_KEY"),
            existing.get("OPENAI_API_KEY"),
            existing.get("LOCAL_LLM_URL"),
            existing.get("LOCAL_LLM_MODEL")
        ]):
            self.config.llm_setup_complete = True
            self.save_config()
            return

        if env_path.exists() and not any([
            existing.get("OPENROUTER_API_KEY"),
            existing.get("OPENAI_API_KEY"),
            existing.get("LOCAL_LLM_URL"),
            existing.get("LOCAL_LLM_MODEL")
        ]):
            # api.env exists but is empty; continue to prompt
            pass

        print("\n🔧 LLM yapılandırmasını şimdi yapmak ister misiniz? (e/h)")
        choice = input("> ").strip().lower()
        if choice not in ["e", "y", "evet", "yes"]:
            self.config.llm_setup_complete = True
            self.save_config()
            return

        print("\nProvider seçin: 1) OpenRouter  2) OpenAI  3) Ollama (Local)  4) Geç")
        provider_choice = input("> ").strip()

        env_values = existing.copy()

        if provider_choice == "1":
            self.config.llm_provider = "openrouter"
            api_key = input("OpenRouter API key: ").strip()
            model = input("Model (boş bırak: default): ").strip()
            if api_key:
                env_values["OPENROUTER_API_KEY"] = api_key
                self.config.openrouter_api_key = api_key
            if model:
                env_values["OPENROUTER_MODEL"] = model
                self.config.openrouter_model = model

        elif provider_choice == "2":
            self.config.llm_provider = "openai"
            api_key = input("OpenAI API key: ").strip()
            model = input("Model (boş bırak: default): ").strip()
            if api_key:
                env_values["OPENAI_API_KEY"] = api_key
                self.config.openai_api_key = api_key
            if model:
                env_values["OPENAI_MODEL"] = model
                self.config.openai_model = model

        elif provider_choice == "3":
            self.config.llm_provider = "ollama"
            url = input("Ollama URL (boş bırak: http://localhost:11434): ").strip()
            model = input("Ollama model (boş bırak: llama3.1): ").strip()
            env_values["LOCAL_LLM_URL"] = url or env_values.get("LOCAL_LLM_URL", "http://localhost:11434")
            env_values["LOCAL_LLM_MODEL"] = model or env_values.get("LOCAL_LLM_MODEL", "llama3.1")
            self.config.ollama_url = env_values["LOCAL_LLM_URL"]
            self.config.ollama_model = env_values["LOCAL_LLM_MODEL"]

        else:
            self.config.llm_setup_complete = True
            self.save_config()
            return

        self._write_env_file(env_values)
        self.config.llm_setup_complete = True
        self.save_config()
    
    def load_config(self) -> DrakbenConfig:
        """Load configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return DrakbenConfig(**data)
            except Exception as e:
                print(f"⚠️  Config load error: {e}")
        
        return DrakbenConfig()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.config), f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"⚠️  Config save error: {e}")
    
    def set_language(self, lang: str):
        """Set interface language"""
        if lang in ["tr", "en"]:
            self.config.language = lang
            self.save_config()
    
    def set_target(self, target: str):
        """Set target"""
        self.config.target = target
        self.save_config()
    
    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration"""
        return {
            "provider": self.config.llm_provider,
            "openrouter_api_key": self.config.openrouter_api_key,
            "openrouter_model": self.config.openrouter_model,
            "ollama_url": self.config.ollama_url,
            "ollama_model": self.config.ollama_model,
            "openai_api_key": self.config.openai_api_key,
            "openai_model": self.config.openai_model,
        }
    
    def mark_approved(self):
        """Mark that user has approved once"""
        self.config.approved_once = True
        self.save_config()
    
    def reset_approval(self):
        """Reset approval state"""
        self.config.approved_once = False
        self.save_config()


class SessionManager:
    """Manage penetration testing sessions"""
    
    def __init__(self, session_dir: str = "sessions"):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.current_session = {
            "target": None,
            "commands": [],
            "findings": [],
            "notes": []
        }
    
    def save_session(self, target: str):
        """Save current session"""
        try:
            import time
            timestamp = int(time.time())
            filename = f"{target.replace('.', '_').replace(':', '_')}_{timestamp}.json"
            filepath = self.session_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.current_session, f, indent=2, ensure_ascii=False)
            
            return filepath
        except Exception as e:
            print(f"⚠️  Session save error: {e}")
            return None
    
    def load_session(self, filename: str) -> Optional[Dict]:
        """Load a session"""
        try:
            filepath = self.session_dir / filename
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"⚠️  Session load error: {e}")
        return None
    
    def list_sessions(self) -> list:
        """List all sessions"""
        sessions = []
        for file in self.session_dir.glob("*.json"):
            sessions.append(file.name)
        return sorted(sessions, reverse=True)
    
    def add_command(self, command: str, output: str):
        """Add command to session"""
        self.current_session["commands"].append({
            "command": command,
            "output": output[:500]  # Limit output size
        })
    
    def add_finding(self, finding: str):
        """Add finding to session"""
        self.current_session["findings"].append(finding)
    
    def add_note(self, note: str):
        """Add note to session"""
        self.current_session["notes"].append(note)
