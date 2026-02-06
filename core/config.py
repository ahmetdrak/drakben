# core/config.py
# Configuration & Session Management
# Thread-safe implementation

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Setup logger
logger = logging.getLogger(__name__)

# Constants
API_ENV_PATH = "config/api.env"


# ===========================================
# CENTRALIZED TIMEOUT CONFIGURATION
# All modules should use these values for consistency
# ===========================================
class TimeoutConfig:
    """Centralized timeout settings for consistency across modules."""

    # Database timeouts
    SQLITE_CONNECT_TIMEOUT = 10.0  # seconds
    SQLITE_BUSY_TIMEOUT = 10000  # milliseconds

    # Network timeouts
    HTTP_REQUEST_TIMEOUT = 30  # seconds
    SOCKET_TIMEOUT = 10  # seconds
    DNS_RESOLVER_TIMEOUT = 5  # seconds
    SMB_TIMEOUT = 2  # seconds

    # LLM timeouts
    LLM_QUERY_TIMEOUT = 30  # seconds
    LLM_STREAMING_TIMEOUT = 60  # seconds
    LLM_MAX_STREAM_TIME = 300  # 5 minutes max

    # Tool execution timeouts
    TOOL_DEFAULT_TIMEOUT = 300  # 5 minutes
    TOOL_FAST_TIMEOUT = 60  # 1 minute for fast tools
    TOOL_SLOW_TIMEOUT = 600  # 10 minutes for slow tools
    SUBPROCESS_TIMEOUT = 120  # 2 minutes for subprocesses

    # Thread timeouts
    THREAD_JOIN_TIMEOUT = 5.0  # seconds
    LOCK_ACQUIRE_TIMEOUT = 5.0  # seconds

    # Process timeouts
    PROCESS_TERMINATE_TIMEOUT = 5  # seconds before kill
    PROCESS_CLEANUP_TIMEOUT = 2  # seconds for cleanup

    # Shell/Connection timeouts
    SSH_COMMAND_TIMEOUT = 30  # seconds
    REVERSE_SHELL_TIMEOUT = 60  # seconds
    SHELL_READ_TIMEOUT = 10  # seconds


# Export for easy import
TIMEOUTS = TimeoutConfig()


# ===========================================
# C2 BEACON CONFIGURATION
# ===========================================
class C2BeaconConfig:
    """Centralized C2 beacon settings for consistency."""

    # Sleep intervals
    DEFAULT_SLEEP_INTERVAL = 60  # seconds between check-ins
    MIN_SLEEP_INTERVAL = 10  # minimum sleep time
    MAX_SLEEP_INTERVAL = 3600  # 1 hour max

    # Jitter (randomization)
    JITTER_MIN = 10  # minimum jitter percentage
    JITTER_MAX = 30  # maximum jitter percentage

    # Protocol defaults
    DEFAULT_PORT_HTTPS = 443
    DEFAULT_PORT_HTTP = 80
    DEFAULT_PORT_DNS = 53

    # Retry settings
    MAX_RETRY_ATTEMPTS = 3
    RETRY_BACKOFF_MULTIPLIER = 2  # exponential backoff

    # Steganography
    STEGO_IMAGE_WIDTH = 800
    STEGO_IMAGE_HEIGHT = 600


# Export for easy import
C2_CONFIG = C2BeaconConfig()


# ===========================================
# NETWORK SCANNING CONFIGURATION
# ===========================================
class NetworkConfig:
    """Centralized network scanning settings."""

    # Common ports for quick scans
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                   993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

    # Port scan settings
    MAX_CONCURRENT_SCANS = 100
    PORT_SCAN_TIMEOUT = 2.0  # seconds per port
    PING_TIMEOUT = 1.0  # seconds

    # Stealth mode delays
    STEALTH_DELAY_MIN = 0.5  # seconds
    STEALTH_DELAY_MAX = 2.0  # seconds

    # DNS settings
    DNS_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]


# Export for easy import
NETWORK_CONFIG = NetworkConfig()


@dataclass
class DrakbenConfig:
    """DRAKBEN configuration."""

    # LLM Settings
    llm_provider: str = "auto"  # auto, openrouter, ollama, openai
    openrouter_api_key: str | None = None
    openrouter_model: str = "meta-llama/llama-3.1-8b-instruct:free"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"

    # Setup
    llm_setup_complete: bool = False

    # UI Settings
    language: str = "en"  # tr, en - Default English
    use_colors: bool = True
    verbose: bool = False

    # Security
    auto_approve: bool = False  # First command needs approval
    approved_once: bool = False
    ssl_verify: bool = True  # SSL certificate verification
    allow_self_signed_certs: bool = False  # Allow self-signed certificates

    # Session
    target: str | None = None
    session_dir: str = "sessions"
    log_dir: str = "logs"

    # Engine Settings
    stealth_mode: bool = False
    max_threads: int = 4
    timeout: int = 30

    # Tools
    tools_available: dict[str, bool] | None = None

    # System Settings (Added to match config.json)
    system: dict[str, Any] | None = None

    def __post_init__(self) -> Any:
        if self.tools_available is None:
            self.tools_available = {}


class ConfigManager:
    """Manage configuration and sessions.
    Thread-safe implementation with locking.
    """

    def __init__(self, config_file: str = "config/settings.json") -> None:
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        self.config_file = Path(config_file)
        self.config = self.load_config()
        self._load_env()
        self._llm_client = None  # Lazy initialization

    def _load_env(self) -> None:
        """Load API keys from .env."""
        env_file = Path(API_ENV_PATH)
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
        if any(
            [
                os.getenv("OPENROUTER_API_KEY"),
                os.getenv("OPENAI_API_KEY"),
                os.getenv("LOCAL_LLM_URL"),
                os.getenv("LOCAL_LLM_MODEL"),
            ],
        ):
            self.config.llm_setup_complete = True

    def _read_env_file(self) -> dict[str, str]:
        """Read api.env into a dict."""
        env_path = Path(API_ENV_PATH)
        values: dict[str, str] = {}

        if not env_path.exists():
            return values

        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

        return values

    def _write_env_file(self, values: dict[str, str]) -> None:
        """Write api.env from a dict."""
        env_path = Path(API_ENV_PATH)
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
            "# Leave keys empty to stay in offline mode",
        ]

        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def prompt_llm_setup_if_needed(self) -> None:
        """Ask for optional LLM setup on first run (only if api.env is missing or empty)."""
        if self.config.llm_setup_complete:
            return

        env_path = Path(API_ENV_PATH)
        existing = self._read_env_file()

        if env_path.exists() and any(
            [
                existing.get("OPENROUTER_API_KEY"),
                existing.get("OPENAI_API_KEY"),
                existing.get("LOCAL_LLM_URL"),
                existing.get("LOCAL_LLM_MODEL"),
            ],
        ):
            self.config.llm_setup_complete = True
            self.save_config()
            return

        if env_path.exists() and not any(
            [
                existing.get("OPENROUTER_API_KEY"),
                existing.get("OPENAI_API_KEY"),
                existing.get("LOCAL_LLM_URL"),
                existing.get("LOCAL_LLM_MODEL"),
            ],
        ):
            # api.env exists but is empty; continue to prompt
            pass

        # Interactive LLM setup prompt
        from rich.console import Console

        console = Console()

        if not self._prompt_user_consent(console):
            self.config.llm_setup_complete = True
            self.save_config()
            return

        console.print(
            "\n[bold]Select provider:[/] 1) OpenRouter  2) OpenAI  3) Ollama (Local)  4) Skip",
        )
        provider_choice = input("> ").strip()

        env_values = existing.copy()

        if not self._configure_provider(provider_choice, env_values):
            self.config.llm_setup_complete = True
            self.save_config()
            return

        self._write_env_file(env_values)
        self.config.llm_setup_complete = True
        self.save_config()

    def _prompt_user_consent(self, console) -> bool:
        """Ask user if they want to configure LLM."""
        console.print("\n[bold cyan]Configure LLM now? (y/n)[/]")
        choice = input("> ").strip().lower()
        return choice in ["e", "y", "evet", "yes"]

    def _configure_provider(self, choice: str, env_values: dict[str, str]) -> bool:
        """Configure specific provider based on user choice."""
        if choice == "1":
            self.config.llm_provider = "openrouter"
            api_key = input("OpenRouter API key: ").strip()
            model = input("Model (leave empty for default): ").strip()
            if api_key:
                env_values["OPENROUTER_API_KEY"] = api_key
                self.config.openrouter_api_key = api_key
            if model:
                env_values["OPENROUTER_MODEL"] = model
                self.config.openrouter_model = model
            return True

        if choice == "2":
            self.config.llm_provider = "openai"
            api_key = input("OpenAI API key: ").strip()
            model = input("Model (leave empty for default): ").strip()
            if api_key:
                env_values["OPENAI_API_KEY"] = api_key
                self.config.openai_api_key = api_key
            if model:
                env_values["OPENAI_MODEL"] = model
                self.config.openai_model = model
            return True

        if choice == "3":
            self.config.llm_provider = "ollama"
            url = input("Ollama URL (leave empty: http://localhost:11434): ").strip()
            model = input("Ollama model (leave empty: llama3.1): ").strip()
            env_values["LOCAL_LLM_URL"] = url or env_values.get(
                "LOCAL_LLM_URL",
                "http://localhost:11434",
            )
            env_values["LOCAL_LLM_MODEL"] = model or env_values.get(
                "LOCAL_LLM_MODEL",
                "llama3.1",
            )
            self.config.ollama_url = env_values["LOCAL_LLM_URL"]
            self.config.ollama_model = env_values["LOCAL_LLM_MODEL"]
            return True

        return False

    @property
    def llm_client(self) -> Any:
        """Lazy initialization of LLM client."""
        with self._lock:
            if self._llm_client is None:
                try:
                    from llm.openrouter_client import OpenRouterClient

                    self._llm_client = OpenRouterClient()
                except Exception as e:
                    logger.exception("Failed to initialize LLM client: %s", e)
                    self._llm_client = None
            return self._llm_client

    @llm_client.setter
    def llm_client(self, value) -> None:
        """Allow setting LLM client (useful for testing/mocking)."""
        with self._lock:
            self._llm_client = value

    @property
    def language(self) -> str:
        """Get current language setting."""
        with self._lock:
            return self.config.language

    def load_config(self) -> DrakbenConfig:
        """Load configuration from file (thread-safe)."""
        with self._lock:
            if self.config_file.exists():
                try:
                    with open(self.config_file, encoding="utf-8") as f:
                        data = json.load(f)
                        # Flatten nested security section
                        if "security" in data and isinstance(data["security"], dict):
                            security = data.pop("security")
                            data["ssl_verify"] = security.get("ssl_verify", True)
                            data["allow_self_signed_certs"] = security.get(
                                "allow_self_signed_certs", False,
                            )
                        return DrakbenConfig(**data)
                except Exception as e:
                    logger.exception("Config load error: %s", e)

            return DrakbenConfig()

    def save_config(self) -> None:
        """Save configuration to file (thread-safe).

        Raises:
            PermissionError: If file cannot be written due to permissions
            OSError: If file system error occurs

        """
        with self._lock:
            try:
                self.config_file.parent.mkdir(parents=True, exist_ok=True)

                # SENSITIVE DATA PROTECTION
                # Do not write API keys to settings.json (they belong in .env)
                data = asdict(self.config)
                keys_to_remove = [k for k in data if "_api_key" in k]
                for k in keys_to_remove:
                    data.pop(k, None)

                with open(self.config_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except PermissionError as e:
                logger.exception("Config save error (permission denied): %s", e)
                raise  # Re-raise to allow caller to handle
            except OSError as e:
                logger.exception("Config save error (OS error): %s", e)
                raise  # Re-raise to allow caller to handle
            except Exception as e:
                logger.exception("Config save error (unexpected): %s", e)
                raise  # Re-raise to allow caller to handle

    def set_language(self, lang: str) -> None:
        """Set interface language (thread-safe)."""
        with self._lock:
            if lang in ["tr", "en"]:
                self.config.language = lang
                self.save_config()

    def set_target(self, target: str | None) -> None:
        """Set target (thread-safe)."""
        with self._lock:
            self.config.target = target
            self.save_config()

    def get_llm_config(self) -> dict[str, Any]:
        """Get LLM configuration (thread-safe)."""
        with self._lock:
            return {
                "provider": self.config.llm_provider,
                "openrouter_api_key": self.config.openrouter_api_key,
                "openrouter_model": self.config.openrouter_model,
                "ollama_url": self.config.ollama_url,
                "ollama_model": self.config.ollama_model,
                "openai_api_key": self.config.openai_api_key,
                "openai_model": self.config.openai_model,
            }

    def mark_approved(self) -> None:
        """Mark that user has approved once (thread-safe)."""
        with self._lock:
            self.config.approved_once = True
            self.save_config()

    def reset_approval(self) -> None:
        """Reset approval state (thread-safe)."""
        with self._lock:
            self.config.approved_once = False
            self.save_config()


class SessionManager:
    """Manage penetration testing sessions.
    Thread-safe implementation with locking.
    """

    def __init__(self, session_dir: str = "sessions") -> None:
        self._lock = threading.RLock()
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: dict[str, Any] = {
            "target": None,
            "commands": [],
            "findings": [],
            "notes": [],
        }

    def save_session(self, target: str) -> Path | None:
        """Save current session (thread-safe)."""
        with self._lock:
            try:
                import time

                timestamp = int(time.time())
                filename = (
                    f"{target.replace('.', '_').replace(':', '_')}_{timestamp}.json"
                )
                filepath = self.session_dir / filename

                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(self.current_session, f, indent=2, ensure_ascii=False)

                return filepath
            except Exception as e:
                logger.exception("Session save error: %s", e)
                return None

    def load_session(self, filename: str) -> dict | None:
        """Load a session (thread-safe)."""
        with self._lock:
            try:
                filepath = self.session_dir / filename
                if filepath.exists():
                    with open(filepath, encoding="utf-8") as f:
                        return json.load(f)
            except Exception as e:
                logger.exception("Session load error: %s", e)
            return None

    def list_sessions(self) -> list:
        """List all sessions (thread-safe)."""
        with self._lock:
            sessions = []
            for file in self.session_dir.glob("*.json"):
                sessions.append(file.name)
            return sorted(sessions, reverse=True)

    def add_command(self, command: str, output: str) -> None:
        """Add command to session (thread-safe)."""
        with self._lock:
            commands = self.current_session.get("commands")
            if commands is not None:
                commands.append(
                    {"command": command, "output": output[:500]},  # Limit output size
                )

    def add_finding(self, finding: str) -> None:
        """Add finding to session (thread-safe)."""
        with self._lock:
            findings = self.current_session.get("findings")
            if findings is not None:
                findings.append(finding)

    def add_note(self, note: str) -> None:
        """Add note to session (thread-safe)."""
        with self._lock:
            notes = self.current_session.get("notes")
            if notes is not None:
                notes.append(note)
