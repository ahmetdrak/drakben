"""Deep coverage tests for core/config.py.

Covers: TimeoutConfig, C2BeaconConfig, NetworkConfig, DrakbenConfig,
        ConfigManager (load/save/env/language/target), SessionManager.
"""

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from core.config import (
    C2_CONFIG,
    NETWORK_CONFIG,
    TIMEOUTS,
    ConfigManager,
    DrakbenConfig,
    SessionManager,
)


# ===================================================================
# 1. TimeoutConfig
# ===================================================================
class TestTimeoutConfig:
    def test_sqlite_timeout(self):
        assert pytest.approx(10.0) == TIMEOUTS.SQLITE_CONNECT_TIMEOUT
        assert TIMEOUTS.SQLITE_BUSY_TIMEOUT == 10000

    def test_http_timeout(self):
        assert TIMEOUTS.HTTP_REQUEST_TIMEOUT == 30
        assert TIMEOUTS.SOCKET_TIMEOUT == 10

    def test_llm_timeout(self):
        assert TIMEOUTS.LLM_QUERY_TIMEOUT == 30
        assert TIMEOUTS.LLM_STREAMING_TIMEOUT == 60
        assert TIMEOUTS.LLM_MAX_STREAM_TIME == 300

    def test_tool_timeouts(self):
        assert TIMEOUTS.TOOL_DEFAULT_TIMEOUT == 300
        assert TIMEOUTS.TOOL_FAST_TIMEOUT == 60
        assert TIMEOUTS.TOOL_SLOW_TIMEOUT == 600

    def test_thread_timeouts(self):
        assert pytest.approx(5.0) == TIMEOUTS.THREAD_JOIN_TIMEOUT
        assert pytest.approx(5.0) == TIMEOUTS.LOCK_ACQUIRE_TIMEOUT

    def test_process_timeouts(self):
        assert TIMEOUTS.PROCESS_TERMINATE_TIMEOUT == 5
        assert TIMEOUTS.PROCESS_CLEANUP_TIMEOUT == 2

    def test_shell_timeouts(self):
        assert TIMEOUTS.SSH_COMMAND_TIMEOUT == 30
        assert TIMEOUTS.REVERSE_SHELL_TIMEOUT == 60
        assert TIMEOUTS.SHELL_READ_TIMEOUT == 10

    def test_dns_timeout(self):
        assert TIMEOUTS.DNS_RESOLVER_TIMEOUT == 5

    def test_smb_timeout(self):
        assert TIMEOUTS.SMB_TIMEOUT == 2

    def test_subprocess_timeout(self):
        assert TIMEOUTS.SUBPROCESS_TIMEOUT == 120


# ===================================================================
# 2. C2BeaconConfig
# ===================================================================
class TestC2BeaconConfig:
    def test_sleep_intervals(self):
        assert C2_CONFIG.DEFAULT_SLEEP_INTERVAL == 60
        assert C2_CONFIG.MIN_SLEEP_INTERVAL == 10
        assert C2_CONFIG.MAX_SLEEP_INTERVAL == 3600

    def test_jitter(self):
        assert C2_CONFIG.JITTER_MIN == 10
        assert C2_CONFIG.JITTER_MAX == 30

    def test_ports(self):
        assert C2_CONFIG.DEFAULT_PORT_HTTPS == 443
        assert C2_CONFIG.DEFAULT_PORT_HTTP == 80
        assert C2_CONFIG.DEFAULT_PORT_DNS == 53

    def test_retry_settings(self):
        assert C2_CONFIG.MAX_RETRY_ATTEMPTS == 3
        assert C2_CONFIG.RETRY_BACKOFF_MULTIPLIER == 2

    def test_stego_dimensions(self):
        assert C2_CONFIG.STEGO_IMAGE_WIDTH == 800
        assert C2_CONFIG.STEGO_IMAGE_HEIGHT == 600


# ===================================================================
# 3. NetworkConfig
# ===================================================================
class TestNetworkConfig:
    def test_common_ports(self):
        assert 80 in NETWORK_CONFIG.COMMON_PORTS
        assert 443 in NETWORK_CONFIG.COMMON_PORTS
        assert 22 in NETWORK_CONFIG.COMMON_PORTS
        assert 3389 in NETWORK_CONFIG.COMMON_PORTS

    def test_scan_settings(self):
        assert NETWORK_CONFIG.MAX_CONCURRENT_SCANS == 100
        assert pytest.approx(2.0) == NETWORK_CONFIG.PORT_SCAN_TIMEOUT
        assert pytest.approx(1.0) == NETWORK_CONFIG.PING_TIMEOUT

    def test_stealth_delays(self):
        assert pytest.approx(0.5) == NETWORK_CONFIG.STEALTH_DELAY_MIN
        assert pytest.approx(2.0) == NETWORK_CONFIG.STEALTH_DELAY_MAX

    def test_dns_nameservers(self):
        assert "1.1.1.1" in NETWORK_CONFIG.DNS_NAMESERVERS
        assert "8.8.8.8" in NETWORK_CONFIG.DNS_NAMESERVERS
        assert len(NETWORK_CONFIG.DNS_NAMESERVERS) == 4


# ===================================================================
# 4. DrakbenConfig dataclass
# ===================================================================
class TestDrakbenConfig:
    def test_defaults(self):
        cfg = DrakbenConfig()
        assert cfg.llm_provider == "auto"
        assert cfg.language == "en"
        assert cfg.auto_approve is False
        assert cfg.ssl_verify is True
        assert cfg.max_threads == 4
        assert cfg.timeout == 30
        assert cfg.tools_available == {}

    def test_custom_values(self):
        cfg = DrakbenConfig(language="tr", verbose=True, max_threads=8)
        assert cfg.language == "tr"
        assert cfg.verbose is True
        assert cfg.max_threads == 8

    def test_post_init_tools(self):
        cfg = DrakbenConfig(tools_available=None)
        assert cfg.tools_available == {}

    def test_post_init_explicit_tools(self):
        cfg = DrakbenConfig(tools_available={"nmap": True})
        assert cfg.tools_available == {"nmap": True}


# ===================================================================
# 5. ConfigManager — load / save
# ===================================================================
class TestConfigManagerLoadSave:
    def test_load_default_when_no_file(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        assert mgr.config.language == "en"

    def test_load_valid_config(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(json.dumps({"language": "tr", "verbose": True}), encoding="utf-8")
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        assert mgr.config.language == "tr"
        assert mgr.config.verbose is True

    def test_load_invalid_json_returns_default(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text("{{invalid json", encoding="utf-8")
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        assert mgr.config.language == "en"  # Fallback to default

    def test_load_config_with_security_section(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        cfg_file.write_text(
            json.dumps(
                {
                    "language": "en",
                    "security": {
                        "ssl_verify": False,
                        "allow_self_signed_certs": True,
                    },
                }
            ),
            encoding="utf-8",
        )
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        assert mgr.config.ssl_verify is False
        assert mgr.config.allow_self_signed_certs is True

    def test_save_config_creates_file(self, tmp_path):
        cfg_file = tmp_path / "subdir" / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.config.language = "tr"
            mgr.save_config()
        assert cfg_file.exists()
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        assert data["language"] == "tr"

    def test_save_config_strips_api_keys(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.config.openrouter_api_key = "sk-secret"
            mgr.config.openai_api_key = "sk-openai"
            mgr.save_config()
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        assert "openrouter_api_key" not in data
        assert "openai_api_key" not in data


# ===================================================================
# 6. ConfigManager — env loading
# ===================================================================
class TestConfigManagerEnv:
    def test_load_env_with_openrouter_key(self, tmp_path, monkeypatch):
        cfg_file = tmp_path / "settings.json"
        env_file = tmp_path / "api.env"
        env_file.write_text("OPENROUTER_API_KEY=test_key_123\n", encoding="utf-8")

        monkeypatch.setenv("OPENROUTER_API_KEY", "test_key_123")
        with patch("core.config.API_ENV_PATH", str(env_file)):
            mgr = ConfigManager(config_file=str(cfg_file))
        assert mgr.config.openrouter_api_key == "test_key_123"
        assert mgr.config.llm_setup_complete is True

    def test_load_env_with_local_llm(self, tmp_path, monkeypatch):
        cfg_file = tmp_path / "settings.json"
        monkeypatch.setenv("LOCAL_LLM_URL", "http://myserver:11434")
        monkeypatch.setenv("LOCAL_LLM_MODEL", "phi3")
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        assert mgr.config.ollama_url == "http://myserver:11434"
        assert mgr.config.ollama_model == "phi3"

    def test_read_env_file_empty(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        env_file = tmp_path / "api.env"
        env_file.write_text("# Just a comment\n\n", encoding="utf-8")
        with patch("core.config.API_ENV_PATH", str(env_file)):
            mgr = ConfigManager(config_file=str(cfg_file))
            vals = mgr._read_env_file()
        assert vals == {}

    def test_read_env_file_nonexistent(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "nonexistent.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            vals = mgr._read_env_file()
        assert vals == {}

    def test_write_env_file(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        env_path = tmp_path / "config" / "api.env"
        with patch("core.config.API_ENV_PATH", str(env_path)):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr._write_env_file(
                {
                    "OPENROUTER_API_KEY": "test_key",
                    "OPENROUTER_MODEL": "gpt-4",
                }
            )
        assert env_path.exists()
        content = env_path.read_text(encoding="utf-8")
        assert "test_key" in content
        assert "gpt-4" in content


# ===================================================================
# 7. ConfigManager — set/get methods
# ===================================================================
class TestConfigManagerMethods:
    def test_set_language_valid(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.set_language("tr")
        assert mgr.config.language == "tr"

    def test_set_language_invalid_ignored(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.set_language("fr")  # Not supported
        assert mgr.config.language == "en"  # Unchanged

    def test_set_target(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.set_target("10.0.0.1")
        assert mgr.config.target == "10.0.0.1"

    def test_set_target_none(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.set_target(None)
        assert mgr.config.target is None

    def test_get_llm_config(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            llm_cfg = mgr.get_llm_config()
        assert "provider" in llm_cfg
        assert "openrouter_model" in llm_cfg
        assert "ollama_url" in llm_cfg

    def test_mark_approved(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.mark_approved()
        assert mgr.config.approved_once is True

    def test_reset_approval(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mgr.mark_approved()
            mgr.reset_approval()
        assert mgr.config.approved_once is False

    def test_language_property(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        assert mgr.language == "en"


# ===================================================================
# 8. ConfigManager — LLM client lazy init
# ===================================================================
class TestConfigManagerLLMClient:
    def test_llm_client_setter(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
            mock_client = MagicMock()
            mgr.llm_client = mock_client
        assert mgr.llm_client is mock_client

    def test_llm_client_lazy_init_failure(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        with patch(
            "llm.openrouter_client.OpenRouterClient",
            side_effect=OSError("no key"),
        ):
            # Force fresh init by resetting cached client
            mgr._llm_client = None
            # Should handle gracefully — OSError is caught by the property
            client = mgr.llm_client
            assert client is None  # OSError → returns None


# ===================================================================
# 9. SessionManager
# ===================================================================
class TestSessionManager:
    def test_init_creates_dir(self, tmp_path):
        session_dir = tmp_path / "sessions"
        SessionManager(session_dir=str(session_dir))
        assert session_dir.exists()

    def test_save_session(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        sm.current_session["target"] = "10.0.0.1"
        filepath = sm.save_session("10.0.0.1")
        assert filepath is not None
        assert filepath.exists()
        data = json.loads(filepath.read_text(encoding="utf-8"))
        assert data["target"] == "10.0.0.1"

    def test_save_session_sanitizes_filename(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        filepath = sm.save_session("10.0.0.1:8080")
        assert filepath is not None
        assert ":" not in filepath.name

    def test_load_session(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        # Create a session file
        data = {"target": "test", "commands": [], "findings": [], "notes": []}
        (tmp_path / "test_session.json").write_text(json.dumps(data), encoding="utf-8")
        loaded = sm.load_session("test_session.json")
        assert loaded is not None
        assert loaded["target"] == "test"

    def test_load_session_nonexistent(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        loaded = sm.load_session("ghost.json")
        assert loaded is None

    def test_list_sessions(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        (tmp_path / "s1.json").write_text("{}", encoding="utf-8")
        (tmp_path / "s2.json").write_text("{}", encoding="utf-8")
        sessions = sm.list_sessions()
        assert len(sessions) == 2

    def test_list_sessions_empty(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        sessions = sm.list_sessions()
        assert sessions == []

    def test_add_command(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        sm.add_command("nmap 10.0.0.1", "22/tcp open ssh")
        assert len(sm.current_session["commands"]) == 1
        assert sm.current_session["commands"][0]["command"] == "nmap 10.0.0.1"

    def test_add_command_truncates_output(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        long_output = "x" * 1000
        sm.add_command("cmd", long_output)
        assert len(sm.current_session["commands"][0]["output"]) <= 500

    def test_add_finding(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        sm.add_finding("SQL injection on /login")
        assert "SQL injection on /login" in sm.current_session["findings"]

    def test_add_note(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        sm.add_note("Check port 8080 later")
        assert "Check port 8080 later" in sm.current_session["notes"]

    def test_multiple_commands(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        sm.add_command("cmd1", "out1")
        sm.add_command("cmd2", "out2")
        sm.add_command("cmd3", "out3")
        assert len(sm.current_session["commands"]) == 3

    def test_save_and_reload(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        sm.add_command("nmap scan", "port 22 open")
        sm.add_finding("SSH found")
        sm.add_note("interesting")
        filepath = sm.save_session("target")
        assert filepath is not None

        sm2 = SessionManager(session_dir=str(tmp_path))
        data = sm2.load_session(filepath.name)
        assert data is not None
        assert len(data["commands"]) == 1
        assert "SSH found" in data["findings"]
        assert "interesting" in data["notes"]

    def test_thread_safety(self, tmp_path):
        sm = SessionManager(session_dir=str(tmp_path))
        errors = []

        def add_commands(start):
            try:
                for i in range(20):
                    sm.add_command(f"cmd_{start}_{i}", f"out_{start}_{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_commands, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(sm.current_session["commands"]) == 100


# ===================================================================
# 10. ConfigManager — configure_provider
# ===================================================================
class TestConfigureProvider:
    def test_configure_skip(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        result = mgr._configure_provider("4", {})  # Skip
        assert result is False

    def test_configure_invalid_choice(self, tmp_path):
        cfg_file = tmp_path / "settings.json"
        with patch("core.config.API_ENV_PATH", str(tmp_path / "api.env")):
            mgr = ConfigManager(config_file=str(cfg_file))
        result = mgr._configure_provider("99", {})
        assert result is False
