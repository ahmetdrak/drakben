"""Menu Config Mixin — LLM setup wizard & configuration commands.

Extracted from menu.py to reduce God object size.
Contains: /llm setup wizard, /config menu, provider/model selection,
          config presets (defaults, shadow mode, manual).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.ui._menu_protocol import MenuProtocol

    _MixinBase = MenuProtocol
else:
    _MixinBase = object


class MenuConfigMixin(_MixinBase):
    """LLM setup and configuration methods for DrakbenMenu."""

    # ── LLM Setup Wizard ────────────────────────────────────────────

    def _cmd_llm_setup(self, _args: str = "") -> None:
        """Interactive LLM/API setup wizard."""
        lang: str = self.config.language

        providers: dict[str, tuple[str, str]] = {
            "1": (
                "openrouter",
                "OpenRouter (Ücretsiz modeller var)" if lang == "tr" else "OpenRouter (Free models available)",
            ),
            "2": ("openai", "OpenAI (GPT-4, GPT-4o)"),
            "3": (
                "ollama",
                "Ollama (Yerel, Ücretsiz)" if lang == "tr" else "Ollama (Local, Free)",
            ),
        }

        self._display_llm_setup_status(lang)

        provider_key = self._select_provider_for_setup(lang, providers)
        if not provider_key:
            return

        selected_model, api_key = self._select_model_and_key(lang, provider_key)
        if not selected_model:
            return

        self._save_llm_config(provider_key, selected_model, api_key)  # type: ignore[arg-type]

    def _display_llm_setup_status(self, lang: str) -> None:
        """Show current LLM configuration status."""
        title: str = "LLM Kurulumu" if lang == "tr" else "LLM Setup"
        self.console.print()
        self.console.print(f"[bold {self.COLORS['cyan']}]{title}[/]")
        self.console.print("─" * 30)

        current_info: str = "[dim]Ayar yok[/]" if lang == "tr" else "[dim]No config[/]"
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            current_info = f"[green]●[/] {info.get('provider', 'N/A')} / {info.get('model', 'N/A')}"

        lbl = "Mevcut" if lang == "tr" else "Current"
        self.console.print(f"{lbl}: {current_info}")
        self.console.print("─" * 30)

    def _select_provider_for_setup(self, lang: str, providers: dict[str, Any]) -> Any:
        """Show provider selection menu and return selected provider key."""
        from rich.table import Table

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("No", style=f"bold {self.COLORS['yellow']}")
        table.add_column("Provider", style=self.COLORS["fg"])

        for key, (_, desc) in providers.items():
            table.add_row(f"[{key}]", desc)

        q_label = "Geri Dön / İptal" if lang == "tr" else "Go Back / Cancel"
        table.add_row("[0]", q_label)

        self.console.print()
        self.console.print(table)

        prompt_text: str = "Seçiminiz (1-3 veya 0)" if lang == "tr" else "Choice (1-3 or 0)"
        self.console.print(f"   {prompt_text}: ", end="")
        choice: str = input().strip().lower()

        if choice == "0" or choice not in providers:
            return None

        return providers[choice][0]

    def _get_models_dict(self, lang: str) -> dict[str, list[tuple[str, str]]]:
        """Get available models for each provider."""
        return {
            "openrouter": [
                (
                    "deepseek/deepseek-chat",
                    "DeepSeek Chat (Ücretsiz)" if lang == "tr" else "DeepSeek Chat (Free)",
                ),
                (
                    "meta-llama/llama-3.1-8b-instruct:free",
                    "Llama 3.1 8B (Ücretsiz)" if lang == "tr" else "Llama 3.1 8B (Free)",
                ),
                (
                    "google/gemma-2-9b-it:free",
                    "Gemma 2 9B (Ücretsiz)" if lang == "tr" else "Gemma 2 9B (Free)",
                ),
                ("anthropic/claude-3.5-sonnet", "Claude 3.5 Sonnet"),
                ("openai/gpt-4o", "GPT-4o"),
            ],
            "openai": [
                (
                    "gpt-4o-mini",
                    "GPT-4o Mini (Ucuz)" if lang == "tr" else "GPT-4o Mini (Cheap)",
                ),
                ("gpt-4o", "GPT-4o"),
                ("gpt-4-turbo", "GPT-4 Turbo"),
            ],
            "ollama": [
                ("llama3.2", "Llama 3.2"),
                ("llama3.1", "Llama 3.1"),
                ("mistral", "Mistral"),
                ("codellama", "Code Llama"),
            ],
        }

    def _select_model_and_key(
        self,
        lang: str,
        provider_key: str,
    ) -> tuple[None, None] | tuple[str, str]:
        """Show model selection and get API key."""
        from rich.table import Table

        models: dict[str, list[tuple[str, str]]] = self._get_models_dict(lang)

        self.console.print()
        model_table = Table(show_header=False, box=None, padding=(0, 2))
        model_table.add_column("No", style=f"bold {self.COLORS['yellow']}")
        model_table.add_column("Model", style=self.COLORS["fg"])

        provider_models: list[tuple[str, str]] = models[provider_key]
        for i, (_, desc) in enumerate(provider_models, 1):
            model_table.add_row(f"[{i}]", desc)

        q_label = "Geri Dön" if lang == "tr" else "Go Back"
        model_table.add_row("[0]", q_label)

        self.console.print(model_table)

        prompt_text: str = (
            f"Seçiminiz (1-{len(provider_models)} veya 0)"
            if lang == "tr"
            else f"Choice (1-{len(provider_models)} or 0)"
        )
        self.console.print(f"   {prompt_text}: ", end="")
        model_choice: str = input().strip().lower()

        if model_choice == "0":
            return None, None

        selected_model = None
        try:
            model_idx: int = int(model_choice) - 1
            if 0 <= model_idx < len(provider_models):
                selected_model, _ = provider_models[model_idx]
            else:
                return None, None
        except ValueError:
            return None, None

        api_key: str = ""
        if provider_key != "ollama":
            prompt_text = "API Key gir" if lang == "tr" else "Enter API Key"
            self.console.print(f"\n{prompt_text}: ", end="")
            api_key = input().strip()

            if not api_key:
                msg: str = "API key gerekli!" if lang == "tr" else "API key required!"
                self.console.print(f"[red]{msg}[/]")
                return None, None

        return selected_model, api_key

    def _save_llm_config(self, provider_key: str, selected_model: str, api_key: str) -> None:
        """Save LLM configuration to api.env and reload."""
        from pathlib import Path

        project_root = Path(__file__).resolve().parent.parent.parent
        env_file = project_root / "config" / "api.env"

        templates: dict[str, str] = {
            "openrouter": f"OPENROUTER_API_KEY={api_key}\nOPENROUTER_MODEL={selected_model}",
            "openai": f"OPENAI_API_KEY={api_key}\nOPENAI_MODEL={selected_model}",
            "ollama": f"LOCAL_LLM_URL=http://localhost:11434\nLOCAL_LLM_MODEL={selected_model}",
        }

        config_body: str | None = templates.get(provider_key)
        if not config_body:
            self.console.print(f"[red]Unknown provider: {provider_key}[/]")
            return

        env_content: str = f"# DRAKBEN LLM Configuration\n# Auto-generated by /llm command\n\n{config_body}\n"

        try:
            env_file.parent.mkdir(parents=True, exist_ok=True)
            with open(env_file, "w") as f:
                f.write(env_content)

            from dotenv import load_dotenv

            load_dotenv(env_file, override=True)

            self.config_manager.config = self.config_manager.load_config()
            self.config_manager._load_env()
            self.config = self.config_manager.config

            self.brain = None
            self.config_manager.llm_client = None

            lang: str = self.config.language
            msg: str = (
                f"LLM ayarlandı: {provider_key} / {selected_model}"
                if lang == "tr"
                else f"LLM configured: {provider_key} / {selected_model}"
            )
            self.console.print(f"\n[green]{msg}[/]")

            test_msg: str = "Bağlantı test ediliyor..." if lang == "tr" else "Testing connection..."
            self.console.print(f"\n[dim]{test_msg}[/dim]")

            from core.agent.brain import DrakbenBrain

            self.brain = DrakbenBrain()

            if self.brain.llm_client:
                test_result = self.brain.test_llm()
                if test_result.get("connected"):
                    ok_msg: str = "Bağlantı başarılı." if lang == "tr" else "Connection OK."
                    self.console.print(f"[green]{ok_msg}[/]\n")
                else:
                    err_msg: str = "Bağlantı hatası:" if lang == "tr" else "Connection error:"
                    self.console.print(
                        f"[red]{err_msg} {test_result.get('error', 'Unknown')}[/]\n",
                    )

        except Exception as e:
            self.console.print(f"\n[red]Save error: {e}[/]")

    # ── Config Command ──────────────────────────────────────────────

    def _config_apply_defaults(self, lang: str) -> None:
        """Apply automatic default configuration."""
        self.config.stealth_mode = False
        self.config.max_threads = 4
        self.config.timeout = 30
        self.config.verbose = False
        self.config_manager.save_config()
        if lang == "tr":
            msg = "Standart ayarlar uygulandı (4 Thread, 30s)."
        else:
            msg = "Standard defaults applied (4 Threads, 30s)."
        self.console.print(f"\n[green]{msg}[/]\n")

    def _config_apply_shadow_mode(self, lang: str) -> None:
        """Apply shadow mode (hacker preset) configuration."""
        self.config.stealth_mode = True
        self.config.max_threads = 1
        self.config.timeout = 300
        self.config.verbose = True
        self.config_manager.save_config()
        if lang == "tr":
            msg = "Shadow Mode Aktif: Ghost Protocol ON, 1 Thread, 300s Timeout."
        else:
            msg = "Shadow Mode Active: Ghost Protocol ON, 1 Thread, 300s Timeout."
        self.console.print(f"\n[bold cyan]{msg}[/]\n")

    def _config_prompt_bool(self, prompt: str, current: bool, y_label: str, n_label: str) -> bool | None:
        """Prompt for boolean config value. Returns None if cancelled."""
        self.console.print(f"   > {prompt} [{y_label}/{n_label}] ({y_label if current else n_label}): ", end="")
        val = input().strip().lower()
        if val == "0":
            return None
        return val in ["e", "y", "yes", "evet"] if val else current

    def _config_prompt_int(self, prompt: str, current: int) -> int | None:
        """Prompt for integer config value. Returns None if cancelled."""
        self.console.print(f"   > {prompt} ({current}): ", end="")
        val = input().strip()
        if val == "0":
            return None
        return int(val) if val.isdigit() else current

    def _config_manual(self, lang: str) -> None:
        """Handle manual configuration."""
        y_label = "e" if lang == "tr" else "y"
        n_label = "h" if lang == "tr" else "n"
        header = "--- MANUEL AYARLAR ---" if lang == "tr" else "--- MANUAL SETTINGS ---"
        self.console.print(f"\n   [{self.STYLE_BOLD_CYAN}]{header}[/]")

        p_s = "Ghost Protocol (Gizli Mod)" if lang == "tr" else "Ghost Protocol (Stealth)"
        new_s = self._config_prompt_bool(p_s, getattr(self.config, "stealth_mode", False), y_label, n_label)
        if new_s is None:
            return

        p_t = "Eşzamanlılık (Threads)" if lang == "tr" else "Concurrency (Threads)"
        new_t = self._config_prompt_int(p_t, getattr(self.config, "max_threads", 4))
        if new_t is None:
            return

        p_to = "Operasyon Zaman Aşımı (sn)" if lang == "tr" else "Operation Timeout (sec)"
        new_to = self._config_prompt_int(p_to, getattr(self.config, "timeout", 30))
        if new_to is None:
            return

        p_v = "Detaylı Çıktı (Verbose)" if lang == "tr" else "Neural Verbosity (Verbose)"
        new_v = self._config_prompt_bool(p_v, getattr(self.config, "verbose", False), y_label, n_label)
        if new_v is None:
            return

        p_a = "Otonom Onay (Auto-Approve)" if lang == "tr" else "Autonomous Approval (Auto)"
        new_a = self._config_prompt_bool(p_a, getattr(self.config, "auto_approve", False), y_label, n_label)
        if new_a is None:
            return

        self.config.stealth_mode = new_s
        self.config.max_threads = new_t
        self.config.timeout = new_to
        self.config.verbose = new_v
        self.config.auto_approve = new_a
        self.config_manager.save_config()

        done_msg = "Sistem parametreleri güncellendi." if lang == "tr" else "System parameters optimized."
        self.console.print(f"\n   [bold green]✅ {done_msg}[/]\n")

    def _cmd_config(self, _args: str) -> None:
        """System Configuration Menu."""
        from rich.table import Table

        lang = self.config.language
        title = "CONFIGURATION" if lang != "tr" else "YAPILANDIRMA"

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style=self.STYLE_BOLD_CYAN, width=6)
        table.add_column("Desc", style="white")

        if lang == "tr":
            table.add_row("[1]", "Otomatik - Standart ayarlar")
            table.add_row("[2]", "Manuel - Ozel yapilandirma")
            table.add_row("[3]", "Stealth - Sessiz mod")
            table.add_row("[0]", "Geri")
            prompt = "Secim"
        else:
            table.add_row("[1]", "Auto - Standard defaults")
            table.add_row("[2]", "Manual - Custom settings")
            table.add_row("[3]", "Stealth - Silent mode")
            table.add_row("[0]", "Back")
            prompt = "Choice"

        self.console.print()
        self.console.print(f"[bold cyan]{title}[/]")
        self.console.print("─" * 30)
        self.console.print(table)
        self.console.print("─" * 30)
        self.console.print(f"{prompt} [0-3]: ", end="")
        choice = input().strip()

        if choice == "1":
            self._config_apply_defaults(lang)
        elif choice == "2":
            try:
                self._config_manual(lang)
            except Exception as e:
                self.console.print(f"   [red]❌ Hata: {e}[/red]")
        elif choice == "3":
            self._config_apply_shadow_mode(lang)
        elif choice == "0":
            self.console.print()
            return
        else:
            invalid_msg = "Geçersiz seçim." if lang == "tr" else "Invalid selection."
            self.console.print(f"   [red]❌ {invalid_msg}[/]")

        self.console.print()
        self.show_status_line()

    # ── Exit & screen ───────────────────────────────────────────────

    def _cmd_exit(self, _args: str = "") -> None:
        """Çıkış."""
        self.running = False

    def _clear_screen(self) -> None:
        """Ekranı temizle."""
        import subprocess

        cmd = "cls" if os.name == "nt" else "clear"
        subprocess.call(cmd, shell=True)  # noqa: S602  # safe: hardcoded command
