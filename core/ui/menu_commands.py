"""Menu Commands Mixin — CLI command handlers.

Extracted from menu.py to reduce God object size.
Contains: /research, /help, /target, /untarget, /tools, /scan, /shell,
          /status, /memory, /report and supporting helpers.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rich.table import Table

    from core.ui._menu_protocol import MenuProtocol

    _MixinBase = MenuProtocol
else:
    _MixinBase = object

logger = logging.getLogger(__name__)


class MenuCommandsMixin(_MixinBase):
    """CLI command handlers for DrakbenMenu."""

    # ── Research ────────────────────────────────────────────────────

    def _cmd_research(self, args: str) -> None:
        """Web research command."""
        if not args:
            self.console.print("[dim]Usage: /research <query>[/]")
            return

        if isinstance(args, list):
            query: str = " ".join(args)
        else:
            query = str(args)
        self.console.print(f"[cyan]Searching: {query}[/]")

        try:
            from core.network.web_researcher import WebResearcher

            researcher = WebResearcher()
            results = researcher.search_tool(query)

            if not results:
                self.console.print("[red]No results found.[/]")
                return

            self.console.print(f"\n[green]Found {len(results)} results:[/]\n")
            for i, r in enumerate(results, 1):
                self.console.print(f"{i}. [bold]{r['title']}[/]")
                self.console.print(f"   [cyan underline]{r['href']}[/]")
                body: Any | str = r.get("body", "")[:200] + "..." if r.get("body") else "No description."
                self.console.print(f"   [dim]{body}[/]\n")

        except (OSError, ValueError, RuntimeError) as e:
            self.console.print(f"[red]Error: {e}[/]")

    # ── Help ────────────────────────────────────────────────────────

    def _cmd_help(self, _args: str = "") -> None:
        """Help command - Clean minimal style."""
        from rich.table import Table

        lang: str = self.config.language
        is_tr = lang == "tr"

        table = Table(show_header=True, box=None, padding=(0, 3))
        table.add_column("Command" if not is_tr else "Komut", style="cyan", width=18)
        table.add_column("Description" if not is_tr else "Açıklama", style="dim")

        if is_tr:
            commands: list[tuple[str, str]] = [
                ("/target <IP>", "Hedef belirle"),
                (self.CMD_UNTARGET, "Hedefi temizle"),
                (self.CMD_SCAN, "Tarama başlat"),
                (self.CMD_STATUS, "Durum göster"),
                (self.CMD_TOOLS, "Araçları listele"),
                (self.CMD_REPORT, "Rapor oluştur"),
                (self.CMD_SHELL, "Terminal erişimi"),
                (self.CMD_CONFIG, "Ayarlar"),
                (self.CMD_MEMORY, "Hafıza durumu"),
                ("/llm", "LLM ayarları"),
                ("/tr /en", "Dil değiştir"),
                (self.CMD_CLEAR, "Ekranı temizle"),
                (self.CMD_EXIT, "Çıkış"),
            ]
        else:
            commands = [
                ("/target <IP>", "Set target"),
                (self.CMD_UNTARGET, "Clear target"),
                (self.CMD_SCAN, "Start scan"),
                (self.CMD_STATUS, "Show status"),
                (self.CMD_TOOLS, "List tools"),
                (self.CMD_REPORT, "Generate report"),
                (self.CMD_SHELL, "Terminal access"),
                (self.CMD_CONFIG, "Settings"),
                (self.CMD_MEMORY, "Memory status"),
                ("/llm", "LLM settings"),
                ("/tr /en", "Change language"),
                (self.CMD_CLEAR, "Clear screen"),
                (self.CMD_EXIT, "Exit"),
            ]

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        self.console.print()
        self.console.print(table)
        self.console.print()

        if is_tr:
            self.console.print('[dim]Doğal dilde de yazabilirsiniz: "10.0.0.1 tara"[/]')
        else:
            self.console.print('[dim]Or type naturally: "scan 10.0.0.1"[/]')
        self.console.print()

    # ── Target management ───────────────────────────────────────────

    def _validate_target(self, target: str) -> bool:
        """Validate if the target is a valid IP or Domain."""
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$"

        return bool(
            re.match(ip_pattern, target) or re.match(domain_pattern, target, re.IGNORECASE),
        )

    def _show_current_target_info(self, lang: str) -> None:
        """Display current target information."""
        current_target = self.config.target
        if current_target:
            if lang == "tr":
                self.console.print(f"Mevcut hedef: [bold]{current_target}[/]")
            else:
                self.console.print(f"Current target: [bold]{current_target}[/]")
        else:
            if lang == "tr":
                self.console.print("[dim]Hedef yok. Kullanım:[/] [green]/target <IP>[/]")
            else:
                self.console.print("[dim]No target set. Usage:[/] [green]/target <IP>[/]")

    def _cmd_target(self, args: str = "") -> None:
        """Set target."""
        lang: str = self.config.language
        args = args.strip()

        if not args:
            self._show_current_target_info(lang)
            return

        clear_keywords = {"clear", "off", "none", "delete", "sil", "iptal", "remove"}
        if args.lower() in clear_keywords:
            self._cmd_untarget("")
            return

        if not self._validate_target(args):
            err_msg = (
                "Geçersiz hedef formatı (IP veya Domain girilmeli)."
                if lang == "tr"
                else "Invalid target format (Must be IP or Domain)."
            )
            self.console.print(f"   [red]❌ {err_msg}[/]")
            return

        self.config_manager.set_target(args)
        self.config = self.config_manager.config

        if self.orchestrator:
            self.orchestrator.set_target(args)

        if lang == "tr":
            self.console.print(f"[green]Hedef ayarlandı:[/] [bold]{args}[/]")
        else:
            self.console.print(f"[green]Target set:[/] [bold]{args}[/]")

    def _cmd_untarget(self, _args: str = "") -> None:
        """Clear target command."""
        lang: str = self.config.language

        if not self.config.target:
            msg = "Zaten hedef belirlenmemiş." if lang == "tr" else "No target is set."
            self.console.print(f"[yellow]{msg}[/]")
            return

        self.config_manager.set_target(None)
        self.config = self.config_manager.config

        if self.orchestrator:
            self.orchestrator.clear_target()

        msg = "Hedef temizlendi." if lang == "tr" else "Target cleared."
        self.console.print(f"[green]{msg}[/]")

    # ── Tools ───────────────────────────────────────────────────────

    def _cmd_tools(self, args: str = "") -> None:
        """List all available tools from the registry."""
        from rich.table import Table

        from core.tools.tool_registry import PentestPhase, get_registry

        lang = self.config.language
        registry = get_registry()

        phase_filter = None
        if args:
            phase_map = {
                "recon": PentestPhase.RECON,
                "vuln": PentestPhase.VULN_SCAN,
                "exploit": PentestPhase.EXPLOIT,
                "post": PentestPhase.POST_EXPLOIT,
                "lateral": PentestPhase.LATERAL,
            }
            phase_filter = phase_map.get(args.lower())

        tools = registry.list_tools(phase=phase_filter)

        title = "Mevcut Araçlar" if lang == "tr" else "Available Tools"
        table = Table(title=title, border_style=self.STYLE_DIM_CYAN)
        table.add_column("Tool", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Phase", style="yellow")
        table.add_column("Description", style="white")

        for tool in tools:
            table.add_row(
                tool.name,
                tool.type.value,
                tool.phase.value,
                tool.description[:50] + "..." if len(tool.description) > 50 else tool.description,
            )

        self.console.print(table)

        if lang == "tr":
            self.console.print("\n[dim]Kullanım:[/] [green]/tools[/] [dim][recon|vuln|exploit|post|lateral][/]")
        else:
            self.console.print("\n[dim]Usage:[/] [green]/tools[/] [dim][recon|vuln|exploit|post|lateral][/]")

    # ── Scan ────────────────────────────────────────────────────────

    def _cmd_scan(self, args: str = "") -> None:
        """Scan target - with visual feedback."""
        scan_mode: str = self._parse_scan_mode(args)

        if not self._check_target_set():
            return

        from core.ui.unified_display import ScanDisplay

        lang: str = self.config.language
        scan_display = ScanDisplay(console=self.console, language=lang)

        try:
            scan_display.start_scan(
                target=self.config.target or "",
                mode=scan_mode,
                phase="RECON",
            )

            self._ensure_agent_initialized()
            self._initialize_agent_with_retry(scan_mode, lang)

            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)

            self._show_scan_plan_and_confirm(lang)

            scan_display.update_progress(tool="nmap", current_action="Port scanning...")
            scan_display.stop(final_message="Starting autonomous scan...", success=True)
            self.agent.run_autonomous_loop()

        except KeyboardInterrupt:
            scan_display.finish_scan(success=False)
            self._handle_scan_interrupt(lang)
        except Exception as e:
            scan_display.finish_scan(success=False)
            self._handle_scan_error(e, lang)

    def _parse_scan_mode(self, args: str) -> str:
        """Parse scan mode from arguments."""
        args_lower: str = args.strip().lower()
        if args_lower in ["stealth", "sessiz", "silent", "quiet", "gizli"]:
            return "stealth"
        if args_lower in ["aggressive", "hizli", "fast", "agresif", "quick"]:
            return "aggressive"
        return "auto"

    def _check_target_set(self) -> bool:
        """Check if target is set, show error if not."""
        if self.config.target:
            return True

        lang: str = self.config.language
        if lang == "tr":
            self.console.print("[red]Hedef yok.[/] [dim]Kullanım:[/] [green]/target <IP>[/]")
        else:
            self.console.print("[red]No target.[/] [dim]Usage:[/] [green]/target <IP>[/]")

        return False

    def _handle_scan_interrupt(self, lang: str) -> None:
        """Handle scan interruption (Ctrl+C)."""
        try:
            from core.stop_controller import stop_controller

            stop_controller.stop()
        except ImportError:
            pass
        interrupt_msg: str = "\nTarama durduruldu." if lang == "tr" else "\nScan stopped."
        self.console.print(f"[yellow]{interrupt_msg}[/]")
        try:
            from core.stop_controller import stop_controller

            stop_controller.reset()
        except ImportError:
            pass

    def _handle_scan_error(self, error: Exception, lang: str) -> None:
        """Handle scan error."""
        logger.exception("Scan error: %s", error)
        error_msg: str = f"Tarama hatası: {error}" if lang == "tr" else f"Scan error: {error}"
        self.console.print(f"[red]{error_msg}[/]")

    def _show_scan_plan_and_confirm(self, lang: str) -> None:
        """Display the scan plan and ask user for confirmation."""
        is_tr = lang == "tr"

        if self.agent is None:
            return

        self._display_plan_table(is_tr)

        prompt_text = (
            "[bold yellow]Taramayı başlatmak istiyor musunuz? (E/h):[/] "
            if is_tr
            else "[bold yellow]Start scan? (Y/n):[/] "
        )
        try:
            answer = self.console.input(prompt_text).strip().lower()
            if answer in ("h", "n", "hayır", "no"):
                cancel_msg = "Tarama iptal edildi." if is_tr else "Scan cancelled."
                self.console.print(f"[yellow]{cancel_msg}[/]")
                msg = "User cancelled scan"
                raise KeyboardInterrupt(msg)
        except EOFError:
            pass

    def _display_plan_table(self, is_tr: bool) -> None:
        """Build and display the scan plan table."""
        from rich.table import Table

        steps = getattr(self.agent, "planner", None)
        if not (steps and hasattr(steps, "steps") and steps.steps):
            return

        table = Table(
            title="📋 Tarama Planı" if is_tr else "📋 Scan Plan",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Adım" if is_tr else "Action", style="cyan")
        table.add_column("Araç" if is_tr else "Tool", style="green")
        table.add_column("Açıklama" if is_tr else "Description", style="dim")

        for i, step in enumerate(steps.steps, 1):
            action = getattr(step, "action", "?")
            tool = getattr(step, "tool", "?")
            expected = getattr(step, "expected_outcome", "")
            table.add_row(str(i), action, tool, expected[:60])

        self.console.print()
        self.console.print(table)
        self.console.print()

    def _ensure_agent_initialized(self) -> None:
        """Ensure agent is initialized."""
        if not self.agent:
            from core.agent.refactored_agent import RefactoredDrakbenAgent

            self.agent = RefactoredDrakbenAgent(self.config_manager)

    def _initialize_agent_with_retry(self, scan_mode: str, lang: str) -> None:
        """Initialize agent with retry on failure."""
        try:
            if self.agent is None:
                raise AssertionError(self.MSG_AGENT_NOT_NONE)
            target: str = self.config.target or "localhost"
            self.agent.initialize(target=target, mode=scan_mode)
        except Exception as init_error:
            error_msg: str = f"Agent hatası: {init_error}" if lang == "tr" else f"Agent error: {init_error}"
            retry_msg = "Yeniden deneniyor..." if lang == "tr" else "Retrying..."
            self.console.print(f"[yellow]{error_msg}[/]")
            self.console.print(f"[dim]{retry_msg}[/]")

            from core.agent.refactored_agent import RefactoredDrakbenAgent

            target = self.config.target or "localhost"
            self.agent = RefactoredDrakbenAgent(self.config_manager)
            self.agent.initialize(target=target, mode=scan_mode)

    # ── Shell ───────────────────────────────────────────────────────

    def _cmd_shell(self, _args: str = "") -> None:
        """Launch interactive shell."""
        lang: str = self.config.language

        if lang == "tr":
            self.console.print("[İnteraktif kabuk başlatılıyor... Çıkmak için 'exit' yazın]")
        else:
            self.console.print("[Starting interactive shell... Type 'exit' to quit]")

        from core.ui.interactive_shell import InteractiveShell

        shell = InteractiveShell(config_manager=self.config_manager, agent=self.agent)
        shell.current_target = self.config.target
        shell.start()

        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    # ── Status ──────────────────────────────────────────────────────

    def _cmd_status(self, _args: str = "") -> None:
        """Show current status - Clean, professional dashboard."""
        from rich.panel import Panel
        from rich.table import Table

        lang: str = self.config.language
        is_tr = lang == "tr"
        self.console.print()

        status_table = Table(box=None, padding=(0, 2), expand=True, show_header=False)
        status_table.add_column("Key", style="dim", width=15)
        status_table.add_column("Value", style="white")

        self._populate_status_rows(status_table, is_tr)
        self._add_llm_status_row(status_table, is_tr)

        title = "DRAKBEN Durumu" if is_tr else "DRAKBEN Status"
        self.console.print(
            Panel(
                status_table,
                title=f"[bold cyan]{title}[/]",
                border_style="cyan",
                padding=(0, 1),
            )
        )

        if self.agent and self.agent.state:
            self._show_agent_status_compact(is_tr)

        self.console.print()

    def _populate_status_rows(self, status_table: Table, is_tr: bool) -> None:
        """Populate basic status table rows."""
        target = self.config.target or ("Belirlenmedi" if is_tr else "Not set")
        target_style = self.STYLE_BOLD_GREEN if self.config.target else self.STYLE_DIM_RED
        status_table.add_row("Hedef" if is_tr else "Target", f"[{target_style}]{target}[/]")

        mode = "Stealth" if self.config.stealth_mode else "Normal"
        mode_style = "green" if self.config.stealth_mode else "dim"
        status_table.add_row("Mod" if is_tr else "Mode", f"[{mode_style}]{mode}[/]")

        status_table.add_row("Threads", f"{self.config.max_threads}")

        tools = self.system_info.get("available_tools", {})
        status_table.add_row("Araçlar" if is_tr else "Tools", f"{len(tools)}")

    def _add_llm_status_row(self, status_table: Table, is_tr: bool) -> None:
        """Add LLM status row to the status table."""
        if self.brain and self.brain.llm_client:
            info = self.brain.llm_client.get_provider_info()
            model = info.get("model", "N/A")
            short_model = model.split("/")[-1][:25] if "/" in model else model[:25]
            status_table.add_row("LLM", f"[green]{short_model}[/]")
        else:
            off_text = "Kapalı" if is_tr else "Off"
            status_table.add_row("LLM", f"[dim]{off_text}[/]")

    def _show_agent_status_compact(self, is_tr: bool) -> None:
        """Show compact agent status."""
        from rich.panel import Panel
        from rich.table import Table

        state = self.agent.state
        phase_colors = {
            "init": "dim",
            "recon": "yellow",
            "vulnerability_scan": "cyan",
            "exploit": "red",
            "foothold": "green",
            "post_exploit": "magenta",
            "complete": self.STYLE_BOLD_GREEN,
            "failed": self.STYLE_BOLD_RED,
        }
        phase_color = phase_colors.get(state.phase.value, "white")
        phase_name = self._get_phase_display_name(state.phase.value, is_tr)

        agent_table = Table(box=None, padding=(0, 2), show_header=False, expand=True)
        agent_table.add_column("Key", style="dim", width=15)
        agent_table.add_column("Value", style="white")

        agent_table.add_row("Phase" if not is_tr else "Aşama", f"[{phase_color}]{phase_name}[/]")
        agent_table.add_row("Services" if not is_tr else "Servisler", f"{len(state.open_services)}")

        vuln_count = len(state.vulnerabilities)
        vuln_style = self.STYLE_BOLD_RED if vuln_count > 0 else "dim"
        agent_table.add_row("Vulns" if not is_tr else "Zafiyetler", f"[{vuln_style}]{vuln_count}[/]")

        foothold_text = "Yes" if state.has_foothold else "No"
        if is_tr:
            foothold_text = "Evet" if state.has_foothold else "Hayır"
        foothold_style = "green" if state.has_foothold else "dim"
        agent_table.add_row("Foothold" if not is_tr else "Erişim", f"[{foothold_style}]{foothold_text}[/]")

        title = "Agent Status" if not is_tr else "Ajan Durumu"
        self.console.print(
            Panel(
                agent_table,
                title=f"[bold yellow]{title}[/]",
                border_style="yellow",
                padding=(0, 1),
            )
        )

    # ── Memory ──────────────────────────────────────────────────────

    def _cmd_memory(self, _args: str = "") -> None:
        """Show memory system status."""
        from rich.panel import Panel
        from rich.table import Table

        lang: str = self.config.language
        is_tr = lang == "tr"
        self.console.print()

        mem_table = Table(box=None, padding=(0, 2), expand=True, show_header=False)
        mem_table.add_column("Key", style="dim", width=22)
        mem_table.add_column("Value", style="white")

        self._populate_stanford_memory_rows(mem_table, is_tr)
        mem_table.add_row("", "")
        self._populate_evolution_memory_rows(mem_table, is_tr)

        title = "Hafıza Sistemi" if is_tr else "Memory System"
        self.console.print(
            Panel(
                mem_table,
                title=f"[bold cyan]{title}[/]",
                border_style="cyan",
                padding=(0, 1),
            )
        )
        self.console.print()

    def _populate_stanford_memory_rows(self, mem_table: Table, is_tr: bool) -> None:
        """Populate Stanford Memory Stream rows."""
        try:
            from core.agent.memory.memory_stream import get_memory_stream

            ms = get_memory_stream()
            stats = ms.get_stats()
            mem_table.add_row(
                "[bold cyan]Stanford Hafıza[/]" if is_tr else "[bold cyan]Stanford Memory[/]",
                "",
            )
            mem_table.add_row(
                "  Toplam Düğüm" if is_tr else "  Total Nodes",
                str(stats.get("total_nodes", 0)),
            )
            by_type = stats.get("by_type", {})
            if by_type:
                type_str = ", ".join(f"{k}: {v}" for k, v in by_type.items() if v > 0)
                mem_table.add_row(
                    "  Türe Göre" if is_tr else "  By Type",
                    type_str or "—",
                )
            targets = stats.get("targets", [])
            mem_table.add_row(
                "  Hedefler" if is_tr else "  Targets",
                ", ".join(targets[:5]) if targets else "—",
            )
            mem_table.add_row(
                "  Kalıcılık" if is_tr else "  Persistence",
                self._format_feature_flags(stats),
            )
        except (ImportError, AttributeError, RuntimeError):
            logger.debug("Stanford Memory unavailable", exc_info=True)
            mem_table.add_row(
                "Stanford Hafıza" if is_tr else "Stanford Memory",
                "[dim]Başlatılmadı[/]" if is_tr else "[dim]Not initialized[/]",
            )

    @staticmethod
    def _format_feature_flags(stats: dict) -> str:
        """Format persistence/embeddings feature flags."""
        persistence = "✓" if stats.get("persistence_enabled") else "✗"
        embeddings = "✓" if stats.get("embeddings_enabled") else "✗"
        return f"SQLite {persistence} | Embeddings {embeddings}"

    def _populate_evolution_memory_rows(self, mem_table: Table, is_tr: bool) -> None:
        """Populate Evolution Memory rows."""
        try:
            from core.intelligence.evolution_memory import get_evolution_memory

            evo = get_evolution_memory()
            mem_table.add_row(
                "[bold yellow]Evrim Hafızası[/]" if is_tr else "[bold yellow]Evolution Memory[/]",
                "",
            )
            recent = evo.get_recent_actions(count=3)
            mem_table.add_row(
                "  Son Eylemler" if is_tr else "  Recent Actions",
                str(len(recent)),
            )
            penalties = evo.get_all_penalties()
            blocked = sum(1 for p in penalties.values() if p.get("blocked"))
            mem_table.add_row(
                "  Araç Cezaları" if is_tr else "  Tool Penalties",
                f"{len(penalties)} ({blocked} engellenmiş)" if is_tr else f"{len(penalties)} ({blocked} blocked)",
            )
            heuristics = evo.get_all_heuristics()
            mem_table.add_row(
                "  Sezgisel Kurallar" if is_tr else "  Heuristics",
                str(len(heuristics)),
            )
        except (ImportError, AttributeError, RuntimeError):
            logger.debug("Evolution Memory unavailable", exc_info=True)
            mem_table.add_row(
                "Evrim Hafızası" if is_tr else "Evolution Memory",
                "[dim]Başlatılmadı[/]" if is_tr else "[dim]Not initialized[/]",
            )

    # ── Report ──────────────────────────────────────────────────────

    def _build_report_summary_table(self, lang: str, final_path: str) -> Table:
        """Build summary table for report output."""
        from rich.table import Table

        summary_table = Table(show_header=False, box=None, padding=(0, 1))
        summary_table.add_column("K", style=self.STYLE_BOLD_CYAN)
        summary_table.add_column("V")

        s = self.agent.state  # type: ignore[union-attr]
        v_count = len(s.vulnerabilities)
        svc_count = len(s.open_services)

        if lang == "tr":
            summary_table.add_row("📊 Durum:", "[bold green]BAŞARILI[/]")
            summary_table.add_row("📂 Dosya:", f"[cyan]{final_path}[/]")
            summary_table.add_row("🔌 Servisler:", f"{svc_count}")
            summary_table.add_row("⚠️  Zafiyetler:", f"[bold red]{v_count}[/]")
        else:
            summary_table.add_row("📊 Status:", "[bold green]SUCCESS[/]")
            summary_table.add_row("📂 Path:", f"[cyan]{final_path}[/]")
            summary_table.add_row("🔌 Services:", f"{svc_count}")
            summary_table.add_row("⚠️  Vulns:", f"[bold red]{v_count}[/]")

        return summary_table

    def _cmd_report(self, _args: str = "") -> None:
        """Generate professional report."""
        from modules.report_generator import (
            ReportConfig,
            ReportFormat,
            generate_report_from_state,
        )

        lang = self.config.language

        if not self.agent or not self.agent.state:
            msg = "Önce bir tarama başlatın." if lang == "tr" else "Start a scan first."
            self.console.print(f"[red]{msg}[/]")
            return

        gen_msg = "Rapor oluşturuluyor..." if lang == "tr" else "Generating report..."
        self.console.print(f"[{self.COLORS['purple']}]{gen_msg}[/]")

        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = (self.config.target or "unknown").replace(".", "_").replace("/", "_").replace(":", "_")
            output_path = reports_dir / f"drakben_report_{target_clean}_{timestamp}.html"

            config = ReportConfig(
                title=f"DRAKBEN AI Security Report - {self.config.target}",
                use_llm_summary=True,
            )
            final_path = generate_report_from_state(
                state=self.agent.state,
                output_path=str(output_path),
                format=ReportFormat.HTML,
                config=config,
            )

            stitle = "RAPOR" if lang == "tr" else "REPORT"
            self.console.print()
            self.console.print(f"[bold {self.COLORS['cyan']}]{stitle}[/]")
            self.console.print("─" * 40)
            self.console.print(self._build_report_summary_table(lang, final_path))
            self.console.print("─" * 40)

        except (OSError, ValueError, RuntimeError) as e:
            err_msg = f"Rapor hatası: {e}" if lang == "tr" else f"Report error: {e}"
            self.console.print(f"[red]{err_msg}[/]")

    def _get_phase_display_name(self, phase_value: str, is_tr: bool) -> str:
        """Get localized phase display name."""
        if not is_tr:
            return phase_value
        phase_map = {
            "init": "başlatma",
            "recon": "keşif",
            "vulnerability_scan": "zafiyet_taraması",
            "exploit": "sömürü",
            "foothold": "erişim",
            "post_exploit": "sızma_sonrası",
            "complete": "tamamlandı",
            "failed": "başarısız",
        }
        return phase_map.get(phase_value, phase_value)

    # ── Simple UI commands ──────────────────────────────────────────

    def _cmd_clear(self, _args: str = "") -> None:
        """Clear screen - banner and menu remain."""
        self._clear_screen()
        self.show_banner()
        self.show_status_line()

    def _cmd_turkish(self, _args: str = "") -> None:
        """Switch to Turkish."""
        self.config_manager.set_language("tr")
        self.config = self.config_manager.config
        self.console.print("[green]Dil Türkçe olarak ayarlandı.[/]")

    def _cmd_english(self, _args: str = "") -> None:
        """Switch to English."""
        self.config_manager.set_language("en")
        self.config = self.config_manager.config
        self.console.print("[green]Language set to English.[/]")
