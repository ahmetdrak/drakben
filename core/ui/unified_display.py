# core/ui/unified_display.py
# DRAKBEN - Unified Display Components
# Tek tip görsel dil: LLM thinking, scan, exploit, confirmation

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from rich.console import RenderableType

# ==============================================================================
# ENUMS & DATA CLASSES
# ==============================================================================


class OperationType(Enum):
    """Operation types for visual distinction."""

    THINKING = "thinking"  # LLM düşünüyor
    SCANNING = "scanning"  # Port/vuln tarama
    EXPLOITING = "exploiting"  # Exploit çalıştırma
    ANALYZING = "analyzing"  # Sonuç analizi
    WAITING = "waiting"  # Kullanıcı bekleme
    EXECUTING = "executing"  # Komut çalıştırma


class RiskLevel(Enum):
    """Risk levels for confirmation prompts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class OperationStatus:
    """Current operation status for live display."""

    operation_type: OperationType
    phase: str = ""  # RECON, VULN_SCAN, EXPLOIT, etc.
    current_tool: str = ""
    current_target: str = ""
    current_step: int = 0
    total_steps: int = 0
    message: str = ""
    sub_message: str = ""
    elapsed_seconds: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfirmationRequest:
    """Confirmation request with risk context."""

    command: str
    risk_level: RiskLevel
    reason: str
    details: list[str] = field(default_factory=list)
    allow_auto: bool = False  # Otonom modda otomatik onay izni


# ==============================================================================
# STYLE CONSTANTS
# ==============================================================================

# Shared style constants to avoid duplication
STYLE_BOLD_RED = "bold red"
STYLE_BOLD_RED_ON_WHITE = "bold red on white"

COLORS = {
    "thinking": "bold magenta",
    "scanning": "bold cyan",
    "exploiting": STYLE_BOLD_RED,
    "analyzing": "bold yellow",
    "waiting": "bold blue",
    "executing": "bold green",
    "risk_low": "green",
    "risk_medium": "yellow",
    "risk_high": "red",
    "risk_critical": STYLE_BOLD_RED_ON_WHITE,
    "success": "bold green",
    "error": STYLE_BOLD_RED,
    "warning": "bold yellow",
    "info": "cyan",
    "dim": "dim white",
}

ICONS = {
    "thinking": "🧠",
    "scanning": "🔍",
    "exploiting": "💥",
    "analyzing": "📊",
    "waiting": "⏳",
    "executing": "⚡",
    "success": "✓",
    "error": "✗",
    "warning": "⚠",
    "info": "ℹ",
    "risk": "🛡",
    "phase": "📍",
    "tool": "🔧",
    "target": "🎯",
    "time": "⏱",
}

PHASE_LABELS = {
    "RECON": ("Keşif", "Reconnaissance"),
    "VULN_SCAN": ("Zafiyet Tarama", "Vulnerability Scan"),
    "EXPLOIT": ("Sömürü", "Exploitation"),
    "POST_EXPLOIT": ("Post-Exploit", "Post-Exploitation"),
    "LATERAL": ("Yanal Hareket", "Lateral Movement"),
    "PERSISTENCE": ("Kalıcılık", "Persistence"),
    "CLEANUP": ("Temizlik", "Cleanup"),
}


# ==============================================================================
# LIVE OPERATION DISPLAY
# ==============================================================================


class LiveOperationDisplay:
    """Unified live display for all long-running operations.

    Features:
    - Real-time status updates
    - Phase/tool/target information
    - Elapsed time tracking
    - Progress indication (determinate or indeterminate)
    - Consistent visual language across all operations
    """

    def __init__(
        self,
        console: Console | None = None,
        language: str = "en",
        refresh_rate: int = 4,
    ) -> None:
        self.console = console or Console()
        self.language = language
        self.refresh_rate = refresh_rate
        self._live: Live | None = None
        self._status: OperationStatus | None = None
        self._start_time: float = 0.0
        self._progress: Progress | None = None
        self._task_id: Any = None

    def _get_phase_label(self, phase: str) -> str:
        """Get localized phase label."""
        labels = PHASE_LABELS.get(phase.upper(), (phase, phase))
        return labels[0] if self.language == "tr" else labels[1]

    def _get_operation_style(self, op_type: OperationType) -> str:
        """Get style for operation type."""
        return COLORS.get(op_type.value, "white")

    def _get_operation_icon(self, op_type: OperationType) -> str:
        """Get icon for operation type."""
        return ICONS.get(op_type.value, "●")

    def _build_status_panel(self) -> Panel:
        """Build the main status panel."""
        if not self._status:
            return Panel("No operation", title="DRAKBEN")

        status = self._status
        op_style = self._get_operation_style(status.operation_type)
        op_icon = self._get_operation_icon(status.operation_type)

        # Build content lines
        lines: list[RenderableType] = []

        # Main message with icon
        main_text = Text()
        main_text.append(f"{op_icon} ", style=op_style)
        main_text.append(status.message or status.operation_type.value.upper(), style=op_style)
        lines.append(main_text)

        # Sub-message if present
        if status.sub_message:
            lines.append(Text(f"   {status.sub_message}", style="dim"))

        # Info table
        info_table = Table.grid(padding=(0, 2))
        info_table.add_column(style="dim", width=12)
        info_table.add_column()

        # Phase
        if status.phase:
            phase_label = self._get_phase_label(status.phase)
            info_table.add_row(
                f"{ICONS['phase']} Phase:",
                f"[bold]{phase_label}[/]",
            )

        # Tool
        if status.current_tool:
            info_table.add_row(
                f"{ICONS['tool']} Tool:",
                f"[cyan]{status.current_tool}[/]",
            )

        # Target
        if status.current_target:
            info_table.add_row(
                f"{ICONS['target']} Target:",
                f"[yellow]{status.current_target}[/]",
            )

        # Progress (steps)
        if status.total_steps > 0:
            progress_text = f"{status.current_step}/{status.total_steps}"
            info_table.add_row("   Steps:", progress_text)

        # Elapsed time
        elapsed = time.time() - self._start_time
        elapsed_str = f"{elapsed:.1f}s"
        if elapsed > 60:
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            elapsed_str = f"{mins}m {secs}s"
        info_table.add_row(f"{ICONS['time']} Time:", elapsed_str)

        lines.append(Text())  # Spacer
        lines.append(info_table)

        # Additional details - use Text.from_markup for Rich markup support
        if status.details:
            lines.append(Text())
            for key, value in status.details.items():
                # Use from_markup to properly render Rich markup in values
                detail_text = Text.from_markup(f"   {key}: {value}")
                lines.append(detail_text)

        # Build title
        title_text = "DRAKBEN"
        if status.phase:
            title_text = f"DRAKBEN • {self._get_phase_label(status.phase)}"

        return Panel(
            Group(*lines),
            title=f"[{op_style}]{title_text}[/]",
            border_style=op_style,
            padding=(1, 2),
        )

    def start(
        self,
        operation_type: OperationType,
        message: str = "",
        phase: str = "",
        target: str = "",
    ) -> LiveOperationDisplay:
        """Start the live display.

        Args:
            operation_type: Type of operation (THINKING, SCANNING, etc.)
            message: Main status message
            phase: Current pentest phase
            target: Current target

        Returns:
            Self for chaining
        """
        self._start_time = time.time()
        self._status = OperationStatus(
            operation_type=operation_type,
            phase=phase,
            current_target=target,
            message=message,
        )

        self._live = Live(
            self._build_status_panel(),
            console=self.console,
            refresh_per_second=self.refresh_rate,
            transient=False,  # Keep visible after completion
        )
        self._live.start()
        return self

    def update(
        self,
        message: str | None = None,
        sub_message: str | None = None,
        tool: str | None = None,
        step: int | None = None,
        total_steps: int | None = None,
        phase: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Update the live display.

        Args:
            message: New main message
            sub_message: New sub-message
            tool: Current tool being used
            step: Current step number
            total_steps: Total number of steps
            phase: New phase
            details: Additional details dict
        """
        if not self._status:
            return

        if message is not None:
            self._status.message = message
        if sub_message is not None:
            self._status.sub_message = sub_message
        if tool is not None:
            self._status.current_tool = tool
        if step is not None:
            self._status.current_step = step
        if total_steps is not None:
            self._status.total_steps = total_steps
        if phase is not None:
            self._status.phase = phase
        if details is not None:
            self._status.details.update(details)

        if self._live:
            self._live.update(self._build_status_panel())

    def stop(self, final_message: str | None = None, success: bool = True) -> None:
        """Stop the live display.

        Args:
            final_message: Optional final message to show
            success: Whether operation succeeded
        """
        if self._live:
            # Show final state
            if final_message and self._status:
                self._status.message = final_message
                icon = ICONS["success"] if success else ICONS["error"]
                result_text = "OK" if success else "FAILED"
                result_color = "green" if success else "red"
                self._status.sub_message = ""
                # Use simple format that will be rendered by from_markup
                self._status.details["Result"] = f"[bold {result_color}]{icon} {result_text}[/]"
                self._live.update(self._build_status_panel())

            self._live.stop()
            self._live = None

    def __enter__(self) -> LiveOperationDisplay:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        success = exc_type is None
        self.stop(success=success)


# ==============================================================================
# UNIFIED CONFIRMATION DIALOG
# ==============================================================================


class UnifiedConfirmation:
    """Unified confirmation dialog with risk visualization.

    Features:
    - Visual risk level indicator
    - Detailed reason display
    - Consistent Y/N handling across TR/EN
    - Auto-approve option for autonomous mode
    """

    def __init__(
        self,
        console: Console | None = None,
        language: str = "en",
        auto_approve: bool = False,
    ) -> None:
        self.console = console or Console()
        self.language = language
        self.auto_approve = auto_approve

    def _get_risk_style(self, risk: RiskLevel) -> str:
        """Get style for risk level."""
        return COLORS.get(f"risk_{risk.value}", "white")

    def _get_risk_label(self, risk: RiskLevel) -> str:
        """Get localized risk label."""
        labels = {
            RiskLevel.LOW: ("Düşük Risk", "Low Risk"),
            RiskLevel.MEDIUM: ("Orta Risk", "Medium Risk"),
            RiskLevel.HIGH: ("Yüksek Risk", "High Risk"),
            RiskLevel.CRITICAL: ("KRİTİK RİSK", "CRITICAL RISK"),
        }
        label_pair = labels.get(risk, ("Risk", "Risk"))
        return label_pair[0] if self.language == "tr" else label_pair[1]

    def _build_confirmation_panel(self, request: ConfirmationRequest) -> Panel:
        """Build confirmation panel."""
        risk_style = self._get_risk_style(request.risk_level)
        risk_label = self._get_risk_label(request.risk_level)

        lines: list[RenderableType] = []

        # Risk header
        risk_text = Text()
        risk_text.append(f"{ICONS['risk']} ", style=risk_style)
        risk_text.append(risk_label, style=risk_style)
        lines.append(risk_text)
        lines.append(Text())

        # Command
        cmd_label = "Komut" if self.language == "tr" else "Command"
        lines.append(Text(f"{cmd_label}:", style="bold"))
        lines.append(Text(f"  {request.command}", style="cyan"))
        lines.append(Text())

        # Reason
        reason_label = "Sebep" if self.language == "tr" else "Reason"
        lines.append(Text(f"{reason_label}:", style="bold"))
        lines.append(Text(f"  {request.reason}", style="yellow"))

        # Details
        if request.details:
            lines.append(Text())
            details_label = "Detaylar" if self.language == "tr" else "Details"
            lines.append(Text(f"{details_label}:", style="bold"))
            for detail in request.details:
                lines.append(Text(f"  • {detail}", style="dim"))

        title = "Onay Gerekiyor" if self.language == "tr" else "Confirmation Required"

        return Panel(
            Group(*lines),
            title=f"[{risk_style}]{ICONS['warning']} {title}[/]",
            border_style=risk_style,
            padding=(1, 2),
        )

    def ask(self, request: ConfirmationRequest) -> bool:
        """Show confirmation dialog and get response.

        Args:
            request: Confirmation request with command, risk, and reason

        Returns:
            True if approved, False if denied
        """
        # Auto-approve if enabled and allowed
        if self.auto_approve and request.allow_auto:
            self.console.print(
                f"[dim]{ICONS['info']} Auto-approved: {request.command[:50]}...[/]",
            )
            return True

        # Show panel
        self.console.print()
        self.console.print(self._build_confirmation_panel(request))

        # Get response
        if self.language == "tr":
            prompt = "Çalıştır? [e/h]"
            yes_values = {"e", "evet", "y", "yes"}
            no_values = {"h", "hayir", "n", "no"}
        else:
            prompt = "Execute? [y/n]"
            yes_values = {"y", "yes", "e", "evet"}
            no_values = {"n", "no", "h", "hayir"}

        try:
            response = self.console.input(f"[bold]{prompt}[/] ").strip().lower()
            if response in yes_values:
                return True
            if response in no_values:
                return False
            # Default to no for safety
            denied_msg = "Varsayılan: Reddedildi" if self.language == "tr" else "Default: Denied"
            self.console.print(f"[dim]{denied_msg}[/]")
            return False
        except (KeyboardInterrupt, EOFError):
            cancelled_msg = "İptal edildi" if self.language == "tr" else "Cancelled"
            self.console.print(f"\n[yellow]{cancelled_msg}[/]")
            return False

    def ask_simple(
        self,
        command: str,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        reason: str = "",
    ) -> bool:
        """Simplified confirmation for quick use.

        Args:
            command: Command to confirm
            risk_level: Risk level
            reason: Reason for confirmation

        Returns:
            True if approved
        """
        request = ConfirmationRequest(
            command=command,
            risk_level=risk_level,
            reason=reason or "User confirmation required",
        )
        return self.ask(request)


# ==============================================================================
# RESULT DISPLAY
# ==============================================================================


class ResultDisplay:
    """Unified result display for operation outcomes."""

    def __init__(
        self,
        console: Console | None = None,
        language: str = "en",
    ) -> None:
        self.console = console or Console()
        self.language = language

    def show_success(
        self,
        message: str,
        details: list[str] | None = None,
        next_action: str | None = None,
    ) -> None:
        """Show success result."""
        lines: list[RenderableType] = []

        # Main message
        main_text = Text()
        main_text.append(f"{ICONS['success']} ", style=COLORS["success"])
        main_text.append(message, style=COLORS["success"])
        lines.append(main_text)

        # Details
        if details:
            lines.append(Text())
            for detail in details:
                lines.append(Text(f"  • {detail}", style="dim"))

        # Next action
        if next_action:
            lines.append(Text())
            next_label = "Sonraki" if self.language == "tr" else "Next"
            lines.append(Text(f"{next_label}: {next_action}", style="cyan"))

        self.console.print(Panel(
            Group(*lines),
            border_style=COLORS["success"],
            padding=(0, 1),
        ))

    def show_error(
        self,
        message: str,
        details: list[str] | None = None,
        suggestion: str | None = None,
    ) -> None:
        """Show error result."""
        lines: list[RenderableType] = []

        # Main message
        main_text = Text()
        main_text.append(f"{ICONS['error']} ", style=COLORS["error"])
        main_text.append(message, style=COLORS["error"])
        lines.append(main_text)

        # Details
        if details:
            lines.append(Text())
            for detail in details:
                lines.append(Text(f"  • {detail}", style="dim red"))

        # Suggestion
        if suggestion:
            lines.append(Text())
            tip_label = "İpucu" if self.language == "tr" else "Tip"
            lines.append(Text(f"{tip_label}: {suggestion}", style="yellow"))

        self.console.print(Panel(
            Group(*lines),
            border_style=COLORS["error"],
            padding=(0, 1),
        ))

    def show_findings(
        self,
        title: str,
        findings: list[dict[str, Any]],
        severity_key: str = "severity",
    ) -> None:
        """Show findings table (vulnerabilities, ports, etc.)."""
        if not findings:
            no_findings = "Bulgu yok" if self.language == "tr" else "No findings"
            self.console.print(f"[dim]{no_findings}[/]")
            return

        table = Table(title=title, border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Finding", style="white")
        table.add_column("Severity", style="yellow")
        table.add_column("Details", style="dim")

        severity_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }

        for i, finding in enumerate(findings[:20], 1):  # Limit to 20
            severity = finding.get(severity_key, "info").lower()
            sev_style = severity_colors.get(severity, "white")

            table.add_row(
                str(i),
                str(finding.get("name", finding.get("title", "Unknown"))),
                f"[{sev_style}]{severity.upper()}[/]",
                str(finding.get("details", finding.get("description", "")))[:50],
            )

        self.console.print(table)


# ==============================================================================
# THINKING DISPLAY (LLM-specific)
# ==============================================================================


class ThinkingDisplay(LiveOperationDisplay):
    """Specialized display for LLM thinking operations.

    Extends LiveOperationDisplay with LLM-specific features:
    - Cache hit indicator
    - Model name display
    - Token count (if available)
    """

    def __init__(
        self,
        console: Console | None = None,
        language: str = "en",
    ) -> None:
        super().__init__(console, language)
        self._model_name: str = ""
        self._cache_hit: bool = False
        self._token_count: int = 0

    def start_thinking(
        self,
        target: str = "",
        phase: str = "",
        model: str = "",
    ) -> ThinkingDisplay:
        """Start thinking display.

        Args:
            target: Current target
            phase: Current pentest phase
            model: LLM model name

        Returns:
            Self for chaining
        """
        self._model_name = model

        message = "Düşünüyor..." if self.language == "tr" else "Thinking..."
        self.start(
            operation_type=OperationType.THINKING,
            message=message,
            phase=phase,
            target=target,
        )

        if model:
            self.update(details={"Model": model})

        return self

    def set_cache_hit(self, hit: bool = True) -> None:
        """Indicate cache hit."""
        self._cache_hit = hit
        if hit:
            cache_msg = "Önbellekten" if self.language == "tr" else "From cache"
            self.update(sub_message=f"⚡ {cache_msg}")

    def set_analyzing(self, what: str = "") -> None:
        """Switch to analyzing state."""
        if self._status:
            self._status.operation_type = OperationType.ANALYZING
            analyzing_msg = "Analiz ediliyor..." if self.language == "tr" else "Analyzing..."
            self.update(message=analyzing_msg, sub_message=what)

    def finish_thinking(self, success: bool = True) -> None:
        """Finish thinking with result status."""
        if success:
            done_msg = "Tamamlandı" if self.language == "tr" else "Complete"
        else:
            done_msg = "Başarısız" if self.language == "tr" else "Failed"

        self.stop(final_message=done_msg, success=success)


# ==============================================================================
# SCAN DISPLAY (Scan-specific)
# ==============================================================================


class ScanDisplay(LiveOperationDisplay):
    """Specialized display for scanning operations.

    Extends LiveOperationDisplay with scan-specific features:
    - Port range display
    - Found services counter
    - Vulnerability counter
    """

    def __init__(
        self,
        console: Console | None = None,
        language: str = "en",
    ) -> None:
        super().__init__(console, language)
        self._ports_scanned: int = 0
        self._services_found: int = 0
        self._vulns_found: int = 0

    def start_scan(
        self,
        target: str,
        mode: str = "auto",
        phase: str = "RECON",
    ) -> ScanDisplay:
        """Start scan display.

        Args:
            target: Scan target
            mode: Scan mode (auto/stealth/aggressive)
            phase: Current phase

        Returns:
            Self for chaining
        """
        scanning_msg = "Taranıyor..." if self.language == "tr" else "Scanning..."

        self.start(
            operation_type=OperationType.SCANNING,
            message=scanning_msg,
            phase=phase,
            target=target,
        )

        mode_label = mode.upper()
        self.update(details={"Mode": mode_label})

        return self

    def update_progress(
        self,
        tool: str = "",
        ports_scanned: int | None = None,
        services_found: int | None = None,
        vulns_found: int | None = None,
        current_action: str = "",
    ) -> None:
        """Update scan progress.

        Args:
            tool: Current tool being used
            ports_scanned: Number of ports scanned
            services_found: Number of services found
            vulns_found: Number of vulnerabilities found
            current_action: Current action description
        """
        if ports_scanned is not None:
            self._ports_scanned = ports_scanned
        if services_found is not None:
            self._services_found = services_found
        if vulns_found is not None:
            self._vulns_found = vulns_found

        details: dict[str, Any] = {}
        if self._ports_scanned > 0:
            details["Ports"] = str(self._ports_scanned)
        if self._services_found > 0:
            services_label = "Servisler" if self.language == "tr" else "Services"
            details[services_label] = str(self._services_found)
        if self._vulns_found > 0:
            vulns_label = "Zafiyetler" if self.language == "tr" else "Vulns"
            details[vulns_label] = f"[red]{self._vulns_found}[/]"

        self.update(
            tool=tool or None,
            sub_message=current_action or None,
            details=details if details else None,
        )

    def finish_scan(self, success: bool = True) -> dict[str, int]:
        """Finish scan and return stats.

        Returns:
            Dict with ports_scanned, services_found, vulns_found
        """
        if success:
            done_msg = "Tarama tamamlandı" if self.language == "tr" else "Scan complete"
        else:
            done_msg = "Tarama başarısız" if self.language == "tr" else "Scan failed"

        self.stop(final_message=done_msg, success=success)

        return {
            "ports_scanned": self._ports_scanned,
            "services_found": self._services_found,
            "vulns_found": self._vulns_found,
        }


# ==============================================================================
# FACTORY FUNCTIONS
# ==============================================================================


def create_thinking_display(
    console: Console | None = None,
    language: str = "en",
) -> ThinkingDisplay:
    """Create a thinking display instance."""
    return ThinkingDisplay(console=console, language=language)


def create_scan_display(
    console: Console | None = None,
    language: str = "en",
) -> ScanDisplay:
    """Create a scan display instance."""
    return ScanDisplay(console=console, language=language)


def create_confirmation(
    console: Console | None = None,
    language: str = "en",
    auto_approve: bool = False,
) -> UnifiedConfirmation:
    """Create a unified confirmation instance."""
    return UnifiedConfirmation(
        console=console,
        language=language,
        auto_approve=auto_approve,
    )


def create_result_display(
    console: Console | None = None,
    language: str = "en",
) -> ResultDisplay:
    """Create a result display instance."""
    return ResultDisplay(console=console, language=language)
