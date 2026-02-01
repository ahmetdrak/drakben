# core/code_review.py
# DRAKBEN Code Review Module
# Provides code review and approval workflow before execution
# Similar to Open Interpreter's code review feature

import ast
import difflib
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from collections.abc import Callable

from rich.console import Console
from rich.panel import Panel

# Setup logger
logger = logging.getLogger(__name__)


class ReviewStatus(Enum):
    """Status of a code review"""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    AUTO_APPROVED = "auto_approved"


class RiskLevel(Enum):
    """Risk level of code changes"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CodeChange:
    """Represents a single code change"""

    change_id: str
    file_path: str
    original_content: str
    new_content: str
    change_type: str  # "create", "modify", "delete"
    description: str
    risk_level: RiskLevel
    created_at: float
    status: ReviewStatus = ReviewStatus.PENDING
    reviewed_by: str = ""
    reviewed_at: float | None = None
    review_notes: str = ""
    diff_lines: list[str] = field(default_factory=list)


@dataclass
class ReviewSession:
    """A review session containing multiple changes"""

    session_id: str
    changes: list[CodeChange]
    created_at: float
    status: ReviewStatus = ReviewStatus.PENDING
    auto_approve_low_risk: bool = False
    requires_all_approved: bool = True


class CodeAnalyzer:
    """
    Analyzes code for security risks and quality issues.
    Used to determine risk level and highlight concerns.
    """

    # Patterns that indicate high-risk code
    HIGH_RISK_PATTERNS = [
        "eval(",
        "exec(",
        "compile(",
        "__import__",
        "getattr(",
        "setattr(",
        "os.system",
        "subprocess.call",
        "subprocess.run",
        "shell=True",
        "rm -rf",
        "del ",
        "unlink",
        "chmod 777",
        "chmod 666",
        "password",
        "secret",
        "token",
    ]

    # Patterns that indicate medium-risk code
    MEDIUM_RISK_PATTERNS = [
        "open(",
        "write(",
        "read(",
        "socket.",
        "http.",
        "requests.",
        "urllib.",
        "pickle.",
        "import os",
        "import sys",
    ]

    # Safe patterns (lower risk score)
    SAFE_PATTERNS = [
        "def ",
        "class ",
        "return ",
        "import logging",
        "import json",
        "# ",
        '"""',
        "'''",
    ]

    @classmethod
    def analyze_code(cls, code: str) -> tuple[RiskLevel, list[str]]:
        """
        Analyze code and return risk level with concerns.

        Returns:
            (RiskLevel, list of concern strings)
        """
        concerns = []
        risk_score = 0

        code_lower = code.lower()

        # Check high-risk patterns
        for pattern in cls.HIGH_RISK_PATTERNS:
            if pattern.lower() in code_lower:
                concerns.append(f"High-risk pattern found: {pattern}")
                risk_score += 10

        # Check medium-risk patterns
        for pattern in cls.MEDIUM_RISK_PATTERNS:
            if pattern.lower() in code_lower:
                concerns.append(f"Medium-risk pattern found: {pattern}")
                risk_score += 3

        # Check for safe patterns (reduce score)
        for pattern in cls.SAFE_PATTERNS:
            if pattern.lower() in code_lower:
                risk_score -= 1

        # Check for syntax errors
        try:
            ast.parse(code)
        except SyntaxError as e:
            concerns.append(f"Syntax error: {e}")
            risk_score += 5

        # Check code length (very long generated code is suspicious)
        line_count = code.count("\n") + 1
        if line_count > 500:
            concerns.append(f"Very long code ({line_count} lines)")
            risk_score += 5

        # Determine risk level
        risk_score = max(0, risk_score)  # Ensure non-negative

        if risk_score >= 20:
            return RiskLevel.CRITICAL, concerns
        elif risk_score >= 10:
            return RiskLevel.HIGH, concerns
        elif risk_score >= 5:
            return RiskLevel.MEDIUM, concerns
        else:
            return RiskLevel.LOW, concerns

    @classmethod
    def check_ast_safety(cls, code: str) -> tuple[bool, list[str]]:
        """
        Perform AST-based safety check.
        """
        issues: list[str] = []
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, [f"Syntax error: {e}"]

        for node in ast.walk(tree):
            cls._check_node_safety(node, issues)

        return len(issues) == 0, issues

    @classmethod
    def _check_node_safety(cls, node: ast.AST, issues: list[str]):
        """Helper to check individual AST nodes for safety"""
        # Check for dangerous function calls
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec", "compile"):
                issues.append(f"Dangerous function call: {node.func.id}")

        # Check for dangerous imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("ctypes", "pickle", "marshal"):
                    issues.append(f"Dangerous import: {alias.name}")

        # Check for dangerous "from" imports
        if isinstance(node, ast.ImportFrom):
            if node.module in ("ctypes", "pickle", "marshal"):
                issues.append(f"Dangerous import from: {node.module}")


class CodeReview:
    """
    Main code review system.

    Features:
    - Interactive diff display
    - Risk assessment
    - Approval workflow
    - Rollback support
    - History tracking
    """

    def __init__(
        self,
        auto_approve_low_risk: bool = False,
        require_explicit_approval: bool = True,
        backup_dir: str = ".drakben_backups",
    ):
        self.console = Console()
        self.auto_approve_low_risk = auto_approve_low_risk
        self.require_explicit_approval = require_explicit_approval
        self.backup_dir = Path(backup_dir)

        # Review history
        self.sessions: list[ReviewSession] = []
        self.pending_changes: list[CodeChange] = []

        # Callbacks
        self.on_approval: Callable[[CodeChange], None] | None = None
        self.on_rejection: Callable[[CodeChange], None] | None = None

        # Create backup directory
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _generate_id() -> str:
        """Generate unique ID"""
        return hashlib.sha256(
            f"{time.time()}{os.urandom(8).hex()}".encode()
        ).hexdigest()[:12]

    def create_change(
        self,
        file_path: str,
        new_content: str,
        description: str = "",
        change_type: str = "modify",
    ) -> CodeChange:
        """
        Create a new code change for review.

        Args:
            file_path: Path to the file
            new_content: New content to write
            description: Description of the change
            change_type: Type of change (create, modify, delete)

        Returns:
            CodeChange object
        """
        # Read original content if file exists
        original_content = ""
        if os.path.exists(file_path):
            try:
                with open(file_path, encoding="utf-8") as f:
                    original_content = f.read()
            except Exception as e:
                logger.debug(f"Failed to read file for diff: {e}")

        # Analyze risk
        risk_level, _ = CodeAnalyzer.analyze_code(new_content)

        # Generate diff
        diff_lines = list(
            difflib.unified_diff(
                original_content.splitlines(keepends=True),
                new_content.splitlines(keepends=True),
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="",
            )
        )

        change = CodeChange(
            change_id=self._generate_id(),
            file_path=file_path,
            original_content=original_content,
            new_content=new_content,
            change_type=change_type,
            description=description or f"Modify {file_path}",
            risk_level=risk_level,
            created_at=time.time(),
            diff_lines=diff_lines,
        )

        self.pending_changes.append(change)
        logger.info(f"Created code change: {change.change_id} ({risk_level.value})")

        return change

    def _handle_approve(self, change: CodeChange) -> bool:
        """Handle approval action"""
        change.status = ReviewStatus.APPROVED
        change.reviewed_at = time.time()
        self.console.print("[green]Change approved.[/green]")
        if self.on_approval:
            self.on_approval(change)
        return True

    def _handle_reject(self, change: CodeChange) -> bool:
        """Handle rejection action"""
        change.status = ReviewStatus.REJECTED
        change.reviewed_at = time.time()
        notes = input("Rejection reason (optional): ").strip()
        change.review_notes = notes
        self.console.print("[red]Change rejected.[/red]")
        if self.on_rejection:
            self.on_rejection(change)
        return False

    def _handle_user_response(self, change: CodeChange, response: str) -> bool | None:
        """Handle user response to review prompt"""
        if response == "a":
            return self._handle_approve(change)
        elif response == "r":
            return self._handle_reject(change)
        elif response == "d":
            self._display_diff(change)
            return None
        elif response == "e":
            self.console.print("[yellow]Edit not implemented yet.[/yellow]")
            return None
        elif response == "q":
            return False
        else:
            self.console.print("[yellow]Invalid option.[/yellow]")
            return None

    def review_change(self, change: CodeChange, interactive: bool = True) -> bool:
        """
        Review a single code change.

        Args:
            change: The CodeChange to review
            interactive: Whether to prompt for user approval

        Returns:
            True if approved, False otherwise
        """
        # Auto-approve low risk if enabled
        if self.auto_approve_low_risk and change.risk_level == RiskLevel.LOW:
            change.status = ReviewStatus.AUTO_APPROVED
            change.reviewed_at = time.time()
            logger.info(f"Auto-approved low-risk change: {change.change_id}")
            return True

        if not interactive:
            return False

        # Show review UI
        self._display_change(change)

        # Get approval
        while True:
            response = (
                input("\n[A]pprove / [R]eject / [D]iff / [E]dit / [Q]uit? ")
                .strip()
                .lower()
            )
            result = self._handle_user_response(change, response)
            if result is not None:
                return result

    def review_all_pending(self, interactive: bool = True) -> tuple[int, int]:
        """
        Review all pending changes.

        Returns:
            (approved_count, rejected_count)
        """
        approved = 0
        rejected = 0

        for change in self.pending_changes[:]:  # Copy list for iteration
            if change.status == ReviewStatus.PENDING:
                if self.review_change(change, interactive):
                    approved += 1
                else:
                    rejected += 1

        return approved, rejected

    def apply_change(self, change: CodeChange, create_backup: bool = True) -> bool:
        """
        Apply an approved change to the filesystem.

        Args:
            change: The approved CodeChange
            create_backup: Whether to create a backup

        Returns:
            True if successful
        """
        if change.status not in (ReviewStatus.APPROVED, ReviewStatus.AUTO_APPROVED):
            logger.warning(f"Cannot apply non-approved change: {change.change_id}")
            return False

        try:
            # Create backup if file exists
            if create_backup and os.path.exists(change.file_path):
                backup_path = (
                    self.backup_dir
                    / f"{change.change_id}_{Path(change.file_path).name}.bak"
                )
                with open(change.file_path, encoding="utf-8") as f:
                    with open(backup_path, "w", encoding="utf-8") as bf:
                        bf.write(f.read())
                logger.info(f"Created backup: {backup_path}")

            # Apply change
            if change.change_type == "delete":
                if os.path.exists(change.file_path):
                    os.remove(change.file_path)
            else:
                # Create parent directories if needed
                Path(change.file_path).parent.mkdir(parents=True, exist_ok=True)

                with open(change.file_path, "w", encoding="utf-8") as f:
                    f.write(change.new_content)

            logger.info(f"Applied change: {change.change_id} to {change.file_path}")
            self.pending_changes.remove(change)
            return True

        except Exception as e:
            logger.exception(f"Failed to apply change: {e}")
            return False

    def rollback_change(self, change_id: str) -> bool:
        """
        Rollback a previously applied change.

        Args:
            change_id: ID of the change to rollback

        Returns:
            True if successful
        """
        # Find backup file
        for backup_file in self.backup_dir.glob(f"{change_id}_*.bak"):
            try:
                # Extract original filename
                original_name = backup_file.name.replace(f"{change_id}_", "").replace(
                    ".bak", ""
                )

                # Read backup content (simplified rollback - would need more context in production)
                with open(backup_file, encoding="utf-8") as f:
                    _ = f.read()
                self.console.print(
                    f"[yellow]Rollback content available for: {original_name}[/yellow]"
                )
                self.console.print(f"Backup file: {backup_file}")

                return True

            except Exception as e:
                logger.exception(f"Rollback failed: {e}")
                return False

        logger.warning(f"No backup found for change: {change_id}")
        return False

    def _display_change(self, change: CodeChange):
        """Display a change for review"""
        # Risk level color
        risk_colors = {
            RiskLevel.LOW: "green",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.HIGH: "red",
            RiskLevel.CRITICAL: "bold red",
        }
        risk_color = risk_colors.get(change.risk_level, "white")

        # Header
        self.console.print("\n" + "=" * 60)
        self.console.print(
            Panel(
                f"[bold]Code Review[/bold]\n\n"
                f"File: [cyan]{change.file_path}[/cyan]\n"
                f"Type: {change.change_type}\n"
                f"Risk: [{risk_color}]{change.risk_level.value.upper()}[/{risk_color}]\n"
                f"Description: {change.description}",
                title="Review Required",
                border_style=risk_color,
            )
        )

        # Show concerns if high risk
        if change.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            _, concerns = CodeAnalyzer.analyze_code(change.new_content)
            if concerns:
                self.console.print("\n[bold red]Security Concerns:[/bold red]")
                for concern in concerns:
                    self.console.print(f"  ⚠️  {concern}")

        # Show diff summary
        additions = sum(
            1
            for line in change.diff_lines
            if line.startswith("+") and not line.startswith("+++")
        )
        deletions = sum(
            1
            for line in change.diff_lines
            if line.startswith("-") and not line.startswith("---")
        )
        self.console.print(
            f"\n[green]+{additions}[/green] / [red]-{deletions}[/red] lines"
        )

    def _display_diff(self, change: CodeChange):
        """Display the diff of a change"""
        self.console.print("\n[bold]Diff:[/bold]\n")

        for line in change.diff_lines:
            if line.startswith("+") and not line.startswith("+++"):
                self.console.print(f"[green]{line}[/green]")
            elif line.startswith("-") and not line.startswith("---"):
                self.console.print(f"[red]{line}[/red]")
            elif line.startswith("@@"):
                self.console.print(f"[cyan]{line}[/cyan]")
            else:
                self.console.print(line)

    def get_pending_summary(self) -> dict:
        """Get summary of pending changes"""
        by_risk: dict[RiskLevel, list[CodeChange]] = {level: [] for level in RiskLevel}

        for change in self.pending_changes:
            if change.status == ReviewStatus.PENDING:
                by_risk[change.risk_level].append(change)

        return {
            "total": sum(len(v) for v in by_risk.values()),
            "by_risk": {k.value: len(v) for k, v in by_risk.items()},
            "changes": self.pending_changes,
        }

    def clear_pending(self):
        """Clear all pending changes"""
        self.pending_changes.clear()
        logger.info("Cleared all pending changes")


class CodeReviewMiddleware:
    """
    Middleware that intercepts code execution and applies review.
    Can be used to wrap the AICoder or ExecutionEngine.
    """

    def __init__(self, review_system: CodeReview):
        self.review = review_system

    def wrap_file_write(
        self, file_path: str, content: str, description: str = ""
    ) -> bool:
        """
        Wrap a file write operation with code review.

        Returns:
            True if write was approved and successful
        """
        change = self.review.create_change(
            file_path=file_path, new_content=content, description=description
        )

        if self.review.review_change(change, interactive=True):
            return self.review.apply_change(change)

        return False

    def wrap_code_execution(
        self, code: str, executor: Callable[[str], Any], description: str = ""
    ) -> tuple[bool, Any]:
        """
        Wrap code execution with review.

        Returns:
            (approved, execution_result)
        """
        # Create a virtual change for the code
        change = self.review.create_change(
            file_path="<execution>",
            new_content=code,
            description=description or "Execute code",
            change_type="execute",
        )

        if self.review.review_change(change, interactive=True):
            # Execute the code
            try:
                result = executor(code)
                return True, result
            except Exception as e:
                return True, {"error": str(e)}

        return False, None


# Convenience functions
def create_review_system(auto_approve_low: bool = False) -> CodeReview:
    """Create a new code review system"""
    return CodeReview(auto_approve_low_risk=auto_approve_low)


def quick_review(file_path: str, new_content: str, description: str = "") -> bool:
    """
    Quick review of a single file change.

    Returns:
        True if approved and applied
    """
    review = CodeReview()
    change = review.create_change(file_path, new_content, description)

    if review.review_change(change):
        return review.apply_change(change)

    return False


if __name__ == "__main__":
    # Demo mode
    console = Console()
    console.print("[bold]DRAKBEN Code Review Demo[/bold]\n")

    review = CodeReview()

    # Create a sample change
    sample_code = '''
def scan_ports(target):
    """Scan ports on target"""
    import socket

    open_ports = []
    for port in range(1, 100):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports
'''

    change = review.create_change(
        file_path="test_tool.py",
        new_content=sample_code,
        description="Add port scanner function",
    )

    console.print("Created sample change for review.\n")

    # Show summary
    summary = review.get_pending_summary()
    console.print(f"Pending changes: {summary['total']}")
    console.print(f"By risk: {summary['by_risk']}")
