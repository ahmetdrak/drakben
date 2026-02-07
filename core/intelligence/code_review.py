# core/code_review.py
# DRAKBEN Code Review Module
# Provides code review and approval workflow before execution
# Similar to Open Interpreter's code review feature

from __future__ import annotations

import ast
import difflib
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from collections.abc import Callable

# Setup logger
logger = logging.getLogger(__name__)


class ReviewStatus(Enum):
    """Status of a code review."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"
    AUTO_APPROVED = "auto_approved"


class RiskLevel(Enum):
    """Risk level of code changes."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CodeChange:
    """Represents a single code change."""

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
    """A review session containing multiple changes."""

    session_id: str
    changes: list[CodeChange]
    created_at: float
    status: ReviewStatus = ReviewStatus.PENDING
    auto_approve_low_risk: bool = False
    requires_all_approved: bool = True


class CodeAnalyzer:
    """Analyzes code for security risks and quality issues.
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
        """Analyze code and return risk level with concerns.

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
        if risk_score >= 10:
            return RiskLevel.HIGH, concerns
        if risk_score >= 5:
            return RiskLevel.MEDIUM, concerns
        return RiskLevel.LOW, concerns

    @classmethod
    def _check_node_safety(cls, node: ast.AST, issues: list[str]) -> None:
        """Helper to check individual AST nodes for safety."""
        # Check for dangerous function calls
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec", "compile"):
                issues.append(f"Dangerous function call: {node.func.id}")

        # Check for dangerous imports
        if isinstance(node, ast.Import):
            issues.extend(
                f"Dangerous import: {alias.name}"
                for alias in node.names
                if alias.name in ("ctypes", "pickle", "marshal")
            )

        # Check for dangerous "from" imports
        if isinstance(node, ast.ImportFrom):
            if node.module in ("ctypes", "pickle", "marshal"):
                issues.append(f"Dangerous import from: {node.module}")


class CodeReview:
    """Main code review system.

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
    ) -> None:
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

    def _generate_id(self) -> str:
        """Generate unique ID."""
        return hashlib.sha256(
            f"{time.time()}{os.urandom(8).hex()}".encode(),
        ).hexdigest()[:12]

    def create_change(
        self,
        file_path: str,
        new_content: str,
        description: str = "",
        change_type: str = "modify",
    ) -> CodeChange:
        """Create a new code change for review.

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
                logger.debug("Failed to read file for diff: %s", e)

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
            ),
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
        logger.info("Created code change: %s (%s)", change.change_id, risk_level.value)

        return change

    def _find_original_path(self, change_id: str, fallback_name: str) -> Path:
        """Find the original file path for a change from session history.

        Args:
            change_id: The change ID to look up
            fallback_name: Fallback filename if not found in history

        Returns:
            Path to the original file

        """
        # Search pending changes
        for change in self.pending_changes:
            if change.change_id == change_id:
                return Path(change.file_path)

        # Search sessions
        for session in self.sessions:
            for change in session.changes:
                if change.change_id == change_id:
                    return Path(change.file_path)

        # Fallback: use CWD + filename (legacy behaviour)
        logger.warning(
            "Could not find original path for change %s, using fallback",
            change_id,
        )
        return Path.cwd() / fallback_name

    def rollback_change(self, change_id: str) -> bool:
        """Rollback a previously applied change.

        Args:
            change_id: ID of the change to rollback

        Returns:
            True if successful

        """
        # Sanitize change_id to prevent path traversal
        safe_change_id = change_id.replace("..", "").replace("/", "_").replace("\\", "_")

        # Find backup file
        for backup_file in self.backup_dir.glob(f"{safe_change_id}_*.bak"):
            try:
                # Extract original filename
                original_name = backup_file.name.replace(f"{safe_change_id}_", "").replace(
                    ".bak",
                    "",
                )

                # Validate the file is within backup_dir (path traversal protection)
                if not backup_file.resolve().is_relative_to(self.backup_dir.resolve()):
                    logger.error("Security: Backup file outside allowed directory")
                    return False

                # Read backup content
                with open(backup_file, encoding="utf-8") as f:
                    backup_content = f.read()

                # Find matching change to get original file path
                original_path = self._find_original_path(change_id, original_name)

                # Write backup content to restore the file
                with open(original_path, "w", encoding="utf-8") as f:
                    f.write(backup_content)

                self.console.print(
                    f"[green]Rollback successful for: {original_name}[/green]",
                )
                self.console.print(f"Restored from backup: {backup_file}")

                return True

            except Exception as e:
                logger.exception("Rollback failed: %s", e)
                return False

        logger.warning("No backup found for change: %s", change_id)
        return False

    def get_pending_summary(self) -> dict:
        """Get summary of pending changes."""
        by_risk: dict[RiskLevel, list[CodeChange]] = {level: [] for level in RiskLevel}

        for change in self.pending_changes:
            if change.status == ReviewStatus.PENDING:
                by_risk[change.risk_level].append(change)

        return {
            "total": sum(len(v) for v in by_risk.values()),
            "by_risk": {k.value: len(v) for k, v in by_risk.items()},
            "changes": self.pending_changes,
        }


class CodeReviewMiddleware:
    """Middleware that intercepts code execution and applies review.
    Can be used to wrap the AICoder or ExecutionEngine.
    """

    def __init__(self, review_system: CodeReview) -> None:
        self.review = review_system


if __name__ == "__main__":
    # Demo mode
    console = Console()
    console.print("[bold]DRAKBEN Code Review Demo[/bold]\n")

    review = CodeReview()

    # Create a sample change
    sample_code = '''
def scan_ports(target) -> Any:
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
