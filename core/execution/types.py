# core/execution/types.py
"""Shared types for the execution module — prevents circular imports."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExecutionStatus(Enum):
    """Status of command execution."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """Result of command execution."""

    command: str
    status: ExecutionStatus
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    timestamp: float
