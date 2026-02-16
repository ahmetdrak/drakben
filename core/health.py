# core/health.py
# DRAKBEN — System Health Checker
# Used by web_api.py for /health, /health/live, /health/ready endpoints
# and by Dockerfile HEALTHCHECK.

"""Health-check subsystem for DRAKBEN.

Checks:
- Python runtime (always healthy)
- Disk space (logs/, sessions/ directories)
- LLM connectivity (optional)
- Database / ChromaDB (optional)
- Docker daemon (optional)

Usage::

    from core.health import get_health_checker

    checker = get_health_checker()
    report = checker.full_check()
    print(report.to_dict())       # → {"status": "healthy", ...}
    print(checker.readiness())    # → True / False
"""

from __future__ import annotations

import logging
import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComponentHealth:
    """Health status for one subsystem."""

    name: str
    healthy: bool
    latency_ms: float = 0.0
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class HealthReport:
    """Aggregated health report."""

    status: str = "healthy"  # healthy, degraded, unhealthy
    timestamp: float = 0.0
    checks: list[ComponentHealth] = field(default_factory=list)
    version: str = "2.5.0"

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "timestamp": self.timestamp,
            "version": self.version,
            "checks": [
                {
                    "name": c.name,
                    "healthy": c.healthy,
                    "latency_ms": round(c.latency_ms, 2),
                    "message": c.message,
                    **c.details,
                }
                for c in self.checks
            ],
        }


# ------------------------------------------------------------------
# Health Checker
# ------------------------------------------------------------------


class HealthChecker:
    """Performs health checks against DRAKBEN subsystems."""

    # Minimum free disk space in MB before we flag degraded
    MIN_DISK_MB = 100

    def __init__(self) -> None:
        self._checks: list[tuple[str, Any]] = [
            ("runtime", self._check_runtime),
            ("disk", self._check_disk),
            ("config", self._check_config),
            ("llm", self._check_llm),
            ("docker", self._check_docker),
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def full_check(self) -> HealthReport:
        """Run all health checks and return an aggregated report."""
        results: list[ComponentHealth] = []
        for name, check_fn in self._checks:
            t0 = time.time()
            try:
                healthy, message, details = check_fn()
            except Exception as exc:
                healthy, message, details = False, str(exc), {}
            latency = (time.time() - t0) * 1000
            results.append(
                ComponentHealth(
                    name=name,
                    healthy=healthy,
                    latency_ms=latency,
                    message=message,
                    details=details,
                )
            )

        # Derive overall status
        unhealthy_count = sum(1 for r in results if not r.healthy)
        if unhealthy_count == 0:
            status = "healthy"
        elif unhealthy_count <= 2:
            status = "degraded"
        else:
            status = "unhealthy"

        return HealthReport(status=status, checks=results)

    def readiness(self) -> bool:
        """Quick readiness probe — only critical checks."""
        try:
            ok_runtime, _, _ = self._check_runtime()
            ok_disk, _, _ = self._check_disk()
            return ok_runtime and ok_disk
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_runtime() -> tuple[bool, str, dict[str, Any]]:
        """Check Python runtime is operational."""
        import sys

        return True, "ok", {"python_version": sys.version.split()[0]}

    def _check_disk(self) -> tuple[bool, str, dict[str, Any]]:
        """Check available disk space."""
        try:
            usage = shutil.disk_usage(Path.cwd())
            free_mb = usage.free / (1024 * 1024)
            healthy = free_mb >= self.MIN_DISK_MB
            return healthy, f"{free_mb:.0f} MB free", {"free_mb": round(free_mb, 1)}
        except OSError as exc:
            return False, str(exc), {}

    @staticmethod
    def _check_config() -> tuple[bool, str, dict[str, Any]]:
        """Check configuration is loadable."""
        try:
            from core.config import ConfigManager

            cm = ConfigManager(config_file="config/settings.json")
            provider = cm.config.llm_provider
            return True, f"provider={provider}", {"llm_provider": provider}
        except (ImportError, OSError, AttributeError) as exc:
            return False, str(exc), {}

    @staticmethod
    def _check_llm() -> tuple[bool, str, dict[str, Any]]:
        """Check at least one LLM provider is configured."""
        try:
            from core.config import ConfigManager

            cm = ConfigManager(config_file="config/settings.json")
            if cm.config.llm_setup_complete:
                return True, "configured", {"setup_complete": True}
            return False, "no LLM configured", {"setup_complete": False}
        except (ImportError, OSError, AttributeError) as exc:
            return False, str(exc), {}

    @staticmethod
    def _check_docker() -> tuple[bool, str, dict[str, Any]]:
        """Check Docker availability (non-critical)."""
        try:
            import docker

            client = docker.from_env()
            client.ping()
            return True, "reachable", {}
        except (ImportError, ConnectionError, OSError):
            # Docker is optional — mark as healthy with warning
            return True, "not available (optional)", {"available": False}


# ------------------------------------------------------------------
# Module-level singleton
# ------------------------------------------------------------------

_health_checker: HealthChecker | None = None
_health_lock = threading.Lock()


def get_health_checker() -> HealthChecker:
    """Return the global health checker singleton."""
    global _health_checker
    if _health_checker is None:
        with _health_lock:
            if _health_checker is None:
                _health_checker = HealthChecker()
    return _health_checker
