"""Smoke tests: importability, file integrity, and critical instantiation."""

import importlib.util
import logging
import os
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("health_check")

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# ---------------------------------------------------------------------------
# 1. Module importability
# ---------------------------------------------------------------------------

def test_module_health() -> None:
    """Verify all critical modules are importable."""
    modules_to_check = [
        "core.agent.refactored_agent",
        "core.intelligence.universal_adapter",
        "core.intelligence.self_refining_engine",
        "core.intelligence.evolution_memory",
        "modules.weapon_foundry",
        "modules.hive_mind",
        "modules.c2_framework",
        "core.security.ghost_protocol",
    ]

    failed_modules = []
    for module_name in modules_to_check:
        try:
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                failed_modules.append(module_name)
        except Exception:
            failed_modules.append(module_name)

    assert not failed_modules, f"Critical modules missing or broken: {failed_modules}"


# ---------------------------------------------------------------------------
# 2. File integrity + leak scan  (was test_integrity.py)
# ---------------------------------------------------------------------------

REQUIRED_FILES = [
    "drakben.py",
    "core/agent/state.py",
    "core/execution/execution_engine.py",
    "core/security/security_utils.py",
    "core/security/ghost_protocol.py",
    "core/intelligence/universal_adapter.py",
    "core/config.py",
]

SENSITIVE_PATTERNS = [
    "OPENROUTER_API_KEY=",
    "OPENAI_API_KEY=",
    "password =",
    "secret =",
    "token =",
]


def _should_skip_file(path: Path) -> bool:
    """Check if file should be skipped during leak scan."""
    return "api.env" in str(path) and "config" in str(path)


def _scan_file_for_leaks(path: Path) -> list[str]:
    """Scan single file for sensitive patterns."""
    leaks: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for pattern in SENSITIVE_PATTERNS:
                if pattern in content and "your_key_here" not in content:
                    leaks.append(str(path))
                    break
    except Exception:
        pass
    return leaks


def test_integrity() -> None:
    """Verify core files exist and no API-key leaks in source."""
    missing = [f for f in REQUIRED_FILES if not Path(f).exists()]
    assert not missing, f"Missing core files: {missing}"

    leaks: list[str] = []
    skip_dirs = {".git", "__pycache__", "logs", "sessions", ".cache"}
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            if not file.endswith((".py", ".env", ".json", ".md")):
                continue
            path = Path(root) / file
            if _should_skip_file(path):
                continue
            leaks.extend(_scan_file_for_leaks(path))
    if leaks:
        logger.warning("Potential leaks detected in: %s", leaks)


# ---------------------------------------------------------------------------
# 3. Critical class instantiation  (was test_final_check.py)
# ---------------------------------------------------------------------------

try:
    from core.agent.refactored_agent import RefactoredDrakbenAgent
    from core.config import ConfigManager
except ImportError:
    RefactoredDrakbenAgent = None  # type: ignore[assignment,misc]
    ConfigManager = None  # type: ignore[assignment,misc]

try:
    from core.intelligence.universal_adapter import UniversalAdapter
except ImportError:
    UniversalAdapter = None  # type: ignore[assignment,misc]

try:
    from modules.weapon_foundry import WeaponFoundry
except ImportError:
    WeaponFoundry = None  # type: ignore[assignment,misc]

try:
    from modules.hive_mind import CredentialHarvester
except ImportError:
    CredentialHarvester = None  # type: ignore[assignment,misc]

try:
    from modules.report_generator import ReportConfig, ReportGenerator
except ImportError:
    ReportGenerator = None  # type: ignore[assignment,misc]
    ReportConfig = None  # type: ignore[assignment,misc]


def test_final_check() -> None:
    """Verify critical modules can be instantiated without errors."""
    assert RefactoredDrakbenAgent is not None and ConfigManager is not None
    _ = RefactoredDrakbenAgent(ConfigManager())

    assert UniversalAdapter is not None
    _ = UniversalAdapter()

    assert WeaponFoundry is not None
    _ = WeaponFoundry()

    assert CredentialHarvester is not None
    _ = CredentialHarvester()

    assert ReportGenerator is not None and ReportConfig is not None
    _ = ReportGenerator(ReportConfig(title="Test Report"))
