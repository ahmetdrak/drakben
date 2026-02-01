import logging
import os
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("integrity_check")

REQUIRED_FILES = [
    "drakben.py",
    "core/state.py",
    "core/execution_engine.py",
    "core/security_utils.py",
    "core/ghost_protocol.py",
    "core/universal_adapter.py",
    "core/config.py",
]

SENSITIVE_PATTERNS = [
    "OPENROUTER_API_KEY=",
    "OPENAI_API_KEY=",
    "password =",
    "secret =",
    "token =",
]


def check_required_files():
    """Verify all core files exist"""
    logger.info("Checking required core files...")
    missing = []
    for f in REQUIRED_FILES:
        if not Path(f).exists():
            logger.error(f"Missing core file: {f}")
            missing.append(f)
    return missing


def check_sensitive_leaks():
    """Check for hardcoded API keys or secrets in the codebase"""
    logger.info("Scanning for sensitive data leaks...")
    leaks = []
    # Skip directories that are large or irrelevant
    skip_dirs = {".git", "__pycache__", "logs", "sessions", ".cache"}

    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            if file.endswith((".py", ".env", ".json", ".md")):
                path = Path(root) / file
                # Skip the template files themselves
                if "api.env" in str(path) and "config" in str(path):
                    continue

                try:
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for pattern in SENSITIVE_PATTERNS:
                            if pattern in content and "your_key_here" not in content:
                                logger.warning(
                                    f"Potential leak in {path}: Found '{pattern}'"
                                )
                                leaks.append(str(path))
                except Exception as e:
                    logger.debug(f"Could not read {path}: {e}")
    return leaks


def test_integrity():
    """Run all integrity checks"""
    missing = check_required_files()
    assert not missing, f"Missing core files: {missing}"

    leaks = check_sensitive_leaks()
    if leaks:
        logger.warning(f"Potential leaks detected in: {leaks}")


if __name__ == "__main__":
    try:
        test_integrity()
        logger.info("Integrity check PASSED.")
    except AssertionError as e:
        logger.error(f"Integrity check FAILED: {e}")
        sys.exit(1)
