import os
import sys
import logging
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
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
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


def run_integrity_check():
    """Run all integrity checks"""
    errors = 0

    missing = check_required_files()
    if missing:
        errors += len(missing)

    leaks = check_sensitive_leaks()
    if leaks:
        # We don't fail CI on potential leaks but we log them
        # logger.warning("Potential leaks detected. Review logs.")
        pass

    if errors > 0:
        logger.error(f"Integrity check FAILED with {errors} errors.")
        sys.exit(1)
    else:
        logger.info("Integrity check PASSED.")
        sys.exit(0)


if __name__ == "__main__":
    run_integrity_check()
