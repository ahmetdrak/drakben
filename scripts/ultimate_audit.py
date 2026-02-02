import logging
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("ultimate_audit")


def run_pytest() -> bool | None:
    """Run all tests using pytest."""
    logger.info("Starting Ultimate Audit (pytest)...")
    try:
        # Run pytest with full project coverage reporting (portable approach)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--cov=.",
                "--cov-report=xml",
                "tests/",
                "-v",
                "--maxfail=5",
            ],
            capture_output=True,
            text=True,
        )

        if result.stderr:
            pass

        if result.returncode == 0:
            logger.info("Ultimate Audit PASSED.")
            return True
        logger.error("Ultimate Audit FAILED.")
        return False

    except Exception as e:
        logger.exception(f"Error running audit: {e}")
        return False


if __name__ == "__main__":
    success = run_pytest()
    sys.exit(0 if success else 1)
