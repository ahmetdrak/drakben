import subprocess
import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("ultimate_audit")

def run_pytest():
    """Run all tests using pytest"""
    logger.info("Starting Ultimate Audit (pytest)...")
    try:
        # Run pytest on the tests directory
        result = subprocess.run(
            ["pytest", "tests/", "-v", "--maxfail=5"],
            capture_output=True,
            text=True
        )
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
            
        if result.returncode == 0:
            logger.info("Ultimate Audit PASSED.")
            return True
        else:
            logger.error("Ultimate Audit FAILED.")
            return False
            
    except Exception as e:
        logger.error(f"Error running audit: {e}")
        return False

if __name__ == "__main__":
    success = run_pytest()
    sys.exit(0 if success else 1)
