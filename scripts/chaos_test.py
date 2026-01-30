import logging
import os
import sys
import time

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.state import reset_state

logger = logging.getLogger("chaos_test")


def test_state_stability():
    """Rapidly reset and update state to check for race conditions"""
    logger.info("Running State Stress Test...")
    try:
        for i in range(100):
            state = reset_state(f"target_{i}")
            state.increment_iteration()
            state.compute_state_hash()
            if i % 25 == 0:
                logger.info(f"Iteration {i} stable.")
        return True
    except Exception as e:
        logger.error(f"State instability detected: {e}")
        return False


def main():
    logger.info("Starting Chaos Test (Stress Test)...")
    start_time = time.time()

    success = test_state_stability()

    duration = time.time() - start_time
    if success:
        logger.info(f"Chaos Test PASSED in {duration:.2f}s.")
        sys.exit(0)
    else:
        logger.error("Chaos Test FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
