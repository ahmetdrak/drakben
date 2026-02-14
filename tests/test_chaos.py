import logging
import os
import sys
import time

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent.state import reset_state

logger = logging.getLogger("chaos_test")


def test_state_stability() -> None:
    """Rapidly reset and update state to check for race conditions."""
    logger.info("Running State Stress Test...")
    for i in range(100):
        state = reset_state(f"target_{i}")
        state.increment_iteration()
        state.compute_state_hash()
        if i % 25 == 0:
            logger.info("Iteration %s stable.", i)


if __name__ == "__main__":
    # Allow manual execution
    import time

    start_time = time.time()
    try:
        test_state_stability()
        logger.info("Chaos Test PASSED in %.2fs.", time.time() - start_time)
        sys.exit(0)
    except Exception as e:
        logger.exception("Chaos Test FAILED: %s", e)
        sys.exit(1)
