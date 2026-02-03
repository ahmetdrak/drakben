# Prevent real LLM init from checking keys/network
import contextlib
import cProfile
import io
import pstats
import time
from unittest.mock import MagicMock

import core.brain
from core.agent.refactored_agent import RefactoredDrakbenAgent

core.brain.OpenRouterClient = MagicMock()


def profile_target() -> None:
    # Mock config
    mock_config = MagicMock()
    mock_config.get.return_value = "fake_key"

    # 1. Profile Initialization
    start = time.time()
    agent = RefactoredDrakbenAgent(config_manager=mock_config)
    init_time = time.time() - start
    _ = init_time  # Track initialization time

    # 2. Profile Plan Creation
    start = time.time()
    agent.planner.create_plan_for_target("example.com")
    plan_time = time.time() - start
    _ = plan_time  # Track plan creation time

    # 3. Profile Internal Logic (Strategy Evolution)
    start = time.time()
    agent.tool_selector.evolve_strategies(agent.evolution)
    evolve_time = time.time() - start
    _ = evolve_time  # Track evolution time


def run_profiler() -> None:
    pr = cProfile.Profile()
    pr.enable()

    with contextlib.suppress(Exception):
        profile_target()

    pr.disable()

    s = io.StringIO()
    # Sort by cumulative time to see what takes the most time including subcalls
    sortby = "cumulative"
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.print_stats(20)


if __name__ == "__main__":
    run_profiler()
