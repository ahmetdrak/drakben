import cProfile
import io
import pstats
import time
from unittest.mock import MagicMock

# Prevent real LLM init from checking keys/network
import core.brain

core.brain.OpenRouterClient = MagicMock()

from core.refactored_agent import RefactoredDrakbenAgent


def profile_target():
    # Mock config
    mock_config = MagicMock()
    mock_config.get.return_value = "fake_key"

    # 1. Profile Initialization
    start = time.time()
    agent = RefactoredDrakbenAgent(config_manager=mock_config)
    init_time = time.time() - start
    print(f"Agent Initialization took: {init_time:.4f}s")

    # 2. Profile Plan Creation
    start = time.time()
    agent.planner.create_plan_for_target("example.com")
    plan_time = time.time() - start
    print(f"Plan Creation took: {plan_time:.4f}s")

    # 3. Profile Internal Logic (Strategy Evolution)
    start = time.time()
    agent.tool_selector.evolve_strategies(agent.evolution)
    evolve_time = time.time() - start
    print(f"Strategy Evolution took: {evolve_time:.4f}s")


def run_profiler():
    print("Starting Profiler...")
    pr = cProfile.Profile()
    pr.enable()

    try:
        profile_target()
    except Exception as e:
        print(f"Profiling Error: {e}")

    pr.disable()

    s = io.StringIO()
    # Sort by cumulative time to see what takes the most time including subcalls
    sortby = "cumulative"
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    print("\nTOP 20 TIME CONSUMING FUNCTIONS (Cumulative):")
    ps.print_stats(20)
    print(s.getvalue())


if __name__ == "__main__":
    run_profiler()
