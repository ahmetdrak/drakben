
import pytest
import time
from unittest.mock import MagicMock
from core.brain import ContinuousReasoning, ExecutionContext
from core.planner import Planner
from core.tool_selector import ToolSelector
from core.tool_parsers import _smart_truncate

# Benchmark Brain Initialization
def test_benchmark_brain_init(benchmark):
    def init_brain():
        return ContinuousReasoning(llm_client=MagicMock())
    benchmark(init_brain)

# Benchmark Planner Plan Creation
def test_benchmark_planner_create(benchmark):
    planner = Planner()
    def create_plan():
        return planner.create_plan_for_target("127.0.0.1", "test_benchmark")
    benchmark(create_plan)

# Benchmark Smart Truncation (Performance Critical for token saving)
def test_benchmark_smart_truncation(benchmark):
    huge_text = "start\n" + ("middle\n" * 5000) + "target_keyword\n" + ("end\n" * 5000)
    def truncate():
        return _smart_truncate(huge_text, ["target_keyword"])
    benchmark(truncate)

# Benchmark Tool Selector Strategy Evolution
def test_benchmark_tool_selector(benchmark):
    selector = ToolSelector()
    evolution_memory = MagicMock()
    evolution_memory.get_global_strategy_stats.return_value = {}
    
    def evolve():
        selector.evolve_strategies(evolution_memory)
    benchmark(evolve)
