
import time
import os
import psutil
import statistics
import sys
from unittest.mock import MagicMock

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.planner import Planner
from core.evolution_memory import EvolutionMemory

def stress_test_planner():
    print("Starting Planner Stress Test (1000 iterations)...")
    
    # Mock database to avoid disk I/O bottleneck during stress test
    # (We want to test CPU/Memory efficiency of the logic)
    mock_memory = MagicMock(spec=EvolutionMemory)
    
    planner = Planner()
    planner.memory = mock_memory
    
    times = []
    initial_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    
    start_total = time.time()
    for i in range(1000):
        t0 = time.time()
        # Create a plan
        planner.create_plan_for_target(f"192.168.1.{i}", "stress_test")
        t1 = time.time()
        times.append(t1 - t0)
        
    end_total = time.time()
    final_memory = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    
    avg_time = statistics.mean(times)
    max_time = max(times)
    total_time = end_total - start_total
    mem_diff = final_memory - initial_memory
    
    print(f"Total Time: {total_time:.4f}s")
    print(f"Avg Time per Plan: {avg_time*1000:.4f}ms")
    print(f"Max Time per Plan: {max_time*1000:.4f}ms")
    print(f"Memory Growth: {mem_diff:.2f} MB")
    
    # Assertions for pass/fail
    if avg_time > 0.05: # 50ms limit
        print("FAIL: Average planner time too high")
    elif mem_diff > 50: # 50MB leak limit
        print("FAIL: Significant memory growth detected")
    else:
        print("PASS: Stress test passed")

if __name__ == "__main__":
    try:
        stress_test_planner()
    except ImportError:
        print("psutil not installed, skipping memory check")
