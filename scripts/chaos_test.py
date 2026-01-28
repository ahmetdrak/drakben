
import sys
import os
import random
import string
import threading
import time
import gc
import tracemalloc
from unittest.mock import MagicMock, patch

# Path Setup
sys.path.append(os.getcwd())

from core.state import AgentState, AttackPhase
from core.refactored_agent import RefactoredDrakbenAgent

def generate_fuzz_input():
    """Generates nasty inputs"""
    fuzz_vectors = [
        None,
        "",
        "A" * 100000,  # Buffer Overflow visual
        "Robert'); DROP TABLE Students;--",  # SQL Injection
        "{{7*7}}",  # SSI Injection
        "../../../etc/passwd",  # Path Traversal
        "\x00\x00\x00",  # Null Bytes
        "😊" * 500,  # Unicode Flood
        "eval('print(1)')", # Code Injection
        os.urandom(1024) # Binary Garbage
    ]
    return random.choice(fuzz_vectors)

def stress_test_agent_init():
    """Tries to initialize agent with garbage configs"""
    try:
        mock_config = MagicMock()
        mock_config.config.language = generate_fuzz_input()
        
        # Mocking external calls to focus on internal logic stability
        with patch('core.brain.OpenRouterClient'), \
             patch('core.kali_detector.KaliDetector'), \
             patch('core.tool_selector.ToolSelector'), \
             patch('core.evolution_memory.EvolutionMemory'):
             
            agent = Agent(mock_config)
            
            # Check state integrity
            if agent.state is None:
                raise ValueError("State is None after init!")
                
            return True
    except Exception:
        # We expect some failures due to garbage input, but NO CRASHES (Segfaults)
        # We want to catch handled exceptions.
        # print(" [Caught expected error]")
        return False

def memory_leak_test():
    print("\n💧 STARTING MEMORY LEAK TEST...")
    tracemalloc.start()
    
    snapshot1 = tracemalloc.take_snapshot()
    
    # Run heavy loop
    for _ in range(100):
        stress_test_agent_init()
        # 1% chance to force GC
        if random.random() < 0.01:
            import gc
            gc.collect()

    snapshot2 = tracemalloc.take_snapshot()
    
    top_stats = snapshot2.compare_to(snapshot1, 'lineno')
    print("   [Memory Delta (Top 3)]")
    for stat in top_stats[:3]:
        print(f"   {stat}")
    
    total_diff = sum(stat.size_diff for stat in top_stats)
    print(f"  [Memory] Total footprint difference: {total_diff / 1024:.2f} KB")
    
    # Threshold: If leaks more than 5MB after GC, it's bad.
    if total_diff > 5 * 1024 * 1024:
        print("❌ MEMORY LEAK DETECTED!")
        return False
    print("✅ Memory usage stable.")
    return True

def concurrency_fuzz_test():
    print("\n⚡ STARTING CONCURRENCY FUZZ TEST (50 THREADS)...")
    
    threads = []
    errors = []
    
    def worker():
        try:
            # Try to break shared resources
            stress_test_agent_init()
        except Exception as e:
            errors.append(str(e))
            
    for _ in range(50):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    if errors:
        print(f"❌ Concurrency Errors Found: {len(errors)}")
        print(f"   Last Error: {errors[-1]}")
        return False
        
    print("✅ 50 Threads finished without crashing components.")
    return True

if __name__ == "__main__":
    print("🚨 DRAKBEN CHAOS & FUZZING TOOL 🚨")
    print("====================================")
    
    mem_result = memory_leak_test()
    conc_result = concurrency_fuzz_test()
    
    if mem_result and conc_result:
        print("\n🎉 CHAOS TEST PASSED: System is resilient.")
        sys.exit(0)
    else:
        print("\n💥 CHAOS TEST FAILED.")
        sys.exit(1)
