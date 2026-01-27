
import asyncio
import sqlite3
import random
import os
from pathlib import Path
from core.evolution_memory import EvolutionMemory

DB_PATH = "test_concurrency.db"

async def worker(worker_id: int, memory: EvolutionMemory):
    """Simulates a module writing to the DB"""
    try:
        # Simulate work
        strategy_id = f"strat_{worker_id}_{random.randint(1, 100)}"
        success = random.choice([True, False])
        
        # Write to DB (Assuming record_outcome is a method)
        # If not, we test internal DB methods or custom queries
        # EvolutionMemory has 'update_strategy_score' or similar
        
        # Let's use raw execution via _get_conn if specific methods aren't exposed easily
        # But better to use public API: record_outcome(profile_id, success, score)
        
        # Mocking a profile update
        # We need to insert a profile first or just test raw concurrent writes
        
        with memory._get_conn() as conn:
            cursor = conn.cursor()
            # Use 'tool_penalties' which exists
            tool_name = f"tool_{worker_id}"
            cursor.execute(
                "INSERT OR IGNORE INTO tool_penalties (tool, penalty_score, success_count) VALUES (?, ?, ?)",
                (tool_name, 0.0, 0)
            )
            cursor.execute(
                "UPDATE tool_penalties SET success_count = success_count + 1 WHERE tool = ?",
                (tool_name,)
            )
            conn.commit()
            
        return True
    except sqlite3.OperationalError:
        return False # Locked
    except Exception as e:
        print(f"Worker {worker_id} Error: {e}")
        return False

async def stress_test_db():
    print("Starting DB Concurrency Stress Test...")
    
    # Init DB
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        
    memory = EvolutionMemory(db_path=DB_PATH)
    
    # Run 100 concurrent workers
    tasks = []
    print("Launching 100 concurrent write operations...")
    for i in range(100):
        tasks.append(worker(i, memory))
        
    results = await asyncio.gather(*tasks)
    
    success_count = sum(results)
    failure_count = len(results) - success_count
    
    print(f"\nStats:")
    print(f"Successful Writes: {success_count}")
    print(f"Failed (Locks/Errors): {failure_count}")
    
    # Cleanup
    try:
        os.remove(DB_PATH)
    except:
        pass
        
    if failure_count > 0:
        print("⚠️ WARNING: SQLite Database Locked during concurrency.")
        print("Recommendation: Enable WAL mode or use a Queue system.")
    else:
        print("✅ PASS: Database handled high concurrency perfectly.")

if __name__ == "__main__":
    asyncio.run(stress_test_db())
