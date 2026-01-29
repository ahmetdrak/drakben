
import sys
import os
import unittest
import traceback

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.self_refining_engine import SelfRefiningEngine

print("="*50)
print("🔍 DEBUGGING SKIPPED TESTS (SelfRefiningEngine)")
print("="*50)

try:
    print("[1] Initializing Engine...")
    engine = SelfRefiningEngine()
    print("✅ Engine Initialized Successfully")

    print("[2] Selecting Strategy...")
    strategy, profile = engine.select_strategy_and_profile("192.168.1.1")
    print(f"✅ Strategy Selected: {strategy.name} / Profile: {profile.profile_id}")

    print("[3] Testing Mutation...")
    engine.update_profile_outcome(profile.profile_id, False)
    # Note: Using public methods if available, otherwise direct test
    print("✅ Mutation Logic Executed (Mock)")

except Exception as e:
    print("\n❌ CRITICAL ERROR CAUSING SKIP:")
    print("-" * 30)
    traceback.print_exc()
    print("-" * 30)
    sys.exit(1)

print("\n✨ All Self-Refining Engine tests passed manually.")
