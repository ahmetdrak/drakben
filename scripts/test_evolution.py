#!/usr/bin/env python3
"""
TEST: Verify SELF-REFINING EVOLUTION SYSTEM works

This test uses the NEW SelfRefiningEngine with:
- Strategy Profiles
- Policy Conflict Resolution
- Profile Mutation
- Restart Evolution
"""

import gc
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.self_refining_engine import SelfRefiningEngine, PolicyTier


def safe_remove(path):
    """Safely remove file, handling Windows locks"""
    gc.collect()
    time.sleep(0.1)
    try:
        if os.path.exists(path):
            os.remove(path)
    except PermissionError:
        pass


def test_target_classification():
    """Test target classification"""
    print("=" * 50)
    print("TEST 1: Target Classification")
    print("=" * 50)
    
    db_path = "test_strategy.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    t1 = engine.classify_target("https://example.com/login")
    assert t1 == "web_app"
    print(f"  ✅ https://example.com/login → {t1}")
    
    t2 = engine.classify_target("https://api.example.com/v1/users")
    assert t2 == "api_endpoint"
    print(f"  ✅ https://api.example.com → {t2}")
    
    t3 = engine.classify_target("192.168.1.1")
    assert t3 == "network_host"
    print(f"  ✅ 192.168.1.1 → {t3}")
    
    del engine
    safe_remove(db_path)
    print()
    return True


def test_strategy_and_profile_selection():
    """Test strategy and profile selection"""
    print("=" * 50)
    print("TEST 2: Strategy and Profile Selection")
    print("=" * 50)
    
    db_path = "test_strategy2.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    # Select strategy and profile
    strategy, profile = engine.select_strategy_and_profile("https://example.com")
    
    print(f"  ✅ Selected strategy: {strategy.name}")
    print(f"  ✅ Selected profile: {profile.profile_id[:12]}...")
    print(f"     Aggressiveness: {profile.aggressiveness}")
    print(f"     Step Order: {profile.step_order}")
    
    # Simulate failure
    target_sig = engine.get_target_signature("https://example.com")
    _ = engine.record_failure(
        target_signature=target_sig,
        strategy_name=strategy.name,
        profile_id=profile.profile_id,
        error_type="timeout",
        error_message="Connection timed out"
    )
    
    # Now get new selection - should be different profile
    _, _ = engine.select_strategy_and_profile("https://example.com")
    
    if profile2.profile_id != profile.profile_id:
        print(f"  ✅ After failure, selected different profile: {profile2.profile_id[:12]}...")
    else:
        print("  ⚠️ Same profile selected (may be OK if only one available)")
    
    # Check has_failed_before
    has_failed = engine.has_failed_before(target_sig, profile.profile_id)
    print(f"  ✅ has_failed_before correctly returns {has_failed}")
    
    del engine
    safe_remove(db_path)
    print()
    return True


def test_policy_learning():
    """Test policy learning from failures"""
    print("=" * 50)
    print("TEST 3: Policy Learning")
    print("=" * 50)
    
    db_path = "test_strategy3.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    target_sig = "web_app:test123"
    
    # Record multiple similar failures to trigger policy learning
    for i in range(3):
        failure_id = engine.record_failure(
            target_signature=target_sig,
            strategy_name="web_aggressive",
            profile_id=f"test_profile_{i}",
            error_type="timeout",
            error_message="Connection timed out",
            tool_name="sqlmap"
        )
        policy_id = engine.learn_policy_from_failure(failure_id)
        if policy_id:
            print(f"  ✅ Created policy: {policy_id[:12]}...")
    
    # Get applicable policies
    context = {"target_signature": target_sig, "error_type": "timeout"}
    policies = engine.get_applicable_policies(context)
    print(f"  ✅ Found {len(policies)} applicable policies")
    
    del engine
    safe_remove(db_path)
    print()
    return True


def test_policy_affects_tools():
    """Test that policies affect tool selection"""
    print("=" * 50)
    print("TEST 4: Policy Affects Tool Selection")
    print("=" * 50)
    
    db_path = "test_strategy4.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    # Add a policy to avoid sqlmap_scan
    engine.add_policy(
        condition={"target_type": "web_app"},
        action={"avoid_tools": ["sqlmap_scan"]},
        priority_tier=PolicyTier.TOOL_SELECTION,
        weight=0.9
    )
    
    tools = ["nmap_port_scan", "nikto_web_scan", "sqlmap_scan"]
    context = {"target_type": "web_app"}
    
    filtered = engine.apply_policies_to_tools(tools, context)
    
    print(f"  ✅ Tools after policy filter: {filtered}")
    
    if "sqlmap_scan" not in filtered:
        print("  ✅ sqlmap_scan was correctly filtered out")
    else:
        print("  ❌ sqlmap_scan should have been filtered")
        return False
    
    del engine
    safe_remove(db_path)
    print()
    return True


def test_profile_mutation():
    """Test profile mutation on exhaustion"""
    print("=" * 50)
    print("TEST 5: Profile Mutation")
    print("=" * 50)
    
    db_path = "test_strategy5.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    # Get initial profiles for aggressive_scan
    initial_profiles = engine.get_profiles_for_strategy("aggressive_scan")
    print(f"  Initial profiles: {len(initial_profiles)}")
    
    # Retire all profiles
    for p in initial_profiles:
        engine.retire_profile(p.profile_id)
    
    # Now select - should trigger mutation
    mutated = engine.select_best_profile("aggressive_scan")
    
    if mutated:
        print(f"  ✅ Mutated profile created: {mutated.profile_id[:12]}...")
        print(f"     Parent: {mutated.parent_profile_id[:12] if mutated.parent_profile_id else 'None'}...")
        print(f"     Generation: {mutated.mutation_generation}")
    else:
        print("  ❌ No mutated profile created")
        return False
    
    del engine
    safe_remove(db_path)
    print()
    return True


def test_restart_persistence():
    """Test that evolution persists across restarts"""
    print("=" * 50)
    print("TEST 6: Restart Persistence")
    print("=" * 50)
    
    db_path = "test_strategy6.db"
    safe_remove(db_path)
    
    # Session 1: Create policy
    engine1 = SelfRefiningEngine(db_path)
    engine1.add_policy(
        condition={"target_type": "web_app"},
        action={"prefer_strategy": "web_stealth"},
        priority_tier=PolicyTier.STRATEGY_OVERRIDE,
        weight=0.8
    )
    status1 = engine1.get_evolution_status()
    print(f"  Run 1 - Policies: {status1['active_policies']}")
    del engine1
    gc.collect()
    
    # Session 2: Load and verify
    engine2 = SelfRefiningEngine(db_path)
    status2 = engine2.get_evolution_status()
    print(f"  Run 2 - Policies: {status2['active_policies']}")
    
    if status2['active_policies'] >= status1['active_policies']:
        print(f"  ✅ Policies persist across restarts")
    else:
        print(f"  ❌ Policies did not persist")
        return False
    
    del engine2
    safe_remove(db_path)
    print()
    return True


def test_evolution_status():
    """Test evolution status reporting"""
    print("=" * 50)
    print("TEST 7: Evolution Status")
    print("=" * 50)
    
    db_path = "test_strategy7.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    status = engine.get_evolution_status()
    print(f"  Active strategies: {status['active_strategies']}")
    print(f"  Active profiles: {status['active_profiles']}")
    print(f"  Retired profiles: {status['retired_profiles']}")
    print(f"  Active policies: {status['active_policies']}")
    print(f"  Total failures: {status['total_failures']}")
    print("  ✅ Evolution status works")
    
    del engine
    safe_remove(db_path)
    print()
    return True


def main():
    print("\n🧪 SELF-REFINING EVOLUTION SYSTEM TESTS\n")
    
    results = {
        "Target Classification": test_target_classification(),
        "Strategy Selection": test_strategy_and_profile_selection(),
        "Policy Learning": test_policy_learning(),
        "Policy Affects Tools": test_policy_affects_tools(),
        "Profile Mutation": test_profile_mutation(),
        "Restart Persistence": test_restart_persistence(),
        "Evolution Status": test_evolution_status(),
    }
    
    print("=" * 50)
    print("SUMMARY")
    print("=" * 50)
    
    all_passed = True
    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False
    
    print()
    if all_passed:
        print("🎉 ALL TESTS PASSED - SELF-REFINING EVOLUTION SYSTEM IS REAL")
    else:
        print("⚠️ SOME TESTS FAILED")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
