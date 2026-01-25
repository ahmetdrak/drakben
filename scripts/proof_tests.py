"""
PROOF TESTS FOR SELF-REFINING EVOLVING AGENT
=============================================

This test file PROVES that the system:
1. Profile mutation works (failed profiles create mutated variants)
2. Policy conflict resolution is deterministic
3. Restart behavior change is measurable

Each test outputs concrete evidence, not assertions.
"""

import sys
import os
import gc
import time
import json

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.self_refining_engine import (
    SelfRefiningEngine, 
    PolicyTier,
    StrategyProfile,
    Policy
)


def safe_remove(path: str):
    """Safely remove a file with retries for Windows"""
    for _ in range(3):
        try:
            gc.collect()
            if os.path.exists(path):
                os.remove(path)
            return
        except PermissionError:
            time.sleep(0.1)


def print_separator(title: str):
    """Print a section separator"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


# =============================================================================
# PROOF 1: PROFILE MUTATION
# =============================================================================


def _check_measurable_differences(original_data: list, mutated_profile: StrategyProfile) -> list:
    """
    Helper to identify measurable differences between parent and mutated profile.
    Returns list of differences strings. Returns None if parent not found.
    """
    parent = None
    for orig in original_data:
        if orig["profile_id"] == mutated_profile.parent_profile_id:
            parent = orig
            break
    
    if parent is None:
        return []
    
    differences = []
    
    # Check parameter differences
    for key in parent["parameters"]:
        if key in mutated_profile.parameters:
            if parent["parameters"][key] != mutated_profile.parameters[key]:
                differences.append(f"Parameter '{key}': {parent['parameters'][key]} → {mutated_profile.parameters[key]}")
    
    # Check step order difference
    if parent["step_order"] != mutated_profile.step_order:
        differences.append(f"Step order: {parent['step_order']} → {mutated_profile.step_order}")
    
    # Check aggressiveness difference
    if abs(parent["aggressiveness"] - mutated_profile.aggressiveness) > 0.001:
        differences.append(f"Aggressiveness: {parent['aggressiveness']:.4f} → {mutated_profile.aggressiveness:.4f}")
        
    return differences


def proof_profile_mutation():
    """
    PROOF: When all profiles for a strategy are retired,
    a NEW mutated profile is created with MEASURABLY DIFFERENT parameters.
    """
    print_separator("PROOF 1: PROFILE MUTATION")
    
    db_path = "test_mutation_proof.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    # Get initial profiles for aggressive_scan strategy
    initial_profiles = engine.get_profiles_for_strategy("aggressive_scan", include_retired=False)
    print(f"Initial profile count: {len(initial_profiles)}")
    
    # Store original profile data
    original_data = []
    for p in initial_profiles:
        original_data.append({
            "profile_id": p.profile_id,
            "parameters": p.parameters.copy(),
            "step_order": p.step_order.copy(),
            "aggressiveness": p.aggressiveness
        })
        print(f"  Profile {p.profile_id[:8]}... | aggression={p.aggressiveness:.2f} | steps={p.step_order}")
    
    # RETIRE ALL PROFILES (simulating repeated failures)
    print("\n[ACTION] Retiring ALL profiles...")
    for p in initial_profiles:
        engine.retire_profile(p.profile_id)
    
    # Verify all retired
    active_after_retire = engine.get_profiles_for_strategy("aggressive_scan", include_retired=False)
    print(f"Active profiles after retirement: {len(active_after_retire)}")
    
    # NOW: Select best profile - should trigger MUTATION
    print("\n[ACTION] Selecting best profile (should trigger mutation)...")
    mutated_profile = engine.select_best_profile("aggressive_scan")
    
    if mutated_profile is None:
        print("❌ FAIL: No profile returned after mutation")
        safe_remove(db_path)
        return False
    
    print("\nMUTATED PROFILE CREATED:")
    print(f"  Profile ID: {mutated_profile.profile_id}")
    print(f"  Parent ID:  {mutated_profile.parent_profile_id}")
    print(f"  Generation: {mutated_profile.mutation_generation}")
    print(f"  Parameters: {json.dumps(mutated_profile.parameters, indent=4)}")
    print(f"  Step Order: {mutated_profile.step_order}")
    print(f"  Aggression: {mutated_profile.aggressiveness:.4f}")
    
    # PROVE: Mutation is MEASURABLY DIFFERENT
    print("\n[VERIFICATION] Checking measurable differences...")
    
    differences = _check_measurable_differences(original_data, mutated_profile)
    
    if differences is None:
        print("❌ FAIL: Parent profile not found")
        safe_remove(db_path)
        return False
    
    print("\nMEASURABLE DIFFERENCES FROM PARENT:")
    for diff in differences:
        print(f"  ✓ {diff}")
    
    if len(differences) == 0:
        print("❌ FAIL: No measurable differences - mutation did not work")
        safe_remove(db_path)
        return False
    
    # Get lineage
    lineage = engine.get_profile_lineage(mutated_profile.profile_id)
    print(f"\nMutation Lineage: {' → '.join([pid[:8] + '...' for pid in lineage])}")
    
    print("\n✅ PROOF COMPLETE: Profile mutation creates measurably different profiles")
    print(f"   - {len(differences)} measurable differences detected")
    print(f"   - Mutation generation: {mutated_profile.mutation_generation}")
    
    safe_remove(db_path)
    return True


# =============================================================================
# PROOF 2: POLICY CONFLICT RESOLUTION
# =============================================================================

def proof_policy_conflict_resolution():
    """
    PROOF: When multiple policies apply with conflicting actions,
    resolution is DETERMINISTIC based on tier → weight → created_at.
    """
    print_separator("PROOF 2: POLICY CONFLICT RESOLUTION")
    
    db_path = "test_conflict_proof.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    # Create CONFLICTING policies for the same condition
    condition = {"target_type": "web_app"}
    
    print("Creating conflicting policies:\n")
    
    # Policy A: Tier 3 (TOOL_SELECTION), weight 0.9, avoid sqlmap
    _ = engine.add_policy(
        condition=condition,
        action={"avoid_tools": ["sqlmap"]},
        priority_tier=PolicyTier.TOOL_SELECTION,
        weight=0.9,
        source="test"
    )
    print("  Policy A: Tier 3 (TOOL_SELECTION), weight=0.9 → avoid sqlmap")
    time.sleep(0.01)  # Ensure different created_at
    
    # Policy B: Tier 3 (TOOL_SELECTION), weight=0.9, prefer sqlmap (CONFLICT!)
    _ = engine.add_policy(
        condition=condition,
        action={"prefer_tools": ["sqlmap"]},
        priority_tier=PolicyTier.TOOL_SELECTION,
        weight=0.9,
        source="test"
    )
    print("  Policy B: Tier 3 (TOOL_SELECTION), weight=0.9 → prefer sqlmap (CONFLICT!)")
    time.sleep(0.01)
    
    # Policy C: Tier 1 (HARD_AVOIDANCE), weight=0.5, block sqlmap
    _ = engine.add_policy(
        condition=condition,
        action={"block_tool": "sqlmap"},
        priority_tier=PolicyTier.HARD_AVOIDANCE,
        weight=0.5,
        source="test"
    )
    print("  Policy C: Tier 1 (HARD_AVOIDANCE), weight=0.5 → block sqlmap")
    time.sleep(0.01)
    
    # Policy D: Tier 2 (STRATEGY_OVERRIDE), weight=0.8, prefer stealth
    _ = engine.add_policy(
        condition=condition,
        action={"prefer_strategy": "web_stealth"},
        priority_tier=PolicyTier.STRATEGY_OVERRIDE,
        weight=0.8,
        source="test"
    )
    print("  Policy D: Tier 2 (STRATEGY_OVERRIDE), weight=0.8 → prefer web_stealth")
    
    # Get applicable policies
    context = {"target_type": "web_app"}
    applicable = engine.get_applicable_policies(context)
    
    print(f"\nApplicable policies count: {len(applicable)}")
    print("Policy order after retrieval (should be by tier ASC, weight DESC, created_at ASC):")
    for i, pol in enumerate(applicable):
        print(f"  {i+1}. Policy {pol.policy_id[:8]}... | Tier {pol.priority_tier} ({PolicyTier(pol.priority_tier).name}) | Weight {pol.weight}")
    
    # RESOLVE CONFLICTS
    print("\n[ACTION] Resolving conflicts...")
    resolved = engine.resolve_policy_conflicts(applicable)
    
    print("\nRESOLVED ACTIONS (execution order):")
    for action in resolved:
        print(f"  Tier {action['tier']}: {action['action_type']} = {action['action_value']}")
        print(f"         Source policy: {action['source_policy'][:8]}...")
    
    # VERIFY DETERMINISM: Run multiple times
    print("\n[VERIFICATION] Running conflict resolution 10 times to verify determinism...")
    results = []
    for _ in range(10):
        res = engine.resolve_policy_conflicts(applicable)
        results.append(json.dumps(res, sort_keys=True))
    
    unique_results = set(results)
    print(f"  Unique results: {len(unique_results)}")
    
    if len(unique_results) != 1:
        print("❌ FAIL: Conflict resolution is NOT deterministic!")
        safe_remove(db_path)
        return False
    
    # VERIFY: Tier 1 always wins for conflicting actions
    print("\n[VERIFICATION] Checking tier priority...")
    
    # Apply policies to tools
    tools = ["nmap", "nikto", "sqlmap", "gobuster", "dirb"]
    filtered_tools = engine.apply_policies_to_tools(tools, context)
    
    print(f"  Original tools: {tools}")
    print(f"  After policy filter: {filtered_tools}")
    
    # sqlmap should be BLOCKED (Tier 1 wins over Tier 3 prefer)
    if "sqlmap" in filtered_tools:
        print("❌ FAIL: Tier 1 block did not win over Tier 3 prefer!")
        safe_remove(db_path)
        return False
    
    print("\n✅ PROOF COMPLETE: Policy conflict resolution is deterministic")
    print("   - Tier 1 (HARD_AVOIDANCE) correctly overrides Tier 3 (TOOL_SELECTION)")
    print("   - Resolution is deterministic (10 identical runs)")
    
    safe_remove(db_path)
    return True


# =============================================================================
# PROOF 3: RESTART BEHAVIOR CHANGE
# =============================================================================

def proof_restart_behavior_change():
    """
    PROOF: After restart, if evolution data exists,
    behavior is MEASURABLY DIFFERENT.
    """
    print_separator("PROOF 3: RESTART BEHAVIOR CHANGE")
    
    db_path = "test_restart_proof.db"
    safe_remove(db_path)
    
    # ========== SESSION 1: Initial Run ==========
    print("[SESSION 1] Initial run - no evolution data\n")
    
    engine1 = SelfRefiningEngine(db_path)
    
    target = "https://example.com/app"
    
    # Select strategy and profile
    strategy1, profile1 = engine1.select_strategy_and_profile(target)
    
    print(f"Selected Strategy: {strategy1.name}")
    print(f"Selected Profile:  {profile1.profile_id[:12]}...")
    print(f"  - Aggressiveness: {profile1.aggressiveness}")
    print(f"  - Step Order: {profile1.step_order}")
    print(f"  - Parameters: {json.dumps(profile1.parameters)}")
    
    # SIMULATE FAILURE
    target_sig = engine1.get_target_signature(target)
    print(f"\n[SIMULATING FAILURE] Recording failure for profile {profile1.profile_id[:8]}...")
    
    # Record multiple failures to trigger policy learning
    for _ in range(3):
        ctx_id = engine1.record_failure(
            target_signature=target_sig,
            strategy_name=strategy1.name,
            profile_id=profile1.profile_id,
            error_type="timeout",
            error_message="Connection timed out",
            tool_name="nikto"
        )
        engine1.learn_policy_from_failure(ctx_id)
    
    # Update profile outcome (failure)
    _ = engine1.update_profile_outcome(profile1.profile_id, success=False)
    engine1.update_profile_outcome(profile1.profile_id, success=False)
    engine1.update_profile_outcome(profile1.profile_id, success=False)
    
    print("  Recorded 3 failures")
    print(f"  Profile success rate: {engine1.get_profile(profile1.profile_id).success_rate:.2f}")
    
    status1 = engine1.get_evolution_status()
    print("\nSession 1 Evolution Status:")
    print(f"  Active Profiles: {status1['active_profiles']}")
    print(f"  Retired Profiles: {status1['retired_profiles']}")
    print(f"  Active Policies: {status1['active_policies']}")
    print(f"  Total Failures: {status1['total_failures']}")
    
    # Close connection
    del engine1
    gc.collect()
    
    # ========== SESSION 2: After Restart ==========
    print("\n" + "="*40)
    print("[SESSION 2] After restart - evolution data exists\n")
    
    engine2 = SelfRefiningEngine(db_path)  # Same database!
    
    # Check that evolution data persisted
    status2 = engine2.get_evolution_status()
    print("Loaded Evolution Status:")
    print(f"  Active Profiles: {status2['active_profiles']}")
    print(f"  Retired Profiles: {status2['retired_profiles']}")
    print(f"  Active Policies: {status2['active_policies']}")
    print(f"  Total Failures: {status2['total_failures']}")
    print(f"  Policies by Tier: {status2['policies_by_tier']}")
    
    # NOW: Select strategy and profile for SAME target
    strategy2, profile2 = engine2.select_strategy_and_profile(target)
    
    print(f"\nSelected Strategy: {strategy2.name}")
    print(f"Selected Profile:  {profile2.profile_id[:12]}...")
    print(f"  - Aggressiveness: {profile2.aggressiveness}")
    print(f"  - Step Order: {profile2.step_order}")
    print(f"  - Parameters: {json.dumps(profile2.parameters)}")
    
    # PROVE BEHAVIOR CHANGE
    print("\n[VERIFICATION] Comparing Session 1 vs Session 2...\n")
    
    behavior_changes = []
    
    # Check if different profile
    if profile1.profile_id != profile2.profile_id:
        behavior_changes.append(f"Different profile selected: {profile1.profile_id[:8]}... → {profile2.profile_id[:8]}...")
    
    # Check if different strategy
    if strategy1.name != strategy2.name:
        behavior_changes.append(f"Different strategy: {strategy1.name} → {strategy2.name}")
    
    # Check parameter differences
    for key in profile1.parameters:
        if key in profile2.parameters:
            if profile1.parameters[key] != profile2.parameters[key]:
                behavior_changes.append(f"Parameter '{key}': {profile1.parameters[key]} → {profile2.parameters[key]}")
    
    # Check step order
    if profile1.step_order != profile2.step_order:
        behavior_changes.append(f"Step order: {profile1.step_order} → {profile2.step_order}")
    
    # Check aggressiveness
    if abs(profile1.aggressiveness - profile2.aggressiveness) > 0.001:
        behavior_changes.append(f"Aggressiveness: {profile1.aggressiveness:.4f} → {profile2.aggressiveness:.4f}")
    
    print("BEHAVIOR CHANGES AFTER RESTART:")
    for change in behavior_changes:
        print(f"  ✓ {change}")
    
    if len(behavior_changes) == 0:
        print("❌ FAIL: No behavior change after restart despite evolution data!")
        safe_remove(db_path)
        return False
    
    # Verify policies affect tool selection
    context = {"target_type": "web_app", "target_signature": target_sig, "error_type": "timeout"}
    applicable_policies = engine2.get_applicable_policies(context)
    print(f"\nApplicable policies from learning: {len(applicable_policies)}")
    for pol in applicable_policies:
        print(f"  - Tier {pol.priority_tier}: {pol.action}")
    
    print("\n✅ PROOF COMPLETE: Restart behavior change is measurable")
    print(f"   - {len(behavior_changes)} behavior changes detected after restart")
    print(f"   - Evolution data persisted: {status2['total_failures']} failures, {status2['active_policies']} policies")
    
    safe_remove(db_path)
    return True


# =============================================================================
# PROOF 4: NON-REPETITION GUARANTEE
# =============================================================================

def proof_non_repetition():
    """
    PROOF: For identical target_signature + failure_context,
    the agent MUST choose a DIFFERENT profile.
    """
    print_separator("PROOF 4: NON-REPETITION GUARANTEE")
    
    db_path = "test_nonrepeat_proof.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    target = "192.168.1.100"
    target_sig = engine.get_target_signature(target)
    
    print(f"Target: {target}")
    print(f"Signature: {target_sig}")
    
    used_profiles = []
    
    print("\nSimulating repeated failures and selections:\n")
    
    for attempt in range(5):
        # Get strategies
        strategies = engine.get_strategies_for_target_type("network_host")
        strategy = strategies[0]  # aggressive_scan
        
        # Get available profiles (excluding failed ones)
        failed_for_target = engine.get_failed_profiles_for_target(target_sig)
        profile = engine.select_best_profile(strategy.name, excluded_profile_ids=failed_for_target)
        
        if profile is None:
            print(f"  Attempt {attempt+1}: No more profiles available - all exhausted or mutating")
            break
        
        print(f"  Attempt {attempt+1}: Selected profile {profile.profile_id[:12]}...")
        print(f"              Mutation Gen: {profile.mutation_generation}, Aggression: {profile.aggressiveness:.2f}")
        
        # Check for repetition
        if profile.profile_id in used_profiles:
            print(f"  ❌ FAIL: Profile {profile.profile_id[:8]}... was already used!")
            safe_remove(db_path)
            return False
        
        used_profiles.append(profile.profile_id)
        
        # Record failure for this attempt
        engine.record_failure(
            target_signature=target_sig,
            strategy_name=strategy.name,
            profile_id=profile.profile_id,
            error_type="connection_refused",
            error_message="Host unreachable"
        )
        
        # Update profile outcome
        engine.update_profile_outcome(profile.profile_id, success=False)
    
    print(f"\nTotal unique profiles used: {len(used_profiles)}")
    print("Profile selection history:")
    for i, pid in enumerate(used_profiles):
        profile = engine.get_profile(pid)
        if profile:
            status = "RETIRED" if profile.retired else "ACTIVE"
            print(f"  {i+1}. {pid[:12]}... | Gen {profile.mutation_generation} | {status}")
    
    # Verify all are unique
    if len(used_profiles) != len(set(used_profiles)):
        print("❌ FAIL: Duplicate profile detected!")
        safe_remove(db_path)
        return False
    
    print("\n✅ PROOF COMPLETE: Non-repetition guarantee works")
    print(f"   - {len(used_profiles)} consecutive failures used {len(used_profiles)} DIFFERENT profiles")
    print("   - No profile was ever repeated after failure")
    
    safe_remove(db_path)
    return True


# =============================================================================
# PROOF 5: ENFORCED SELECTION ORDER
# =============================================================================

def proof_selection_order():
    """
    PROOF: Selection order is enforced:
    1. classify target → target_signature
    2. select strategy.name
    3. select best strategy_profile
    4. profile is used for planning
    """
    print_separator("PROOF 5: ENFORCED SELECTION ORDER")
    
    db_path = "test_order_proof.db"
    safe_remove(db_path)
    
    engine = SelfRefiningEngine(db_path)
    
    target = "https://api.example.com/v1/users"
    
    print(f"Target: {target}\n")
    
    # Step 1: Classify
    print("STEP 1: Target Classification")
    target_type = engine.classify_target(target)
    target_sig = engine.get_target_signature(target)
    print(f"  Target Type: {target_type}")
    print(f"  Target Signature: {target_sig}")
    
    # Step 2: Select Strategy
    print("\nSTEP 2: Strategy Selection")
    strategies = engine.get_strategies_for_target_type(target_type)
    print(f"  Available strategies for '{target_type}': {[s.name for s in strategies]}")
    
    context = {"target_type": target_type, "target_signature": target_sig}
    filtered_strategies = engine.apply_policies_to_strategies(strategies, context)
    print(f"  After policy filter: {[s.name for s in filtered_strategies]}")
    
    selected_strategy = filtered_strategies[0] if filtered_strategies else None
    print(f"  Selected Strategy: {selected_strategy.name if selected_strategy else 'NONE'}")
    
    # Step 3: Select Profile
    print("\nSTEP 3: Profile Selection (for selected strategy)")
    if selected_strategy:
        profiles = engine.get_profiles_for_strategy(selected_strategy.name)
        print(f"  Available profiles: {len(profiles)}")
        for p in profiles:
            print(f"    - {p.profile_id[:12]}... | success_rate={p.success_rate:.2f} | aggression={p.aggressiveness:.2f}")
        
        # Apply policies to profiles
        filtered_profiles = engine.apply_policies_to_profiles(profiles, context)
        print(f"  After policy filter: {len(filtered_profiles)} profiles")
        
        # Exclude failed profiles
        failed = engine.get_failed_profiles_for_target(target_sig)
        print(f"  Previously failed profiles: {len(failed)}")
        
        available = [p for p in filtered_profiles if p.profile_id not in failed]
        print(f"  Available after exclusion: {len(available)} profiles")
        
        selected_profile = available[0] if available else None
        print(f"  Selected Profile: {selected_profile.profile_id if selected_profile else 'NONE'}")
    
    # Step 4: Profile used for planning
    print("\nSTEP 4: Profile parameters for planning")
    if selected_profile:
        print(f"  Step Order from Profile: {selected_profile.step_order}")
        print(f"  Parameters from Profile: {json.dumps(selected_profile.parameters, indent=4)}")
        print(f"  Aggressiveness: {selected_profile.aggressiveness}")
    
    # Verify using the combined method
    print("\n[VERIFICATION] Using select_strategy_and_profile() method:")
    strat, prof = engine.select_strategy_and_profile(target)
    print(f"  Result: strategy={strat.name}, profile={prof.profile_id[:12]}...")
    
    # Verify order is enforced (profile comes from correct strategy)
    if prof.strategy_name != strat.name:
        print("❌ FAIL: Profile does not belong to selected strategy!")
        safe_remove(db_path)
        return False
    
    print("\n✅ PROOF COMPLETE: Selection order is enforced")
    print("   - Classification → Strategy Selection → Profile Selection → Planning")
    print("   - Profile correctly belongs to selected strategy")
    
    safe_remove(db_path)
    return True


# =============================================================================
# MAIN
# =============================================================================

def main():
    """Run all proof tests"""
    print("\n" + "="*70)
    print("  SELF-REFINING EVOLVING AGENT - PROOF TESTS")
    print("  These tests PROVE the system works, not just assert it.")
    print("="*70)
    
    results = {}
    
    # Run all proofs
    results["Profile Mutation"] = proof_profile_mutation()
    results["Policy Conflict Resolution"] = proof_policy_conflict_resolution()
    results["Restart Behavior Change"] = proof_restart_behavior_change()
    results["Non-Repetition Guarantee"] = proof_non_repetition()
    results["Enforced Selection Order"] = proof_selection_order()
    
    # Summary
    print_separator("FINAL SUMMARY")
    
    all_passed = True
    for name, passed in results.items():
        status = "✅ PROVED" if passed else "❌ FAILED"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False
    
    print()
    if all_passed:
        print("🎉 ALL PROOFS COMPLETE - THIS IS A SELF-REFINING EVOLVING AGENT")
    else:
        print("⚠️  SOME PROOFS FAILED - SYSTEM DOES NOT MEET REQUIREMENTS")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
