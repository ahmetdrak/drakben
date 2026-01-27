
import asyncio
import os
import json
import sys
import logging
from unittest.mock import MagicMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.state import AgentState, AttackPhase, ServiceInfo, VulnerabilityInfo, reset_state, get_state

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ResurrectionTest")

def run_resurrection_test():
    print("\n=== 🛡️ DRAKBEN RESURRECTION (PERSISTENCE) TEST ===\n")
    
    STATE_FILE = "agent_state.json"
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

    # --- 1. SEAMLESS INITIALIZATION ---
    print("[1/5] Initializing attack on '10.0.0.5'...")
    state = reset_state("10.0.0.5")
    state.phase = AttackPhase.RECON
    
    # Simulate finding some services
    services = [
        ServiceInfo(port=80, protocol="tcp", service="http", version="Apache 2.4"),
        ServiceInfo(port=22, protocol="tcp", service="ssh", version="OpenSSH 8.0")
    ]
    state.update_services(services)
    state.mark_surface_tested(80, "http")
    
    # Add a vulnerability
    state.add_vulnerability(VulnerabilityInfo(
        vuln_id="CVE-2023-1234",
        service="http",
        port=80,
        severity="CRITICAL",
        exploitable=True
    ))

    # --- 2. FORCE SAVE & "CRASH" ---
    print("[2/5] State populated. Simulating system crash/shutdown...")
    state.save()
    
    if not os.path.exists(STATE_FILE):
        print("❌ FAIL: State file was not created!")
        return False
        
    print(f"✅ State saved to {STATE_FILE} ({os.path.getsize(STATE_FILE)} bytes)")

    # --- 3. REBIRTH (NEW INSTANCE) ---
    print("[3/5] Restarting Drakben and loading state...")
    # Completely reset the singleton for simulation
    new_state = reset_state(None) # Don't pass target to simulate fresh load
    
    success = new_state.load()
    if not success:
        print("❌ FAIL: Failed to load state from disk!")
        return False

    # --- 4. VERIFICATION ---
    print("[4/5] Verifying data integrity...")
    
    checks = {
        "Target Recovery": new_state.target == "10.0.0.5",
        "Phase Recovery": new_state.phase == AttackPhase.RECON,
        "Service Count": len(new_state.open_services) == 2,
        "Surface Memory": "80:http" in new_state.tested_attack_surface,
        "Vuln Recovery": len(new_state.vulnerabilities) == 1 and new_state.vulnerabilities[0].vuln_id == "CVE-2023-1234",
        "Version Integrity": new_state.open_services[80].version == "Apache 2.4"
    }

    all_passed = True
    for name, result in checks.items():
        status = "✅" if result else "❌"
        print(f"   {status} {name}")
        if not result: all_passed = False

    # --- 5. PHASE CONTINUITY TEST ---
    print("[5/5] Testing logic continuity...")
    # If all surfaces are tested, it should be ready for Vuln Scan transition
    # (Since we only had 80 and 22, and we marked 80 as tested, let's mark 22 too)
    new_state.mark_surface_tested(22, "ssh")
    
    if len(new_state.remaining_attack_surface) == 0:
        print("✅ RECOVERY SUCCESS: Agent knows exactly where it left off!")
    else:
        print(f"⚠️ RECOVERY PARTIAL: {len(new_state.remaining_attack_surface)} surfaces unexpectedly remaining.")
        all_passed = False

    if all_passed:
        print("\n🏆 RESULT: DRAKBEN IS IMMORTAL! Resurrection test PASSED.\n")
    else:
        print("\n💀 RESULT: Resurrection test FAILED. Data loss detected.\n")
    
    return all_passed

if __name__ == "__main__":
    passed = run_resurrection_test()
    sys.exit(0 if passed else 1)
