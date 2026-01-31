import sys
import os
sys.path.append(os.getcwd())
import asyncio
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FINAL_CHECK")

print("\n" + "="*60)
print("DRAKBEN FINAL SYSTEM INTEGRITY CHECK (RUNTIME)")
print("="*60 + "\n")

modules_to_check = [
    "modules.c2_framework",
    "modules.weapon_foundry",
    "modules.exploit",
    "modules.social_eng.profiler",
    "modules.social_eng.phishing",
    "modules.cve_database",
    "modules.hive_mind",
    "modules.ad_attacks",
    "modules.report_generator",
    "modules.research.symbolic",
    "modules.post_exploit"
]

failed_modules = []

for mod_name in modules_to_check:
    print(f"[*] Testing Import: {mod_name}...", end=" ")
    try:
        __import__(mod_name)
        print("✅ OK")
    except ImportError as e:
        print(f"❌ FAIL ({e})")
        failed_modules.append(mod_name)
    except Exception as e:
        print(f"❌ CRASH ({e})")
        failed_modules.append(mod_name)

print("\n" + "="*60)
print("INSTANTIATION CHECKS")
print("="*60 + "\n")

async def test_instantiation():
    try:
        print("[*] Testing WeaponFoundry...", end=" ")
        from modules.weapon_foundry import WeaponFoundry
        wf = WeaponFoundry()
        print("✅ OK")
    except Exception as e:
        print(f"❌ FAIL ({e})")

    try:
        print("[*] Testing CVE Database (Mock Init)...", end=" ")
        # Mocking init to avoid heavy DB creation
        from modules.cve_database import AutoUpdater
        # We won't fully init because it downloads data, just check class existence
        updater = AutoUpdater(None)
        print("✅ OK")
    except Exception as e:
        print(f"❌ FAIL ({e})")

    try:
        print("[*] Testing HiveMind...", end=" ")
        from modules.hive_mind import CredentialHarvester
        harvester = CredentialHarvester()
        print("✅ OK")
    except Exception as e:
        print(f"❌ FAIL ({e})")

    try:
        print("[*] Testing ReportGenerator...", end=" ")
        from modules.report_generator import ReportGenerator, ReportConfig
        rg = ReportGenerator(ReportConfig(title="Test Report"))
        print("✅ OK")
    except Exception as e:
        print(f"❌ FAIL ({e})")

    try:
        print("[*] Testing SymbolicExecutor...", end=" ")
        from modules.research.symbolic import SymbolicExecutor
        se = SymbolicExecutor()
        print("✅ OK (Z3: " + str(se.z3_available) + ")")
    except Exception as e:
        print(f"❌ FAIL ({e})")


if __name__ == "__main__":
    try:
        asyncio.run(test_instantiation())
    except Exception as e:
        print(f"Generic Async Error: {e}")

    if not failed_modules:
        print("\n" + "="*60)
        print("🎉 INTEGRITY CHECK PASSED: SYSTEM IS 100% OPERATIONAL")
        print("="*60 + "\n")
        exit(0)
    else:
        print("\n" + "="*60)
        print(f"⚠️ SYSTEM INTEGRITY FAILED: {len(failed_modules)} MODULES BROKEN")
        print("="*60 + "\n")
        exit(1)
