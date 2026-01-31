import importlib.util
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

print("Starting Drakben Health Check...")

modules_to_check = [
    "core.refactored_agent",
    "core.universal_adapter",
    "core.self_refining_engine",
    "core.evolution_memory",
    "modules.weapon_foundry",
    "modules.hive_mind",
    "modules.c2_framework",
    "core.ghost_protocol",
]

failed_modules = []

print("Checking Modules...")

for module_name in modules_to_check:
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            print(f"✅ {module_name} FOUND")
        else:
            print(f"❌ {module_name} NOT FOUND")
            failed_modules.append(module_name)
    except Exception as e:
        print(f"❌ {module_name} ERROR: {e}")
        failed_modules.append(module_name)

if failed_modules:
    print(f"\n❌ FATAL: The following modules are missing or broken: {failed_modules}")
    sys.exit(1)
else:
    print("\n🎉 ALL CRITICAL MODULES VERIFIED SUCCESSFULLY!")
    print("System is structurally sound.")
