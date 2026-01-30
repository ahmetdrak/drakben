import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

print("Starting Drakben Health Check...")

try:
    print("Checking Core Modules...")
    from core.refactored_agent import RefactoredDrakbenAgent
    print("✅ core.refactored_agent OK")
    
    from core.universal_adapter import UniversalAdapter
    print("✅ core.universal_adapter OK")

    from core.self_refining_engine import SelfRefiningEngine
    print("✅ core.self_refining_engine OK")

    from core.evolution_memory import EvolutionMemory
    print("✅ core.evolution_memory OK")

    print("Checking Offensive Modules...")
    from modules.weapon_foundry import WeaponFoundry
    print("✅ modules.weapon_foundry OK")
    
    from modules.hive_mind import HiveMind
    print("✅ modules.hive_mind OK")
    
    from modules.c2_framework import C2Channel
    print("✅ modules.c2_framework OK")

    from core.ghost_protocol import GhostProtocol
    print("✅ core.ghost_protocol OK")

    print("\n🎉 ALL CRITICAL MODULES IMPORTED SUCCESSFULLY!")
    print("System is structurally sound.")

except ImportError as e:
    print(f"\n❌ FATAL IMPORT ERROR: {e}")
    sys.exit(1)
except Exception as e:
    print(f"\n❌ UNEXPECTED ERROR: {e}")
    sys.exit(1)
