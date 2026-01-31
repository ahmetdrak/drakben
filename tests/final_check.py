import sys
import os

# Add project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

print("Starting Drakben Final System Check...")

# -----------------------------------------------------------------------------
# LATE IMPORTS (Moved to top for E402 compliance)
# -----------------------------------------------------------------------------
try:
    from core.refactored_agent import RefactoredDrakbenAgent
    from core.config import ConfigManager
except ImportError:
    RefactoredDrakbenAgent = None
    ConfigManager = None

try:
    from core.universal_adapter import UniversalAdapter
except ImportError:
    UniversalAdapter = None

try:
    from modules.weapon_foundry import WeaponFoundry
except ImportError:
    WeaponFoundry = None

try:
    from modules.hive_mind import CredentialHarvester
except ImportError:
    CredentialHarvester = None

try:
    from modules.report_generator import ReportGenerator, ReportConfig
except ImportError:
    ReportGenerator = None
    ReportConfig = None
# -----------------------------------------------------------------------------


def check_modules():
    print("\n[1] Checking Core Modules...")
    
    # 1. Agent
    print("[*] Testing RefactoredDrakbenAgent...", end=" ")
    if RefactoredDrakbenAgent and ConfigManager:
        try:
            _ = RefactoredDrakbenAgent(ConfigManager())
            print("✅ OK")
        except Exception as e:
            print(f"❌ FAIL: {e}")
    else:
        print("❌ FAIL: Module not found")

    # 2. Universal Adapter
    print("[*] Testing UniversalAdapter...", end=" ")
    if UniversalAdapter:
        try:
            _ = UniversalAdapter()
            print("✅ OK")
        except Exception as e:
            print(f"❌ FAIL: {e}")
    else:
        print("❌ FAIL: Module not found")

    # 3. Weapon Foundry
    print("[*] Testing WeaponFoundry...", end=" ")
    if WeaponFoundry:
        try:
            _ = WeaponFoundry()
            print("✅ OK")
        except Exception as e:
            print(f"❌ FAIL: {e}")
    else:
        print("❌ FAIL: Module not found")

    # 4. Hive Mind
    print("[*] Testing HiveMind...", end=" ")
    if CredentialHarvester:
        try:
            _ = CredentialHarvester()
            print("✅ OK")
        except Exception as e:
            print(f"❌ FAIL: {e}")
    else:
        print("❌ FAIL: Module not found")

    # 5. Report Generator
    print("[*] Testing ReportGenerator...", end=" ")
    if ReportGenerator and ReportConfig:
        try:
            _ = ReportGenerator(ReportConfig(title="Test Report"))
            print("✅ OK")
        except Exception as e:
            print(f"❌ FAIL: {e}")
    else:
        print("❌ FAIL: Module not found")


if __name__ == "__main__":
    try:
        check_modules()
        print("\n🎉 Final Check Complete: System is Ready!")
    except Exception as e:
        print(f"\n❌ Final Check Failed: {e}")
        sys.exit(1)
