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


def test_final_check():
    """Verify all critical modules can be instantiated"""
    # 1. Agent
    if RefactoredDrakbenAgent and ConfigManager:
        _ = RefactoredDrakbenAgent(ConfigManager())
    else:
        assert False, "RefactoredDrakbenAgent or ConfigManager missing"

    # 2. Universal Adapter
    if UniversalAdapter:
        _ = UniversalAdapter()
    else:
        assert False, "UniversalAdapter missing"

    # 3. Weapon Foundry
    if WeaponFoundry:
        _ = WeaponFoundry()
    else:
        assert False, "WeaponFoundry missing"

    # 4. Hive Mind
    if CredentialHarvester:
        _ = CredentialHarvester()
    else:
        assert False, "CredentialHarvester (HiveMind) missing"

    # 5. Report Generator
    if ReportGenerator and ReportConfig:
        _ = ReportGenerator(ReportConfig(title="Test Report"))
    else:
        assert False, "ReportGenerator missing"


if __name__ == "__main__":
    try:
        test_final_check()
        print("\n🎉 Final Check Complete: System is Ready!")
    except Exception as e:
        print(f"\n❌ Final Check Failed: {e}")
        sys.exit(1)
