import os
import sys

# Add project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# -----------------------------------------------------------------------------
# LATE IMPORTS (Moved to top for E402 compliance)
# -----------------------------------------------------------------------------
try:
    from core.agent.refactored_agent import RefactoredDrakbenAgent
    from core.config import ConfigManager
except ImportError:
    RefactoredDrakbenAgent = None
    ConfigManager = None

try:
    from core.intelligence.universal_adapter import UniversalAdapter
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
    from modules.report_generator import ReportConfig, ReportGenerator
except ImportError:
    ReportGenerator = None
    ReportConfig = None
# -----------------------------------------------------------------------------


def test_final_check() -> None:
    """Verify all critical modules can be instantiated."""
    # 1. Agent
    if RefactoredDrakbenAgent is not None and ConfigManager is not None:
        _ = RefactoredDrakbenAgent(ConfigManager())
    else:
        msg = "RefactoredDrakbenAgent or ConfigManager missing"
        raise AssertionError(msg)

    # 2. Universal Adapter
    if UniversalAdapter is not None:
        _ = UniversalAdapter()
    else:
        msg = "UniversalAdapter missing"
        raise AssertionError(msg)

    # 3. Weapon Foundry
    if WeaponFoundry is not None:
        _ = WeaponFoundry()
    else:
        msg = "WeaponFoundry missing"
        raise AssertionError(msg)

    # 4. Hive Mind
    if CredentialHarvester is not None:
        _ = CredentialHarvester()
    else:
        msg = "CredentialHarvester (HiveMind) missing"
        raise AssertionError(msg)

    # 5. Report Generator
    if ReportGenerator is not None and ReportConfig is not None:
        _ = ReportGenerator(ReportConfig(title="Test Report"))
    else:
        msg = "ReportGenerator missing"
        raise AssertionError(msg)


if __name__ == "__main__":
    try:
        test_final_check()
    except Exception:
        sys.exit(1)
