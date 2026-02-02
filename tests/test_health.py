import importlib.util
import logging
import os
import sys

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("health_check")

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def test_module_health() -> None:
    """Verify all critical modules are importable."""
    logger.info("Starting Drakben Health Check...")
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
    for module_name in modules_to_check:
        try:
            spec = importlib.util.find_spec(module_name)
            if spec is None:
                failed_modules.append(module_name)
        except Exception:
            failed_modules.append(module_name)

    assert not failed_modules, f"Critical modules missing or broken: {failed_modules}"


if __name__ == "__main__":
    try:
        test_module_health()
    except AssertionError:
        sys.exit(1)
