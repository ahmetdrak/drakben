import asyncio
import importlib.util
import importlib.machinery
import types
import sys
from pathlib import Path

# Load core.state directly from file to avoid importing package `core` which
# can pull in refactored modules and cause circular imports during tests.
ROOT = Path(__file__).parent.parent
core_pkg = types.ModuleType("core")
sys.modules["core"] = core_pkg

spec = importlib.util.spec_from_file_location("core.state", str(ROOT / "core" / "state.py"))
state_mod = importlib.util.module_from_spec(spec)
sys.modules["core.state"] = state_mod
spec.loader.exec_module(state_mod)

reset_state = state_mod.reset_state

# Now import modules which expect `core.state` to be available
from modules import payload, exploit


def test_exploit_precondition_blocks_without_services():
    """Exploit should be blocked when preconditions fail (no services, wrong phase)."""
    state = reset_state(target="http://example.com")
    # Default phase is INIT, no services discovered
    result = exploit.run_sqlmap("http://example.com", param="id", level="1", state=state)
    assert isinstance(result, dict)
    assert result.get("blocked") is True
    assert "Precondition failed" in result.get("error", "")


def test_payload_blocked_without_foothold():
    """Payload functions must be blocked when no foothold is present."""
    state = reset_state(target="10.0.0.1")

    # reverse_shell is async
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        res = loop.run_until_complete(payload.reverse_shell("127.0.0.1", 4444, state=state))
    finally:
        try:
            loop.close()
        except Exception:
            pass

    assert isinstance(res, dict)
    assert res.get("blocked") is True
    assert "FORBIDDEN" in res.get("error", "") or res.get("critical_violation")
