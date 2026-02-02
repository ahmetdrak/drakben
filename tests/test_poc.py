import asyncio
import contextlib
import logging
import os
import sys

import pytest

# Add project root to path
sys.path.append(os.getcwd())

# Late imports moved to top for E402 compliance
try:
    from modules.stealth_client import StealthSession
except ImportError:
    StealthSession = None

try:
    from modules.waf_evasion import WAFEvasion
except ImportError:
    WAFEvasion = None

try:
    from core.database_manager import SQLiteProvider
except ImportError:
    SQLiteProvider = None

try:
    from modules.post_exploit import PostExploitEngine, ShellInterface
except ImportError:
    PostExploitEngine = None
    ShellInterface = object

# Setup logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("TheGauntlet")


@pytest.mark.asyncio
async def test_gauntlet_poc() -> None:
    """DRAKBEN 'THE GAUNTLET' PROOF-OF-CONCEPT - Full feature verification."""
    results = {"Stealth": False, "WAF": False, "Database": False, "PostExploit": False}

    # -------------------------------------------------------------
    # TEST 1: STEALTH & TLS FINGERPRINTING
    # -------------------------------------------------------------
    if StealthSession:
        session = StealthSession(impersonate="chrome120")
        headers = session.headers
        assert "Chrome" in headers.get("User-Agent", ""), (
            "User-Agent does not mimic Chrome!"
        )
        results["Stealth"] = True

    # -------------------------------------------------------------
    # TEST 2: WAF EVASION POLYMORPHISM
    # -------------------------------------------------------------
    if WAFEvasion:
        evader = WAFEvasion()
        payload = "<script>alert(1)</script>"
        obfuscated = evader.obfuscate_xss(payload)
        assert payload != obfuscated, "Payload was NOT obfuscated!"
        results["WAF"] = True

    # -------------------------------------------------------------
    # TEST 3: DATABASE CONCURRENCY (ASYNC STRESS)
    # -------------------------------------------------------------
    if SQLiteProvider:
        db_path = "tests/gauntlet_test.db"
        db = SQLiteProvider(db_path)
        tasks = []
        for _ in range(10):  # Stress test

            def log_task(d=db):
                return d.execute("SELECT 1").fetchone()

            tasks.append(asyncio.to_thread(log_task))
        await asyncio.gather(*tasks)
        results["Database"] = True
        db.close()
        del db
        await asyncio.sleep(0.5)
        if os.path.exists(db_path):
            with contextlib.suppress(Exception):
                os.remove(db_path)

    # -------------------------------------------------------------
    # TEST 4: POST-EXPLOITATION AI (SIMULATION)
    # -------------------------------------------------------------
    if PostExploitEngine:

        class MockHackedShell(ShellInterface):
            async def execute(self, cmd: str) -> str:
                if "uname -a" in cmd:
                    return "Linux k8s-node-1 5.15.0-1044-aws"
                if "cat /etc/*release" in cmd:
                    return "Ubuntu 22.04.1 LTS"
                if "ls -la /.dockerenv" in cmd:
                    return "-rwxr-xr-x 1 root root 0 Jan 1 /.dockerenv"
                if "cat /proc/1/cgroup" in cmd:
                    return "1:name=systemd:/kubepods/burstable/pod123"
                if "serviceaccount/token" in cmd:
                    return "EYJhbGciOiJSUzI1NiIsImtpZ..."
                if "passwd" in cmd:
                    return "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000:/home/user:/bin/bash"
                if "suid" in cmd:
                    return "/usr/bin/passwd\n/usr/bin/vim.basic"
                if "getcap" in cmd:
                    return "/usr/bin/python3 = cap_sys_admin+ep"
                if "sysctl" in cmd:
                    return "kernel.unprivileged_bpf_disabled = 0"
                return ""

            async def upload(self, data, path) -> bool:
                return True

            async def download(self, path) -> bytes:
                return b""

        mock_shell = MockHackedShell()
        engine = PostExploitEngine(mock_shell, os_type="linux")
        loot = await engine.run()
        assert loot.get("container")["environment"] == "Kubernetes"
        assert any("CAPABILITIES" in v["type"] for v in loot.get("privesc"))
        results["PostExploit"] = True

    # Final Verification
    assert all(results.values()), f"Some POC tests failed: {results}"


if __name__ == "__main__":
    asyncio.run(test_gauntlet_poc())
