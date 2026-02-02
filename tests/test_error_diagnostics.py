"""Tests for ErrorDiagnosticsMixin."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent.error_diagnostics import ErrorDiagnosticsMixin


class TestErrorDiagnostics(unittest.TestCase):
    """Test error diagnosis functionality."""

    def setUp(self) -> None:
        """Create a test class that uses the mixin."""

        class TestClass(ErrorDiagnosticsMixin):
            pass

        self.diagnoser = TestClass()

    def test_missing_tool(self) -> None:
        """Test missing tool detection."""
        result = self.diagnoser._diagnose_error("bash: nmap: command not found", 127)
        if result["type"] != "missing_tool":
            msg = 'result["type"] == "missing_tool"'
            raise AssertionError(msg)
        if result["tool"] != "nmap":
            msg = 'result["tool"] == "nmap"'
            raise AssertionError(msg)

    def test_permission_denied(self) -> None:
        """Test permission denied detection."""
        result = self.diagnoser._diagnose_error("Permission denied", 1)
        if result["type"] != "permission_denied":
            msg = 'result["type"] == "permission_denied"'
            raise AssertionError(msg)

    def test_timeout(self) -> None:
        """Test timeout detection."""
        result = self.diagnoser._diagnose_error("Connection timed out", 1)
        if result["type"] != "timeout":
            msg = 'result["type"] == "timeout"'
            raise AssertionError(msg)

    def test_network_error(self) -> None:
        """Test network error detection."""
        result = self.diagnoser._diagnose_error("Connection refused", 1)
        if result["type"] != "connection_error":
            msg = 'result["type"] == "connection_error"'
            raise AssertionError(msg)

    def test_python_module_missing(self) -> None:
        """Test Python module missing detection."""
        result = self.diagnoser._diagnose_error(
            "ModuleNotFoundError: No module named 'requests'",
            1,
        )
        if result["type"] != "python_module_missing":
            msg = 'result["type"] == "python_module_missing"'
            raise AssertionError(msg)
        if result["module"] != "requests":
            msg = 'result["module"] == "requests"'
            raise AssertionError(msg)

    def test_file_not_found(self) -> None:
        """Test file not found detection."""
        result = self.diagnoser._diagnose_error(
            "No such file or directory: config.json",
            1,
        )
        if result["type"] != "file_not_found":
            msg = 'result["type"] == "file_not_found"'
            raise AssertionError(msg)

    def test_exit_code_127(self) -> None:
        """Test exit code 127 (command not found) with empty output."""
        result = self.diagnoser._diagnose_error("", 127)
        if result["type"] != "missing_tool":
            msg = 'result["type"] == "missing_tool"'
            raise AssertionError(msg)

    def test_unknown_error(self) -> None:
        """Test unknown error handling."""
        result = self.diagnoser._diagnose_error("Something weird happened xyz123", 99)
        if result["type"] != "unknown":
            msg = 'result["type"] == "unknown"'
            raise AssertionError(msg)

    def test_rate_limit(self) -> None:
        """Test rate limit detection."""
        result = self.diagnoser._diagnose_error("Error 429: Too many requests", 1)
        if result["type"] != "rate_limit":
            msg = 'result["type"] == "rate_limit"'
            raise AssertionError(msg)

    def test_firewall(self) -> None:
        """Test firewall detection."""
        result = self.diagnoser._diagnose_error("Request filtered by WAF", 1)
        if result["type"] != "firewall_blocked":
            msg = 'result["type"] == "firewall_blocked"'
            raise AssertionError(msg)


if __name__ == "__main__":
    unittest.main()
