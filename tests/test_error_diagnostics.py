"""Tests for ErrorDiagnosticsMixin"""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.agent.error_diagnostics import ErrorDiagnosticsMixin


class TestErrorDiagnostics(unittest.TestCase):
    """Test error diagnosis functionality"""
    
    def setUp(self):
        """Create a test class that uses the mixin"""
        class TestClass(ErrorDiagnosticsMixin):
            pass
        self.diagnoser = TestClass()
    
    def test_missing_tool(self):
        """Test missing tool detection"""
        result = self.diagnoser._diagnose_error("bash: nmap: command not found", 127)
        self.assertEqual(result["type"], "missing_tool")
        self.assertEqual(result["tool"], "nmap")
    
    def test_permission_denied(self):
        """Test permission denied detection"""
        result = self.diagnoser._diagnose_error("Permission denied", 1)
        self.assertEqual(result["type"], "permission_denied")
    
    def test_timeout(self):
        """Test timeout detection"""
        result = self.diagnoser._diagnose_error("Connection timed out", 1)
        self.assertEqual(result["type"], "timeout")
    
    def test_network_error(self):
        """Test network error detection"""
        result = self.diagnoser._diagnose_error("Connection refused", 1)
        self.assertEqual(result["type"], "connection_error")
    
    def test_python_module_missing(self):
        """Test Python module missing detection"""
        result = self.diagnoser._diagnose_error("ModuleNotFoundError: No module named 'requests'", 1)
        self.assertEqual(result["type"], "python_module_missing")
        self.assertEqual(result["module"], "requests")
    
    def test_file_not_found(self):
        """Test file not found detection"""
        result = self.diagnoser._diagnose_error("No such file or directory: config.json", 1)
        self.assertEqual(result["type"], "file_not_found")
    
    def test_exit_code_127(self):
        """Test exit code 127 (command not found) with empty output"""
        result = self.diagnoser._diagnose_error("", 127)
        self.assertEqual(result["type"], "missing_tool")
    
    def test_unknown_error(self):
        """Test unknown error handling"""
        result = self.diagnoser._diagnose_error("Something weird happened xyz123", 99)
        self.assertEqual(result["type"], "unknown")
    
    def test_rate_limit(self):
        """Test rate limit detection"""
        result = self.diagnoser._diagnose_error("Error 429: Too many requests", 1)
        self.assertEqual(result["type"], "rate_limit")
    
    def test_firewall(self):
        """Test firewall detection"""
        result = self.diagnoser._diagnose_error("Request filtered by WAF", 1)
        self.assertEqual(result["type"], "firewall_blocked")


if __name__ == "__main__":
    unittest.main()
