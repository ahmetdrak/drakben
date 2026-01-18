"""
Test suite for core.zero_day_scanner module
"""

import pytest
from unittest.mock import Mock, patch
from core.zero_day_scanner import ZeroDayScanner


class TestZeroDayScanner:
    """Test cases for ZeroDayScanner class"""
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly"""
        scanner = ZeroDayScanner(use_api=False)
        assert scanner is not None
    
    def test_parse_scan_results(self, mock_scan_output):
        """Test parsing nmap scan output"""
        scanner = ZeroDayScanner(use_api=False)
        results = scanner.scan_results(mock_scan_output, {"target": "192.168.1.100"})
        
        assert results is not None
        assert "services" in results
        assert len(results["services"]) > 0
    
    @patch('requests.get')
    def test_cve_api_query(self, mock_get, mock_cve_data):
        """Test CVE API querying"""
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: mock_cve_data
        )
        
        scanner = ZeroDayScanner(use_api=True)
        cve_info = scanner._fetch_cve_data("CVE-2021-3156")
        
        assert cve_info is not None
        mock_get.assert_called_once()
    
    def test_severity_calculation(self):
        """Test CVSS severity calculation"""
        scanner = ZeroDayScanner(use_api=False)
        
        # High severity
        severity = scanner._get_severity("CVE-2021-3156")
        assert severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    def test_cve_caching(self, mock_cve_data):
        """Test CVE data caching mechanism"""
        scanner = ZeroDayScanner(use_api=False)
        
        # Cache data
        scanner._cache_cve_data("CVE-2021-3156", mock_cve_data)
        
        # Retrieve from cache
        cached = scanner._get_cve_from_cache("CVE-2021-3156")
        assert cached is not None
        assert cached["cve_id"] == "CVE-2021-3156"
