"""
DRAKBEN Test Suite Configuration
pytest configuration and fixtures
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def mock_target():
    """Mock target IP for testing"""
    return "192.168.1.100"


@pytest.fixture
def mock_session():
    """Mock session data"""
    return {
        "target": "192.168.1.100",
        "strategy": "balanced",
        "scan_results": [],
        "vulnerabilities": [],
        "exploits": []
    }


@pytest.fixture
def mock_scan_output():
    """Mock nmap scan output"""
    return """
    Starting Nmap 7.93 ( https://nmap.org )
    Nmap scan report for 192.168.1.100
    Host is up (0.0010s latency).
    PORT     STATE SERVICE    VERSION
    22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2
    80/tcp   open  http       Apache httpd 2.4.38
    443/tcp  open  ssl/http   Apache httpd 2.4.38
    3306/tcp open  mysql      MySQL 5.7.33
    """


@pytest.fixture
def mock_cve_data():
    """Mock CVE vulnerability data"""
    return {
        "cve_id": "CVE-2021-3156",
        "severity": "HIGH",
        "cvss": 7.8,
        "description": "Sudo heap-based buffer overflow",
        "affected_versions": ["1.8.2", "1.8.31p2"],
        "exploit_available": True
    }
