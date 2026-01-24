# tests/conftest.py
# DRAKBEN Test Configuration
# Pytest fixtures and configuration

import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def project_root():
    """Return project root directory"""
    return Path(__file__).parent.parent


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    temp = tempfile.mkdtemp()
    yield temp
    # Cleanup
    import shutil
    shutil.rmtree(temp, ignore_errors=True)


@pytest.fixture
def temp_db():
    """Create temporary database file"""
    temp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    temp.close()
    yield temp.name
    # Cleanup
    try:
        os.unlink(temp.name)
    except OSError:
        pass


@pytest.fixture
def reset_state():
    """Reset AgentState singleton before each test"""
    from core.state import reset_state
    reset_state()
    yield
    # Reset after test too
    reset_state()


@pytest.fixture
def sample_state(reset_state):
    """Create sample AgentState with basic data"""
    from core.state import reset_state, ServiceInfo, VulnerabilityInfo
    
    state = reset_state("192.168.1.1")
    
    # Add some services
    state.add_open_services([
        ServiceInfo(port=80, protocol="tcp", service="http", version="Apache/2.4"),
        ServiceInfo(port=443, protocol="tcp", service="https", version="nginx/1.18"),
        ServiceInfo(port=22, protocol="tcp", service="ssh", version="OpenSSH 8.0")
    ])
    
    return state


@pytest.fixture
def sample_config(temp_dir):
    """Create sample configuration"""
    from core.config import ConfigManager
    
    config_path = os.path.join(temp_dir, "settings.json")
    config = ConfigManager(config_file=config_path)
    
    return config


@pytest.fixture
def sample_findings():
    """Create sample findings for report tests"""
    from modules.report_generator import Finding, FindingSeverity
    
    return [
        Finding(
            title="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            description="SQL injection in login endpoint",
            affected_asset="https://example.com/login",
            evidence="Parameter 'id' is vulnerable",
            remediation="Use parameterized queries"
        ),
        Finding(
            title="XSS",
            severity=FindingSeverity.HIGH,
            description="Reflected XSS in search",
            affected_asset="https://example.com/search",
            evidence="<script>alert(1)</script> executed",
            remediation="Encode output"
        ),
        Finding(
            title="Information Disclosure",
            severity=FindingSeverity.LOW,
            description="Server version exposed",
            affected_asset="https://example.com",
            evidence="Server: Apache/2.4.41"
        )
    ]


@pytest.fixture
def mock_llm_response():
    """Mock LLM response for testing"""
    return {
        "choices": [{
            "message": {
                "content": "Test response from LLM"
            }
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5
        }
    }


# Async fixtures
@pytest.fixture
def event_loop():
    """Create event loop for async tests"""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# Markers
def pytest_configure(config):
    """Configure custom markers"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "network: marks tests that require network access"
    )
