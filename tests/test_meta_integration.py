import importlib
from types import SimpleNamespace

import pytest

from core import tool_parsers
from core import meta_reasoning


def test_parse_nmap_output_basic():
    sample = """
80/tcp open http
22/tcp open ssh
"""
    services = tool_parsers.parse_nmap_output(sample)
    assert isinstance(services, list)
    assert any(s.get("port") == 80 for s in services)


def test_parse_sqlmap_output_basic():
    sample = "Parameter 'id' is injectable with boolean-based blind"
    vulns = tool_parsers.parse_sqlmap_output(sample)
    assert isinstance(vulns, list)
    assert vulns and vulns[0]["technique"] == "sqli"


def test_meta_reasoning_recommends_foothold_and_stop():
    # mock state as SimpleNamespace
    state = SimpleNamespace(has_foothold=False, iteration_count=14, max_iterations=15)
    obs = [{"service": "http"}, {"service": "mysql"}]
    report = meta_reasoning.analyze_run(state, obs)
    assert "acquire_foothold" in report["recommendations"]
    assert "stop_or_rotate_target" in report["recommendations"]


def test_legacy_c2_beacon_import_raises():
    # Load the file directly to avoid package import resolution issues in test runner
    import importlib.util
    from pathlib import Path

    beacon_path = Path("core") / "c2_beacon.py"
    spec = importlib.util.spec_from_file_location("core.c2_beacon", str(beacon_path))
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(RuntimeError):
        spec.loader.exec_module(module)  # type: ignore[attr-defined]
