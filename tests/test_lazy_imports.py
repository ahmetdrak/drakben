# tests/test_lazy_imports.py
"""Tests for the lazy-import mechanism in modules/__init__.py."""


import pytest

import modules


class TestLazyImportMap:
    """Verify _LAZY_MAP metadata is well-formed."""

    def test_lazy_map_exists(self) -> None:
        assert hasattr(modules, "_LAZY_MAP")
        assert isinstance(modules._LAZY_MAP, dict)

    def test_lazy_map_not_empty(self) -> None:
        assert len(modules._LAZY_MAP) > 50  # We know there are ~100 entries

    def test_all_values_are_two_tuples(self) -> None:
        for name, value in modules._LAZY_MAP.items():
            assert isinstance(value, tuple), f"{name}: expected tuple"
            assert len(value) == 2, f"{name}: expected 2-tuple"
            mod_path, attr_name = value
            assert isinstance(mod_path, str)
            assert isinstance(attr_name, str)

    def test_all_keys_in_all(self) -> None:
        for key in modules._LAZY_MAP:
            assert key in modules.__all__


class TestGetattr:
    """Test the __getattr__ lazy loader."""

    def test_unknown_attribute_raises(self) -> None:
        with pytest.raises(AttributeError, match="no attribute"):
            modules.__getattr__("absolutely_nonexistent_symbol_xyz")

    def test_known_symbol_loads(self) -> None:
        # Pick a lightweight symbol from each category
        # ReportFormat is an Enum — cheap to import
        report_format = modules.__getattr__("ReportFormat")
        assert report_format is not None
        assert hasattr(report_format, "HTML")

    def test_idempotent_load(self) -> None:
        """Requesting the same symbol twice returns the same object."""
        a = modules.__getattr__("FindingSeverity")
        b = modules.__getattr__("FindingSeverity")
        assert a is b

    def test_multiple_categories(self) -> None:
        """Symbols from different submodules all resolve."""
        # These should not raise
        for sym in ("ReportFormat", "Finding", "ReportGenerator"):
            obj = modules.__getattr__(sym)
            assert obj is not None

    def test_scan_ports_in_lazy_map(self) -> None:
        """port scanner symbols are registered."""
        assert "scan_ports" in modules._LAZY_MAP
        assert "scan_ports_sync" in modules._LAZY_MAP


class TestDirectImport:
    """Integration: ``from modules import X`` should work via lazy loading."""

    def test_from_import(self) -> None:
        from modules import ReportFormat
        assert hasattr(ReportFormat, "HTML")

    def test_from_import_finding(self) -> None:
        from modules import Finding
        f = Finding(
            title="t", severity=modules.__getattr__("FindingSeverity").LOW,
            description="d", affected_asset="a",
        )
        assert f.title == "t"
