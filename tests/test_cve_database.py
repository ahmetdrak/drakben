# tests/test_cve_database.py
"""Tests for CVE Database module."""

from unittest.mock import patch

import pytest

from modules.cve_database import (
    AutoUpdater,
    CVEDatabase,
    CVEEntry,
    CVSSSeverity,
    VulnerabilityMatch,
    VulnerabilityMatcher,
)


class TestCVSSeverity:
    """Tests for CVSSSeverity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert CVSSSeverity.NONE.value == "none"
        assert CVSSSeverity.LOW.value == "low"
        assert CVSSSeverity.MEDIUM.value == "medium"
        assert CVSSSeverity.HIGH.value == "high"
        assert CVSSSeverity.CRITICAL.value == "critical"

    def test_all_severities_exist(self):
        """Test all severity levels exist."""
        severities = [s.value for s in CVSSSeverity]
        assert "none" in severities
        assert "critical" in severities


class TestCVEEntry:
    """Tests for CVEEntry dataclass."""

    def test_cve_entry_creation(self):
        """Test CVE entry creation."""
        entry = CVEEntry(
            cve_id="CVE-2024-1234",
            description="Test vulnerability",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            severity=CVSSSeverity.HIGH,
            published_date="2024-01-01",
            last_modified="2024-01-15",
        )
        assert entry.cve_id == "CVE-2024-1234"
        assert abs(entry.cvss_score - 7.5) < 0.001  # Use epsilon comparison
        assert entry.severity == CVSSSeverity.HIGH

    def test_cve_entry_to_dict(self):
        """Test CVE entry serialization."""
        entry = CVEEntry(
            cve_id="CVE-2024-5678",
            description="Another test",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            severity=CVSSSeverity.CRITICAL,
            published_date="2024-02-01",
            last_modified="2024-02-01",
            references=["https://example.com"],
        )
        result = entry.to_dict()
        assert result["cve_id"] == "CVE-2024-5678"
        assert result["severity"] == "critical"
        assert "https://example.com" in result["references"]

    def test_cve_entry_defaults(self):
        """Test CVE entry default values."""
        entry = CVEEntry(
            cve_id="CVE-2024-0000",
            description="Minimal",
            cvss_score=0.0,
            cvss_vector="",
            severity=CVSSSeverity.NONE,
            published_date="",
            last_modified="",
        )
        assert entry.references == []
        assert entry.cpe_matches == []
        assert entry.weaknesses == []


class TestVulnerabilityMatch:
    """Tests for VulnerabilityMatch dataclass."""

    def test_vulnerability_match_with_cve(self):
        """Test vulnerability match with CVE."""
        cve = CVEEntry(
            cve_id="CVE-2024-1111",
            description="Test",
            cvss_score=5.0,
            cvss_vector="",
            severity=CVSSSeverity.MEDIUM,
            published_date="2024-01-01",
            last_modified="2024-01-01",
        )
        match = VulnerabilityMatch(
            detected_vuln="SQL Injection",
            cve_entry=cve,
            confidence=0.85,
            match_method="keyword",
        )
        assert abs(match.confidence - 0.85) < 0.001  # Use epsilon comparison
        assert match.match_method == "keyword"

    def test_vulnerability_match_without_cve(self):
        """Test vulnerability match without CVE."""
        match = VulnerabilityMatch(
            detected_vuln="Unknown vuln",
            cve_entry=None,
            confidence=0.3,
            match_method="fuzzy",
        )
        result = match.to_dict()
        assert result["cve"] is None
        assert abs(result["confidence"] - 0.3) < 0.001  # Use epsilon comparison


class TestCVEDatabase:
    """Tests for CVEDatabase class."""

    def test_database_initialization(self, tmp_path):
        """Test database initialization."""
        db_path = tmp_path / "test_cve.db"
        db = CVEDatabase(db_path=str(db_path), auto_update=False)
        assert str(db.db_path) == str(db_path)
        assert db_path.exists()

    def test_database_default_path(self):
        """Test database uses default path."""
        db = CVEDatabase(auto_update=False)
        assert "nvd_cache.db" in str(db.db_path)

    def test_get_last_sync_time(self, tmp_path):
        """Test getting last sync time."""
        db_path = tmp_path / "test_sync.db"
        db = CVEDatabase(db_path=str(db_path), auto_update=False)
        result = db.get_last_sync_time()
        # May be None if never synced
        assert result is None or isinstance(result, str)


class TestAutoUpdater:
    """Tests for AutoUpdater class."""

    def test_auto_updater_initialization(self, tmp_path):
        """Test auto updater initialization."""
        db_path = tmp_path / "test_auto.db"
        db = CVEDatabase(db_path=str(db_path), auto_update=False)
        updater = AutoUpdater(db)
        assert updater.db == db
        assert updater.running is False

    def test_start_background_update(self, tmp_path):
        """Test starting background update thread."""
        db_path = tmp_path / "test_bg.db"
        db = CVEDatabase(db_path=str(db_path), auto_update=False)
        updater = AutoUpdater(db)

        # Should not raise
        with patch.object(updater, '_update_loop'):
            updater.start_background_update()


class TestEnrichedVulnerability:
    """Tests for VulnerabilityMatcher."""

    def test_vulnerability_matcher_creation(self, tmp_path):
        """Test vulnerability matcher creation."""
        db_path = tmp_path / "test_matcher.db"
        db = CVEDatabase(db_path=str(db_path), auto_update=False)
        matcher = VulnerabilityMatcher(db)
        assert isinstance(matcher, VulnerabilityMatcher)


# Integration tests
class TestCVEDatabaseIntegration:
    """Integration tests for CVE database."""

    def test_full_workflow(self, tmp_path):
        """Test complete workflow."""
        db_path = tmp_path / "test_workflow.db"
        cve_db = CVEDatabase(db_path=str(db_path), auto_update=False)

        # Verify database created
        assert db_path.exists()
        assert isinstance(cve_db, CVEDatabase)

        # Check tables exist
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t[0] for t in tables]
            assert "cve_cache" in table_names
            assert "keyword_index" in table_names

    @pytest.mark.asyncio
    @pytest.mark.filterwarnings("ignore::ResourceWarning")
    async def test_cpe_matching_async(self, tmp_path):
        """Test CPE-based matching (async)."""
        db_path = tmp_path / "test_cpe.db"
        db = CVEDatabase(db_path=str(db_path), auto_update=False)

        # CPE format: cpe:2.3:a:vendor:product:version
        cpe = "cpe:2.3:a:apache:tomcat:9.0.0"
        results = await db.search_by_cpe(cpe)
        assert isinstance(results, list)
