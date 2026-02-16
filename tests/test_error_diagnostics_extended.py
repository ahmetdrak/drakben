# tests/test_error_diagnostics_extended.py
"""Comprehensive tests for ErrorDiagnosticsMixin — basic + extended checkers."""

import pytest

from core.agent.error_diagnostics import ErrorDiagnosticsMixin


class DiagnosticsHelper(ErrorDiagnosticsMixin):
    """Concrete class to test the mixin."""


@pytest.fixture()
def diag() -> DiagnosticsHelper:
    return DiagnosticsHelper()


# ── Basic error categories (was test_error_diagnostics.py) ────


class TestBasicDiagnostics:
    """Basic _diagnose_error coverage for common error types."""

    def test_missing_tool(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error("bash: nmap: command not found", 127)
        assert result["type"] == "missing_tool"
        assert result["tool"] == "nmap"

    def test_permission_denied(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error("Permission denied", 1)
        assert result["type"] == "permission_denied"

    def test_timeout(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error("Connection timed out", 1)
        assert result["type"] == "timeout"

    def test_network_error(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error("Connection refused", 1)
        assert result["type"] == "connection_error"

    def test_python_module_missing(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error(
            "ModuleNotFoundError: No module named 'requests'",
            1,
        )
        assert result["type"] == "python_module_missing"
        assert result["module"] == "requests"

    def test_file_not_found(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error(
            "No such file or directory: config.json",
            1,
        )
        assert result["type"] == "file_not_found"

    def test_unknown_error(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error("Something weird happened xyz123", 99)
        assert result["type"] == "unknown"

    def test_rate_limit(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error("Error 429: Too many requests", 1)
        assert result["type"] == "rate_limit"

    def test_firewall(self, diag: DiagnosticsHelper) -> None:
        result = diag._diagnose_error("Request filtered by WAF", 1)
        assert result["type"] == "firewall_blocked"


# ── _check_library_error ──────────────────────────────────────


class TestLibraryError:
    def test_shared_object(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_library_error("error: cannot open shared object file: libssl.so.1.1")
        assert r is not None
        assert r["type"] == "library_missing"
        assert r["library"] is not None

    def test_dll(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_library_error("error loading msvcrt.dll")
        assert r is not None
        assert r["type"] == "library_missing"

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_library_error("all good") is None


# ── _check_syntax_error ──────────────────────────────────────


class TestSyntaxError:
    def test_invalid_argument(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_syntax_error("error: invalid argument '--foo'")
        assert r is not None
        assert r["type"] == "invalid_argument"

    def test_unrecognized_option(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_syntax_error("unrecognized option: -z")
        assert r is not None

    def test_usage(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_syntax_error("usage: nmap [options] target")
        assert r is not None

    def test_try_help(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_syntax_error("try '--help' for more information")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_syntax_error("scan complete") is None


# ── _check_memory_error ──────────────────────────────────────


class TestMemoryError:
    def test_out_of_memory(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_memory_error("killed (out of memory)")
        assert r is not None
        assert r["type"] == "memory_error"

    def test_segfault(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_memory_error("segmentation fault (core dumped)")
        assert r is not None
        assert r["type"] == "memory_error"

    def test_enomem(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_memory_error("enomem: cannot allocate")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_memory_error("healthy") is None


# ── _check_disk_error ────────────────────────────────────────


class TestDiskError:
    def test_no_space(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_disk_error("no space left on device")
        assert r is not None
        assert r["type"] == "disk_full"

    def test_disk_quota(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_disk_error("disk quota exceeded")
        assert r is not None

    def test_enospc(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_disk_error("enospc error writing file")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_disk_error("plenty of space") is None


# ── _check_auth_error ────────────────────────────────────────


class TestAuthError:
    def test_auth_failed(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_auth_error("authentication failed for user admin")
        assert r is not None
        assert r["type"] == "auth_error"

    def test_unauthorized(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_auth_error("HTTP 401 unauthorized")
        assert r is not None

    def test_forbidden(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_auth_error("403 forbidden")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_auth_error("logged in successfully") is None


# ── _check_port_error ────────────────────────────────────────


class TestPortError:
    def test_address_in_use(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_port_error("error: address already in use port: 8080")
        assert r is not None
        assert r["type"] == "port_in_use"
        assert r["port"] == "8080"

    def test_eaddrinuse(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_port_error("eaddrinuse on 0.0.0.0:3000")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_port_error("listening on port 80") is None


# ── _check_database_error ────────────────────────────────────


class TestDatabaseError:
    def test_sqlite_locked(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_database_error("sqlite3.operationalerror: database is locked")
        assert r is not None
        assert r["type"] == "database_error"

    def test_mysql_error(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_database_error("mysql error: connection refused")
        assert r is not None

    def test_deadlock(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_database_error("deadlock detected")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_database_error("database query ok") is None


# ── _check_parse_error ───────────────────────────────────────


class TestParseError:
    def test_json_decode(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_parse_error("json.decoder.jsondecodeerror: expecting value")
        assert r is not None
        assert r["type"] == "parse_error"

    def test_xml_parsing(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_parse_error("xml parsing error: unclosed tag")
        assert r is not None

    def test_malformed_json(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_parse_error("malformed json in response body")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_parse_error("parsed successfully") is None


# ── _check_version_error ─────────────────────────────────────


class TestVersionError:
    def test_version_mismatch(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_version_error("version mismatch: expected 3.9, got 3.7")
        assert r is not None
        assert r["type"] == "version_error"

    def test_requires_python(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_version_error("requires python >= 3.10")
        assert r is not None

    def test_deprecated_removed(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_version_error("this api is deprecated and removed")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_version_error("python 3.13 ready") is None


# ── _check_resource_error ────────────────────────────────────


class TestResourceError:
    def test_too_many_files(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_resource_error("too many open files")
        assert r is not None
        assert r["type"] == "resource_limit"

    def test_eagain(self, diag: DiagnosticsHelper) -> None:
        r = diag._check_resource_error("eagain: resource temporarily unavailable")
        assert r is not None

    def test_no_match(self, diag: DiagnosticsHelper) -> None:
        assert diag._check_resource_error("resources ok") is None


# ── _diagnose_error (top-level integration) ──────────────────


class TestDiagnoseError:
    def test_unknown_error_fallback(self, diag: DiagnosticsHelper) -> None:
        r = diag._diagnose_error("something completely unknown happened", 0)
        assert r["type"] == "unknown"
        assert "raw_output" in r

    def test_exit_code_127(self, diag: DiagnosticsHelper) -> None:
        r = diag._diagnose_error("", 127)
        assert r["type"] == "missing_tool"

    def test_exit_code_137(self, diag: DiagnosticsHelper) -> None:
        r = diag._diagnose_error("", 137)
        assert r["type"] == "killed"

    def test_exit_code_139(self, diag: DiagnosticsHelper) -> None:
        r = diag._diagnose_error("", 139)
        assert r["type"] == "segfault"

    def test_signal_above_128(self, diag: DiagnosticsHelper) -> None:
        r = diag._diagnose_error("", 200)
        assert r["type"] == "signal_killed"

    def test_exit_code_0_no_output_is_unknown(self, diag: DiagnosticsHelper) -> None:
        r = diag._diagnose_error("", 0)
        assert r["type"] == "unknown"
