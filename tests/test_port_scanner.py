# tests/test_port_scanner.py
"""Tests for the native port scanner in modules/recon.py."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules.recon import (
    _get_common_ports,
    _guess_service,
    scan_ports,
    scan_ports_sync,
)

# ── _guess_service ─────────────────────────────────────────────

class TestGuessService:
    """Tests for the port-to-service mapping helper."""

    @pytest.mark.parametrize(
        ("port", "expected"),
        [
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "dns"),
            (80, "http"),
            (110, "pop3"),
            (135, "msrpc"),
            (143, "imap"),
            (389, "ldap"),
            (443, "https"),
            (445, "smb"),
            (587, "submission"),
            (993, "imaps"),
            (1433, "mssql"),
            (1521, "oracle"),
            (3306, "mysql"),
            (3389, "rdp"),
            (5432, "postgresql"),
            (5900, "vnc"),
            (6379, "redis"),
            (6443, "kubernetes"),
            (8080, "http-proxy"),
            (8443, "https-alt"),
            (9200, "elasticsearch"),
            (27017, "mongodb"),
        ],
    )
    def test_known_ports(self, port: int, expected: str) -> None:
        assert _guess_service(port) == expected

    def test_unknown_port(self) -> None:
        assert _guess_service(55_555) == "unknown"

    def test_zero_port(self) -> None:
        assert _guess_service(0) == "unknown"


# ── _get_common_ports ──────────────────────────────────────────

class TestGetCommonPorts:
    """Tests for the common ports list helper."""

    def test_returns_list(self) -> None:
        ports = _get_common_ports()
        assert isinstance(ports, list)

    def test_length_approximately_1000(self) -> None:
        ports = _get_common_ports()
        assert 900 <= len(ports) <= 1100

    def test_contains_well_known(self) -> None:
        ports = _get_common_ports()
        for p in [22, 80, 443, 3306, 8080]:
            assert p in ports

    def test_all_positive_integers(self) -> None:
        ports = _get_common_ports()
        assert all(isinstance(p, int) and p > 0 for p in ports)

    def test_no_duplicates(self) -> None:
        ports = _get_common_ports()
        assert len(ports) == len(set(ports))


# ── scan_ports (async) ─────────────────────────────────────────

class TestScanPorts:
    """Async tests for scan_ports."""

    @pytest.mark.asyncio
    async def test_dns_resolution_failure(self) -> None:
        """Unresolvable host should return an error dict."""
        import socket

        with patch("socket.gethostbyname", side_effect=socket.gaierror("resolve fail")):
            result = await scan_ports("nonexistent.invalid", ports=[80])
        assert result["error"] == "DNS resolution failed"
        assert result["open_ports"] == []

    @pytest.mark.asyncio
    async def test_open_port_detected(self) -> None:
        """Mock an open port and verify detection."""
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.return_value = (AsyncMock(), mock_writer)
                result = await scan_ports("localhost", ports=[80], connect_timeout=0.1, concurrency=10)

        assert result["host"] == "localhost"
        assert result["ip"] == "127.0.0.1"
        assert len(result["open_ports"]) == 1
        assert result["open_ports"][0]["port"] == 80
        assert result["open_ports"][0]["service"] == "http"

    @pytest.mark.asyncio
    async def test_closed_port(self) -> None:
        """Connection refusal → port not in results."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.side_effect = ConnectionRefusedError
                result = await scan_ports("localhost", ports=[9999], connect_timeout=0.1)

        assert result["open_ports"] == []
        assert result["closed_count"] == 1

    @pytest.mark.asyncio
    async def test_timeout_port(self) -> None:
        """Timeout → port not in results."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.side_effect = TimeoutError
                result = await scan_ports("localhost", ports=[12345], connect_timeout=0.1)

        assert result["open_ports"] == []

    @pytest.mark.asyncio
    async def test_multiple_ports(self) -> None:
        """Mix of open and closed ports."""
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        async def fake_connect(host, port):
            await asyncio.sleep(0)
            if port in (22, 80):
                return (AsyncMock(), mock_writer)
            raise ConnectionRefusedError

        with patch("socket.gethostbyname", return_value="10.0.0.1"):
            with patch("asyncio.open_connection", side_effect=fake_connect):
                result = await scan_ports(
                    "example.com", ports=[22, 80, 443, 8080], connect_timeout=0.1,
                )

        assert len(result["open_ports"]) == 2
        ports_found = {p["port"] for p in result["open_ports"]}
        assert ports_found == {22, 80}
        assert result["closed_count"] == 2
        assert result["scanned_count"] == 4

    @pytest.mark.asyncio
    async def test_result_sorted_by_port(self) -> None:
        """Open ports should be returned sorted."""
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        async def fake_connect(host, port):
            await asyncio.sleep(0)
            if port in (8080, 22, 443):
                return (AsyncMock(), mock_writer)
            raise ConnectionRefusedError

        with patch("socket.gethostbyname", return_value="10.0.0.1"):
            with patch("asyncio.open_connection", side_effect=fake_connect):
                result = await scan_ports(
                    "example.com", ports=[8080, 22, 443], connect_timeout=0.1,
                )

        port_numbers = [p["port"] for p in result["open_ports"]]
        assert port_numbers == sorted(port_numbers)

    @pytest.mark.asyncio
    async def test_state_update(self) -> None:
        """When state is provided, open_services should be updated."""
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_state = MagicMock()
        mock_state.open_services = {}

        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.return_value = (AsyncMock(), mock_writer)
                with patch("modules.recon.STATE_AVAILABLE", True):
                    await scan_ports(
                        "localhost", ports=[443], connect_timeout=0.1, state=mock_state,
                    )

        assert 443 in mock_state.open_services
        assert mock_state.open_services[443] == "https"

    @pytest.mark.asyncio
    async def test_default_ports(self) -> None:
        """No ports argument → common ports used."""
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.side_effect = ConnectionRefusedError
                result = await scan_ports("localhost", connect_timeout=0.01, concurrency=50)

        assert result["scanned_count"] >= 900

    @pytest.mark.asyncio
    async def test_duration_field(self) -> None:
        """Result must have a non-negative duration."""
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.side_effect = ConnectionRefusedError
                result = await scan_ports("x.com", ports=[80], connect_timeout=0.01)

        assert "duration" in result
        assert result["duration"] >= 0


# ── scan_ports_sync ────────────────────────────────────────────

class TestScanPortsSync:
    """Tests for the synchronous wrapper."""

    def test_sync_wrapper_returns_result(self) -> None:
        with patch("socket.gethostbyname", return_value="127.0.0.1"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.side_effect = ConnectionRefusedError
                result = scan_ports_sync("localhost", ports=[80], connect_timeout=0.01)

        assert isinstance(result, dict)
        assert "open_ports" in result

    def test_sync_wrapper_matches_async(self) -> None:
        """Sync wrapper should yield same result as async version."""
        mock_writer = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
                mock_conn.return_value = (AsyncMock(), mock_writer)
                sync_result = scan_ports_sync("test.com", ports=[22], connect_timeout=0.01)

        assert sync_result["host"] == "test.com"
        assert len(sync_result["open_ports"]) == 1
