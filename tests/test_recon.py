# tests/test_recon.py
"""Tests for modules/recon.py - Reconnaissance module test suite."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from modules.recon import (
    AsyncRetry,
    ReconError,
    extract_domain,
    fetch_url,
    passive_recon,
)

# Suppress coroutine warnings from AsyncMock in these tests
pytestmark = pytest.mark.filterwarnings(
    "ignore:coroutine.*was never awaited:RuntimeWarning"
)

# =============================================================================
# ReconError Tests
# =============================================================================


class TestReconError:
    """Test ReconError exception class."""

    def test_exception_message(self):
        """Test exception message."""
        with pytest.raises(ReconError, match="Test error"):
            raise ReconError("Test error")

    def test_exception_inheritance(self):
        """Test exception inherits from Exception."""
        assert issubclass(ReconError, Exception)


# =============================================================================
# AsyncRetry Tests
# =============================================================================


class TestAsyncRetry:
    """Test AsyncRetry decorator."""

    def test_init_default_values(self):
        """Test default values."""
        retry = AsyncRetry()
        assert retry.max_retries == 3
        assert retry.base_delay == pytest.approx(1.0)

    def test_init_custom_values(self):
        """Test custom values."""
        retry = AsyncRetry(max_retries=5, base_delay=2.0)
        assert retry.max_retries == 5
        assert retry.base_delay == pytest.approx(2.0)

    @pytest.mark.asyncio
    async def test_success_no_retry(self):
        """Test successful function doesn't retry."""
        call_count = 0

        @AsyncRetry(max_retries=3, base_delay=0.01)
        async def success_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await success_func()
        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_timeout(self):
        """Test retry on TimeoutError."""
        call_count = 0

        @AsyncRetry(max_retries=3, base_delay=0.01)
        async def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("timeout")
            return "success"

        result = await flaky_func()
        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_exhausted(self):
        """Test exception raised after retries exhausted."""
        @AsyncRetry(max_retries=2, base_delay=0.01)
        async def always_fails():
            raise TimeoutError("always fails")

        with pytest.raises(TimeoutError):
            await always_fails()


# =============================================================================
# extract_domain Tests
# =============================================================================


class TestExtractDomain:
    """Test domain extraction function."""

    def test_extract_from_http_url(self):
        """Test domain extraction from HTTP URL."""
        assert extract_domain("http://example.com/path") == "example.com"

    def test_extract_from_https_url(self):
        """Test domain extraction from HTTPS URL."""
        assert extract_domain("https://secure.example.com") == "secure.example.com"

    def test_extract_with_port(self):
        """Test domain extraction removes port."""
        assert extract_domain("http://example.com:8080/path") == "example.com"

    def test_extract_with_subdomain(self):
        """Test domain extraction with subdomain."""
        assert extract_domain("https://sub.domain.example.com") == "sub.domain.example.com"

    def test_extract_bare_domain(self):
        """Test domain extraction from bare domain."""
        assert extract_domain("example.com") == "example.com"

    def test_extract_ip_address(self):
        """Test domain extraction from IP address."""
        assert extract_domain("http://192.168.1.1/page") == "192.168.1.1"

    def test_extract_ip_with_port(self):
        """Test domain extraction from IP with port."""
        assert extract_domain("http://192.168.1.1:8080") == "192.168.1.1"


# =============================================================================
# fetch_url Tests
# =============================================================================


class TestFetchUrl:
    """Test URL fetching function."""

    @pytest.mark.asyncio
    async def test_fetch_success(self):
        """Test successful URL fetch."""

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = AsyncMock(return_value="<html>test</html>")

        mock_session = MagicMock()
        mock_context = AsyncMock()
        mock_context.__aenter__.return_value = mock_response
        mock_session.get.return_value = mock_context

        result = await fetch_url(mock_session, "http://example.com")

        assert result["status"] == 200
        assert result["error"] is None
        assert "Content-Type" in result["headers"]

    @pytest.mark.asyncio
    async def test_fetch_timeout(self):
        """Test URL fetch timeout handling."""

        mock_session = MagicMock()
        mock_session.get.side_effect = TimeoutError()

        result = await fetch_url(mock_session, "http://slow.example.com")

        assert result["status"] == 0
        assert result["error"] is not None
        assert "timeout" in result["error"].lower() or result["error"]

    @pytest.mark.asyncio
    async def test_fetch_client_error(self):
        """Test URL fetch client error handling."""
        import aiohttp

        mock_session = MagicMock()
        mock_session.get.side_effect = aiohttp.ClientError("Connection refused")

        result = await fetch_url(mock_session, "http://unreachable.com")

        assert result["status"] == 0
        assert result["error"] is not None


# =============================================================================
# passive_recon Tests
# =============================================================================


class TestPassiveRecon:
    """Test passive reconnaissance function."""

    @pytest.fixture
    def mock_state(self):
        """Create mock AgentState."""
        state = MagicMock()
        state.target = None
        state.open_services = []
        return state

    @pytest.mark.asyncio
    async def test_passive_recon_basic(self):
        """Test basic passive recon without state."""
        with patch("modules.recon.aiohttp.ClientSession") as mock_session_class:
            # Create proper async context manager chain
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {"Server": "Apache"}
            mock_resp.text = AsyncMock(return_value="<html></html>")

            # session.get() returns an async context manager
            mock_get_cm = AsyncMock()
            mock_get_cm.__aenter__.return_value = mock_resp
            mock_get_cm.__aexit__.return_value = None

            mock_session = AsyncMock()
            mock_session.get.return_value = mock_get_cm

            # ClientSession() returns an async context manager
            mock_session_cm = AsyncMock()
            mock_session_cm.__aenter__.return_value = mock_session
            mock_session_cm.__aexit__.return_value = None
            mock_session_class.return_value = mock_session_cm

            result = await passive_recon("http://example.com", state=None)

            assert isinstance(result, dict)
            assert "target" in result

    @pytest.mark.asyncio
    async def test_passive_recon_cached(self, mock_state):
        """Test passive recon with cached results."""
        mock_state.target = "http://example.com"
        mock_state.open_services = [80, 443]

        result = await passive_recon("http://example.com", state=mock_state)

        assert result.get("cached") is True
        assert result.get("cached_services") == 2

    @pytest.mark.asyncio
    async def test_passive_recon_new_target(self, mock_state):
        """Test passive recon with new target."""
        mock_state.target = "http://other.com"
        mock_state.open_services = []

        with patch("modules.recon.aiohttp.ClientSession") as mock_session_class:
            # Create proper async context manager chain
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.headers = {}
            mock_resp.text = AsyncMock(return_value="")

            mock_get_cm = AsyncMock()
            mock_get_cm.__aenter__.return_value = mock_resp
            mock_get_cm.__aexit__.return_value = None

            mock_session = AsyncMock()
            mock_session.get.return_value = mock_get_cm

            mock_session_cm = AsyncMock()
            mock_session_cm.__aenter__.return_value = mock_session
            mock_session_cm.__aexit__.return_value = None
            mock_session_class.return_value = mock_session_cm

            result = await passive_recon("http://example.com", state=mock_state)

            assert isinstance(result, dict)
            # Should not be cached since target is different
            assert result.get("cached") is not True


# =============================================================================
# Integration Tests
# =============================================================================


class TestReconIntegration:
    """Integration tests for recon module."""

    def test_module_imports(self):
        """Test that module imports correctly."""
        from modules import recon

        assert hasattr(recon, "passive_recon")
        assert hasattr(recon, "extract_domain")
        assert hasattr(recon, "fetch_url")
        assert hasattr(recon, "ReconError")
        assert hasattr(recon, "AsyncRetry")

    def test_dns_availability_flag(self):
        """Test DNS availability flag exists."""
        from modules import recon

        assert hasattr(recon, "DNS_AVAILABLE")
        assert isinstance(recon.DNS_AVAILABLE, bool)

    def test_whois_availability_flag(self):
        """Test WHOIS availability flag exists."""
        from modules import recon

        assert hasattr(recon, "WHOIS_AVAILABLE")
        assert isinstance(recon.WHOIS_AVAILABLE, bool)


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_extract_domain_empty_string(self):
        """Test domain extraction with empty string."""
        result = extract_domain("")
        assert result == ""

    def test_extract_domain_invalid_url(self):
        """Test domain extraction with invalid URL."""
        # Should not raise, just return what it can
        result = extract_domain("not-a-valid-url")
        assert isinstance(result, str)

    def test_extract_domain_with_path_only(self):
        """Test domain extraction with path only."""
        result = extract_domain("/path/to/resource")
        assert isinstance(result, str)

    def test_recon_error_with_cause(self):
        """Test ReconError with cause."""
        try:
            try:
                raise ValueError("Original error")
            except ValueError as e:
                raise ReconError("Wrapped error") from e
        except ReconError as e:
            assert "Wrapped" in str(e)
            assert e.__cause__ is not None
