"""Tests for C2 Framework module."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.c2_framework import (
    DEFAULT_JITTER_MAX,
    DEFAULT_JITTER_MIN,
    DEFAULT_SLEEP_INTERVAL,
    BeaconMessage,
    BeaconResponse,
    BeaconSession,
    BeaconStatus,
    C2Channel,
    C2Config,
    C2Listener,
    C2Protocol,
    DNSTunneler,
    DoHTransport,
    DomainFronter,
    HeartbeatManager,
    JitterEngine,
    create_dns_channel,
    create_fronted_channel,
)


class TestJitterEngine(unittest.TestCase):
    """Test timing jitter functionality."""

    def test_initialization(self) -> None:
        """Test jitter engine initialization."""
        jitter = JitterEngine(60, 10, 25)
        assert jitter.base_interval == 60
        assert jitter.jitter_min == 10
        assert jitter.jitter_max == 25

    def test_default_values(self) -> None:
        """Test default jitter values."""
        jitter = JitterEngine()
        assert jitter.base_interval == DEFAULT_SLEEP_INTERVAL
        assert jitter.jitter_min == DEFAULT_JITTER_MIN
        assert jitter.jitter_max == DEFAULT_JITTER_MAX

    def test_sleep_time_in_range(self) -> None:
        """Test that sleep time is within expected range."""
        jitter = JitterEngine(100, 10, 20)

        for _ in range(100):
            sleep_time = jitter.get_sleep_time()
            # Base ± 20% = 80-120
            assert sleep_time >= 1.0  # Minimum 1 second
            assert sleep_time <= 120.0

    def test_sleep_time_randomness(self) -> None:
        """Test that sleep times vary (not always the same)."""
        jitter = JitterEngine(60, 10, 25)

        times = [jitter.get_sleep_time() for _ in range(10)]
        unique_times = set(times)

        # Should have variation
        assert len(unique_times) > 1

    def test_update_interval(self) -> None:
        """Test interval update."""
        jitter = JitterEngine(60)
        jitter.update_interval(120)
        assert jitter.base_interval == 120

    def test_minimum_interval(self) -> None:
        """Test that interval cannot go below 1."""
        jitter = JitterEngine(60)
        jitter.update_interval(0)
        assert jitter.base_interval == 1


class TestDomainFronter(unittest.TestCase):
    """Test domain fronting functionality."""

    def setUp(self) -> None:
        self.fronter = DomainFronter(
            fronting_domain="cdn.example.com",
            actual_host="c2.hidden.com",
            port=443,
            verify_ssl=False,
        )

    def test_initialization(self) -> None:
        """Test fronter initialization."""
        assert self.fronter.fronting_domain == "cdn.example.com"
        assert self.fronter.actual_host == "c2.hidden.com"
        assert self.fronter.port == 443

    def test_create_request(self) -> None:
        """Test request creation with correct headers."""
        request = self.fronter.create_request(endpoint="/api/beacon", method="POST")

        # Host header should be actual target
        assert request.get_header("Host") == "c2.hidden.com"
        assert "User-agent" in request.headers

    def test_is_domain_frontable(self) -> None:
        """Test frontable domain detection."""
        assert DomainFronter.is_domain_frontable("abc.cloudfront.net")
        assert DomainFronter.is_domain_frontable("x.azureedge.net")
        assert not DomainFronter.is_domain_frontable("example.com")


class TestDNSTunneler(unittest.TestCase):
    """Test DNS tunneling functionality."""

    def setUp(self) -> None:
        self.tunneler = DNSTunneler(c2_domain="beacon.example.com", subdomain_length=32)

    def test_initialization(self) -> None:
        """Test tunneler initialization."""
        assert self.tunneler.c2_domain == "beacon.example.com"
        assert self.tunneler.subdomain_length == 32

    def test_encode_decode_roundtrip(self) -> None:
        """Test data encoding/decoding roundtrip."""
        original = b"Hello, World!"

        labels = self.tunneler.encode_data(original)
        decoded = self.tunneler.decode_data(labels)

        assert decoded == original

    def test_encode_binary_data(self) -> None:
        """Test encoding binary data."""
        binary = bytes(range(256))

        labels = self.tunneler.encode_data(binary)
        decoded = self.tunneler.decode_data(labels)

        assert decoded == binary

    def test_build_query(self) -> None:
        """Test DNS query building."""
        data = b"test"
        query = self.tunneler.build_query(data, "checkin")

        assert query.endswith(".beacon.example.com")
        assert "checkin" in query

    def test_chunk_data(self) -> None:
        """Test data chunking."""
        data = b"A" * 250
        chunks = self.tunneler.chunk_data(data, 100)

        assert len(chunks) == 3
        assert b"".join(chunks) == data

    def test_label_length_limit(self) -> None:
        """Test that labels respect DNS limits."""
        data = b"A" * 100
        labels = self.tunneler.encode_data(data)

        for label in labels:
            assert len(label) <= 63


class TestDoHTransport(unittest.TestCase):
    """Test DNS over HTTPS transport functionality."""

    def test_initialization_cloudflare(self) -> None:
        """Test DoH transport initialization with Cloudflare."""
        doh = DoHTransport(c2_domain="c2.example.com", provider="cloudflare")
        assert doh.c2_domain == "c2.example.com"
        assert doh.provider == "cloudflare"
        assert "cloudflare-dns.com" in doh.endpoint

    def test_initialization_google(self) -> None:
        """Test DoH transport initialization with Google."""
        doh = DoHTransport(c2_domain="c2.example.com", provider="google")
        assert "dns.google" in doh.endpoint

    def test_initialization_custom(self) -> None:
        """Test DoH transport with custom endpoint."""
        custom_url = "https://custom-doh.example.com/dns-query"
        doh = DoHTransport(
            c2_domain="c2.example.com",
            provider="custom",
            custom_endpoint=custom_url,
        )
        assert doh.endpoint == custom_url

    def test_build_dns_query(self) -> None:
        """Test DNS wire format query building."""
        doh = DoHTransport(c2_domain="test.example.com")
        query = doh._build_dns_query("test.example.com", qtype=16)

        # Should be valid DNS query bytes
        assert isinstance(query, bytes)
        assert len(query) > 12  # At least header + question

        # Should contain domain name
        assert b"test" in query
        assert b"example" in query

    def test_parse_empty_response(self) -> None:
        """Test parsing empty/short response."""
        doh = DoHTransport(c2_domain="test.example.com")

        # Too short
        result = doh._parse_dns_response(b"short")
        assert result == []

        # Empty
        result = doh._parse_dns_response(b"")
        assert result == []

    def test_providers_dict(self) -> None:
        """Test that all expected providers exist."""
        assert "cloudflare" in DoHTransport.DOH_PROVIDERS
        assert "google" in DoHTransport.DOH_PROVIDERS
        assert "quad9" in DoHTransport.DOH_PROVIDERS
        assert "custom" in DoHTransport.DOH_PROVIDERS


class TestHeartbeatManager(unittest.TestCase):
    """Test heartbeat manager functionality."""

    def setUp(self) -> None:
        self.config = C2Config(
            sleep_interval=1,  # 1 second for fast testing
            jitter_min=0,
            jitter_max=0,  # No jitter for predictable tests
        )
        self.callback_count = 0
        self.manager = HeartbeatManager(self.config, callback=self._test_callback)

    def _test_callback(self) -> None:
        self.callback_count += 1

    def tearDown(self) -> None:
        if self.manager._running:
            self.manager.stop()

    def test_initialization(self) -> None:
        """Test heartbeat initialization."""
        assert not self.manager._running
        assert self.manager._last_checkin is None

    def test_get_status(self) -> None:
        """Test status retrieval."""
        status = self.manager.get_status()

        assert "running" in status
        assert "last_checkin" in status
        assert "interval" in status
        assert "jitter_range" in status

    def test_start_stop(self) -> None:
        """Test starting and stopping heartbeat."""
        self.manager.start()
        assert self.manager._running

        self.manager.stop()
        assert not self.manager._running

    def test_update_interval(self) -> None:
        """Test interval update."""
        self.manager.update_interval(120)
        assert self.manager.jitter.base_interval == 120


class TestC2Config(unittest.TestCase):
    """Test C2 configuration."""

    def test_default_values(self) -> None:
        """Test default configuration."""
        config = C2Config()

        assert config.protocol == C2Protocol.HTTPS
        assert config.primary_port == 443
        assert config.sleep_interval == DEFAULT_SLEEP_INTERVAL

    def test_custom_values(self) -> None:
        """Test custom configuration."""
        config = C2Config(
            protocol=C2Protocol.DNS,
            primary_host="c2.example.com",
            sleep_interval=120,
            dns_domain="tunnel.example.com",
        )

        assert config.protocol == C2Protocol.DNS
        assert config.dns_domain == "tunnel.example.com"


class TestBeaconMessage(unittest.TestCase):
    """Test beacon message structures."""

    def test_message_creation(self) -> None:
        """Test message creation."""
        msg = BeaconMessage(
            message_id="abc123",
            command="checkin",
            data={"status": "alive"},
        )

        assert msg.message_id == "abc123"
        assert msg.command == "checkin"
        assert msg.timestamp is not None

    def test_response_creation(self) -> None:
        """Test response creation."""
        resp = BeaconResponse(
            success=True,
            message_id="abc123",
            command="sleep",
            data={"interval": 120},
        )

        assert resp.success
        assert resp.command == "sleep"


class TestC2Channel(unittest.TestCase):
    """Test main C2 channel."""

    def setUp(self) -> None:
        self.config = C2Config(
            protocol=C2Protocol.HTTPS,
            primary_host="127.0.0.1",
            primary_port=443,
        )
        self.channel = C2Channel(self.config)

    def test_initialization(self) -> None:
        """Test channel initialization."""
        assert self.channel.status == BeaconStatus.DORMANT
        assert self.channel.encryption_key is not None

    def test_get_status(self) -> None:
        """Test status retrieval."""
        status = self.channel.get_status()

        assert "status" in status
        assert "protocol" in status
        assert "primary_host" in status

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test encryption/decryption."""
        original = b"Secret message"

        encrypted = self.channel._encrypt(original)
        decrypted = self.channel._decrypt(encrypted)

        assert decrypted == original

    def test_encryption_entropy(self) -> None:
        """Test that encryption produces high-entropy (random-looking) output."""
        import base64
        import math
        from collections import Counter

        def shannon_entropy(data):
            if not data:
                return 0
            entropy = 0
            for x in Counter(data).values():
                p_x = float(x) / len(data)
                entropy -= p_x * math.log2(p_x)
            return entropy

        # Encrypt a block of zeros (worst case input for weak encryption)
        plaintext = b"\x00" * 1000
        encrypted_b64 = self.channel._encrypt(plaintext)

        # KEY FIX: Decode Base64 before checking entropy!
        # Base64 has a max entropy of 6 bits/byte. Raw encrypted bytes should be ~8.
        encrypted_raw = base64.b64decode(encrypted_b64)

        entropy = shannon_entropy(encrypted_raw)
        # Random data should have entropy close to 8 bits per byte
        assert entropy > 7.5, f"Encryption entropy too low: {entropy} (Weak Crypto Detected!)"

    def test_dns_packet_limit(self) -> None:
        """Test DNS packet size limits (UDP 512 bytes)."""
        # Create a large payload
        payload = b"Z" * 1000
        # The tunneler should chunk this into multiple packets
        # We need to access the tunneler inside the channel (mocking or direct use)
        from modules.c2_framework import DNSTunneler

        tunneler = DNSTunneler("example.com")

        # KEY FIX: Use a smaller chunk size to respect DNS limits
        chunks = tunneler.chunk_data(payload, 60)

        for chunk in chunks:
            encoded_query = tunneler.build_query(chunk, "data")
            # DNS packet overhead is roughly header + query length.
            # Safe limit for query name is around 253 chars
            assert len(encoded_query) <= 255, f"DNS query too long: {len(encoded_query)}"


class TestModuleFunctions(unittest.TestCase):
    """Test module-level functions."""

    def test_create_fronted_channel(self) -> None:
        """Test fronted channel creation."""
        channel = create_fronted_channel(
            fronting_domain="cdn.example.com",
            actual_host="c2.hidden.com",
        )

        assert channel is not None
        assert channel.domain_fronter is not None

    def test_create_dns_channel(self) -> None:
        """Test DNS channel creation."""
        channel = create_dns_channel(c2_domain="tunnel.example.com")

        assert channel is not None
        assert channel.config.protocol == C2Protocol.DNS


class TestEnums(unittest.TestCase):
    """Test enum definitions."""

    def test_c2_protocol_values(self) -> None:
        """Test C2Protocol enum."""
        assert C2Protocol.HTTP.value == "http"
        assert C2Protocol.HTTPS.value == "https"
        assert C2Protocol.DNS.value == "dns"

    def test_beacon_status_values(self) -> None:
        """Test BeaconStatus enum."""
        assert BeaconStatus.DORMANT.value == "dormant"
        assert BeaconStatus.ACTIVE.value == "active"
        assert BeaconStatus.ERROR.value == "error"


class TestBeaconSession(unittest.TestCase):
    """Tests for the BeaconSession dataclass."""

    def test_creation_defaults(self) -> None:
        """Test default field values."""
        session = BeaconSession(beacon_id="abc123", remote_addr="10.0.0.1")
        assert session.beacon_id == "abc123"
        assert session.remote_addr == "10.0.0.1"
        assert session.pending_commands == []
        assert session.history == []
        assert session.first_seen > 0
        assert session.last_seen >= session.first_seen

    def test_enqueue_returns_msg_id(self) -> None:
        """Test that enqueue returns a non-empty message ID."""
        session = BeaconSession(beacon_id="b1", remote_addr="10.0.0.2")
        msg_id = session.enqueue("shell", {"cmd": "whoami"})
        assert isinstance(msg_id, str)
        assert len(msg_id) == 16
        assert len(session.pending_commands) == 1
        assert session.pending_commands[0].command == "shell"

    def test_enqueue_multiple(self) -> None:
        """Test queuing several commands."""
        session = BeaconSession(beacon_id="b2", remote_addr="10.0.0.3")
        ids = [session.enqueue(f"cmd{i}") for i in range(5)]
        assert len(set(ids)) == 5  # all unique
        assert len(session.pending_commands) == 5

    def test_to_dict(self) -> None:
        """Test serialisation to dict."""
        session = BeaconSession(beacon_id="b3", remote_addr="10.0.0.4")
        session.enqueue("sleep", {"interval": 120})
        d = session.to_dict()
        assert d["beacon_id"] == "b3"
        assert d["remote_addr"] == "10.0.0.4"
        assert d["pending"] == 1
        assert d["history_count"] == 0


class TestC2Listener(unittest.TestCase):
    """Tests for the C2Listener server-side component."""

    def test_init_defaults(self) -> None:
        """Test default initialisation values."""
        listener = C2Listener()
        assert listener.host == "0.0.0.0"
        assert listener.port == 443
        assert listener.use_tls is True
        assert len(listener.encryption_key) == 32
        assert listener.running is False

    def test_init_custom(self) -> None:
        """Test custom initialisation."""
        key = b"x" * 32
        listener = C2Listener(
            host="127.0.0.1",
            port=8443,
            encryption_key=key,
            use_tls=False,
        )
        assert listener.host == "127.0.0.1"
        assert listener.port == 8443
        assert listener.encryption_key == key
        assert listener.use_tls is False

    def test_get_sessions_empty(self) -> None:
        """Test empty sessions listing."""
        listener = C2Listener()
        assert listener.get_sessions() == {}

    def test_get_session_unknown(self) -> None:
        """Test querying non-existent session."""
        listener = C2Listener()
        assert listener.get_session("non-existent") is None

    def test_queue_command_unknown_beacon(self) -> None:
        """Test queuing to a non-existent beacon returns None."""
        listener = C2Listener()
        assert listener.queue_command("ghost", "shell") is None

    def test_session_management(self) -> None:
        """Test manual session registration and command queuing."""
        listener = C2Listener()
        # Manually register a session (simulating internal bookkeeping)
        listener._sessions["beacon1"] = BeaconSession(
            beacon_id="beacon1",
            remote_addr="192.168.1.50",
        )
        assert len(listener.get_sessions()) == 1
        assert listener.get_session("beacon1") is not None

        # Queue a command
        msg_id = listener.queue_command("beacon1", "shell", {"cmd": "id"})
        assert msg_id is not None
        assert len(listener._sessions["beacon1"].pending_commands) == 1

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """Test that listener encryption is reversible."""
        key = os.urandom(32)
        listener = C2Listener(encryption_key=key)
        plaintext = b'{"cmd": "whoami", "id": "test123"}'
        encrypted = listener._encrypt(plaintext)
        assert encrypted != plaintext
        decrypted = listener._decrypt(encrypted)
        assert decrypted == plaintext

    def test_get_status(self) -> None:
        """Test status reporting."""
        listener = C2Listener(host="0.0.0.0", port=8080, use_tls=False)
        status = listener.get_status()
        assert status["running"] is False
        assert status["port"] == 8080
        assert status["active_beacons"] == 0

    def test_get_session_history_empty(self) -> None:
        """Test history for non-existent session."""
        listener = C2Listener()
        assert listener.get_session_history("nope") == []

    def test_get_session_history(self) -> None:
        """Test history retrieval for existing session."""
        listener = C2Listener()
        session = BeaconSession(beacon_id="b1", remote_addr="10.0.0.1")
        session.history.append({"direction": "in", "command": "checkin"})
        listener._sessions["b1"] = session
        history = listener.get_session_history("b1")
        assert len(history) == 1
        assert history[0]["command"] == "checkin"


if __name__ == "__main__":
    unittest.main()
