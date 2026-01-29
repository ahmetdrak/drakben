"""Tests for C2 Framework module"""
import unittest
import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.c2_framework import (
    C2Protocol,
    BeaconStatus,
    C2Config,
    BeaconMessage,
    BeaconResponse,
    JitterEngine,
    DomainFronter,
    DNSTunneler,
    HeartbeatManager,
    C2Channel,
    get_c2_channel,
    create_fronted_channel,
    create_dns_channel,
    DEFAULT_SLEEP_INTERVAL,
    DEFAULT_JITTER_MIN,
    DEFAULT_JITTER_MAX,
)


class TestJitterEngine(unittest.TestCase):
    """Test timing jitter functionality"""
    
    def test_initialization(self):
        """Test jitter engine initialization"""
        jitter = JitterEngine(60, 10, 25)
        self.assertEqual(jitter.base_interval, 60)
        self.assertEqual(jitter.jitter_min, 10)
        self.assertEqual(jitter.jitter_max, 25)
    
    def test_default_values(self):
        """Test default jitter values"""
        jitter = JitterEngine()
        self.assertEqual(jitter.base_interval, DEFAULT_SLEEP_INTERVAL)
        self.assertEqual(jitter.jitter_min, DEFAULT_JITTER_MIN)
        self.assertEqual(jitter.jitter_max, DEFAULT_JITTER_MAX)
    
    def test_sleep_time_in_range(self):
        """Test that sleep time is within expected range"""
        jitter = JitterEngine(100, 10, 20)
        
        for _ in range(100):
            sleep_time = jitter.get_sleep_time()
            # Base ± 20% = 80-120
            self.assertGreaterEqual(sleep_time, 1.0)  # Minimum 1 second
            self.assertLessEqual(sleep_time, 120.0)
    
    def test_sleep_time_randomness(self):
        """Test that sleep times vary (not always the same)"""
        jitter = JitterEngine(60, 10, 25)
        
        times = [jitter.get_sleep_time() for _ in range(10)]
        unique_times = set(times)
        
        # Should have variation
        self.assertGreater(len(unique_times), 1)
    
    def test_update_interval(self):
        """Test interval update"""
        jitter = JitterEngine(60)
        jitter.update_interval(120)
        self.assertEqual(jitter.base_interval, 120)
    
    def test_minimum_interval(self):
        """Test that interval cannot go below 1"""
        jitter = JitterEngine(60)
        jitter.update_interval(0)
        self.assertEqual(jitter.base_interval, 1)


class TestDomainFronter(unittest.TestCase):
    """Test domain fronting functionality"""
    
    def setUp(self):
        self.fronter = DomainFronter(
            fronting_domain="cdn.example.com",
            actual_host="c2.hidden.com",
            port=443,
            verify_ssl=False
        )
    
    def test_initialization(self):
        """Test fronter initialization"""
        self.assertEqual(self.fronter.fronting_domain, "cdn.example.com")
        self.assertEqual(self.fronter.actual_host, "c2.hidden.com")
        self.assertEqual(self.fronter.port, 443)
    
    def test_create_request(self):
        """Test request creation with correct headers"""
        request = self.fronter.create_request(
            endpoint="/api/beacon",
            method="POST"
        )
        
        # Host header should be actual target
        self.assertEqual(request.get_header("Host"), "c2.hidden.com")
        self.assertIn("User-agent", request.headers)
    
    def test_is_domain_frontable(self):
        """Test frontable domain detection"""
        self.assertTrue(DomainFronter.is_domain_frontable("abc.cloudfront.net"))
        self.assertTrue(DomainFronter.is_domain_frontable("x.azureedge.net"))
        self.assertFalse(DomainFronter.is_domain_frontable("example.com"))


class TestDNSTunneler(unittest.TestCase):
    """Test DNS tunneling functionality"""
    
    def setUp(self):
        self.tunneler = DNSTunneler(
            c2_domain="beacon.example.com",
            subdomain_length=32
        )
    
    def test_initialization(self):
        """Test tunneler initialization"""
        self.assertEqual(self.tunneler.c2_domain, "beacon.example.com")
        self.assertEqual(self.tunneler.subdomain_length, 32)
    
    def test_encode_decode_roundtrip(self):
        """Test data encoding/decoding roundtrip"""
        original = b"Hello, World!"
        
        labels = self.tunneler.encode_data(original)
        decoded = self.tunneler.decode_data(labels)
        
        self.assertEqual(decoded, original)
    
    def test_encode_binary_data(self):
        """Test encoding binary data"""
        binary = bytes(range(256))
        
        labels = self.tunneler.encode_data(binary)
        decoded = self.tunneler.decode_data(labels)
        
        self.assertEqual(decoded, binary)
    
    def test_build_query(self):
        """Test DNS query building"""
        data = b"test"
        query = self.tunneler.build_query(data, "checkin")
        
        self.assertTrue(query.endswith(".beacon.example.com"))
        self.assertIn("checkin", query)
    
    def test_chunk_data(self):
        """Test data chunking"""
        data = b"A" * 250
        chunks = self.tunneler.chunk_data(data, 100)
        
        self.assertEqual(len(chunks), 3)
        self.assertEqual(b"".join(chunks), data)
    
    def test_label_length_limit(self):
        """Test that labels respect DNS limits"""
        data = b"A" * 100
        labels = self.tunneler.encode_data(data)
        
        for label in labels:
            self.assertLessEqual(len(label), 63)


class TestHeartbeatManager(unittest.TestCase):
    """Test heartbeat manager functionality"""
    
    def setUp(self):
        self.config = C2Config(
            sleep_interval=1,  # 1 second for fast testing
            jitter_min=0,
            jitter_max=0  # No jitter for predictable tests
        )
        self.callback_count = 0
        self.manager = HeartbeatManager(
            self.config,
            callback=self._test_callback
        )
    
    def _test_callback(self):
        self.callback_count += 1
    
    def tearDown(self):
        if self.manager._running:
            self.manager.stop()
    
    def test_initialization(self):
        """Test heartbeat initialization"""
        self.assertFalse(self.manager._running)
        self.assertIsNone(self.manager._last_checkin)
    
    def test_get_status(self):
        """Test status retrieval"""
        status = self.manager.get_status()
        
        self.assertIn("running", status)
        self.assertIn("last_checkin", status)
        self.assertIn("interval", status)
        self.assertIn("jitter_range", status)
    
    def test_start_stop(self):
        """Test starting and stopping heartbeat"""
        self.manager.start()
        self.assertTrue(self.manager._running)
        
        self.manager.stop()
        self.assertFalse(self.manager._running)
    
    def test_update_interval(self):
        """Test interval update"""
        self.manager.update_interval(120)
        self.assertEqual(self.manager.jitter.base_interval, 120)


class TestC2Config(unittest.TestCase):
    """Test C2 configuration"""
    
    def test_default_values(self):
        """Test default configuration"""
        config = C2Config()
        
        self.assertEqual(config.protocol, C2Protocol.HTTPS)
        self.assertEqual(config.primary_port, 443)
        self.assertEqual(config.sleep_interval, DEFAULT_SLEEP_INTERVAL)
    
    def test_custom_values(self):
        """Test custom configuration"""
        config = C2Config(
            protocol=C2Protocol.DNS,
            primary_host="c2.example.com",
            sleep_interval=120,
            dns_domain="tunnel.example.com"
        )
        
        self.assertEqual(config.protocol, C2Protocol.DNS)
        self.assertEqual(config.dns_domain, "tunnel.example.com")


class TestBeaconMessage(unittest.TestCase):
    """Test beacon message structures"""
    
    def test_message_creation(self):
        """Test message creation"""
        msg = BeaconMessage(
            message_id="abc123",
            command="checkin",
            data={"status": "alive"}
        )
        
        self.assertEqual(msg.message_id, "abc123")
        self.assertEqual(msg.command, "checkin")
        self.assertIsNotNone(msg.timestamp)
    
    def test_response_creation(self):
        """Test response creation"""
        resp = BeaconResponse(
            success=True,
            message_id="abc123",
            command="sleep",
            data={"interval": 120}
        )
        
        self.assertTrue(resp.success)
        self.assertEqual(resp.command, "sleep")


class TestC2Channel(unittest.TestCase):
    """Test main C2 channel"""
    
    def setUp(self):
        self.config = C2Config(
            protocol=C2Protocol.HTTPS,
            primary_host="127.0.0.1",
            primary_port=443
        )
        self.channel = C2Channel(self.config)
    
    def test_initialization(self):
        """Test channel initialization"""
        self.assertEqual(self.channel.status, BeaconStatus.DORMANT)
        self.assertIsNotNone(self.channel.encryption_key)
    
    def test_get_status(self):
        """Test status retrieval"""
        status = self.channel.get_status()
        
        self.assertIn("status", status)
        self.assertIn("protocol", status)
        self.assertIn("primary_host", status)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption/decryption"""
        original = b"Secret message"
        
        encrypted = self.channel._encrypt(original)
        decrypted = self.channel._decrypt(encrypted)
        
        self.assertEqual(decrypted, original)
    
    def test_generate_id(self):
        """Test ID generation uniqueness"""
        ids = [self.channel._generate_id() for _ in range(100)]
        unique_ids = set(ids)
        
        # All IDs should be unique
        self.assertEqual(len(ids), len(unique_ids))


class TestModuleFunctions(unittest.TestCase):
    """Test module-level functions"""
    
    def test_create_fronted_channel(self):
        """Test fronted channel creation"""
        channel = create_fronted_channel(
            fronting_domain="cdn.example.com",
            actual_host="c2.hidden.com"
        )
        
        self.assertIsNotNone(channel)
        self.assertIsNotNone(channel.domain_fronter)
    
    def test_create_dns_channel(self):
        """Test DNS channel creation"""
        channel = create_dns_channel(
            c2_domain="tunnel.example.com"
        )
        
        self.assertIsNotNone(channel)
        self.assertEqual(channel.config.protocol, C2Protocol.DNS)


class TestEnums(unittest.TestCase):
    """Test enum definitions"""
    
    def test_c2_protocol_values(self):
        """Test C2Protocol enum"""
        self.assertEqual(C2Protocol.HTTP.value, "http")
        self.assertEqual(C2Protocol.HTTPS.value, "https")
        self.assertEqual(C2Protocol.DNS.value, "dns")
    
    def test_beacon_status_values(self):
        """Test BeaconStatus enum"""
        self.assertEqual(BeaconStatus.DORMANT.value, "dormant")
        self.assertEqual(BeaconStatus.ACTIVE.value, "active")
        self.assertEqual(BeaconStatus.ERROR.value, "error")


if __name__ == "__main__":
    unittest.main()
