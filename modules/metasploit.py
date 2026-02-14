# modules/metasploit.py
# DRAKBEN Metasploit RPC Integration
# Automated exploitation through Metasploit Framework

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

# Optional msgpack for MSFRPC
try:
    import msgpack

    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False
    logger.info("msgpack not installed - using JSON fallback")

# Optional requests for HTTP API
try:
    import requests  # noqa: F401
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SessionType(Enum):
    """Metasploit session types."""

    SHELL = "shell"
    METERPRETER = "meterpreter"
    VNC = "vnc"
    UNKNOWN = "unknown"


class ExploitStatus(Enum):
    """Exploit execution status."""

    SUCCESS = "success"
    FAILED = "failed"
    RUNNING = "running"
    NO_SESSION = "no_session"
    ERROR = "error"


@dataclass
class MSFSession:
    """Metasploit session information."""

    session_id: int
    session_type: SessionType
    target_host: str
    target_port: int
    via_exploit: str
    via_payload: str
    username: str = ""
    info: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type.value,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "via_exploit": self.via_exploit,
            "via_payload": self.via_payload,
            "username": self.username,
            "info": self.info,
        }


@dataclass
class ExploitResult:
    """Exploit execution result."""

    status: ExploitStatus
    exploit_name: str
    target: str
    session: MSFSession | None = None
    output: str = ""
    error: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "exploit_name": self.exploit_name,
            "target": self.target,
            "session": self.session.to_dict() if self.session else None,
            "output": self.output,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }


class MetasploitRPC:
    """Metasploit RPC Client.

    Supports both MSGRPC (msgpack) and REST API.

    Usage:
        msf = MetasploitRPC()
        await msf.connect("127.0.0.1", 55553, "msf", "password")
        result = await msf.run_exploit("exploit/windows/smb/ms17_010_eternalblue", "192.168.1.100")
    """

    def __init__(self, use_ssl: bool = False) -> None:
        """Initialize Metasploit RPC client.

        Args:
            use_ssl: Use SSL for connection

        """
        self.host: str = ""
        self.port: int = 55553
        self.token: str = ""
        self.use_ssl = use_ssl
        self.connected = False
        self._session_counter = 0
        logger.info("MetasploitRPC client initialized")

    async def _try_json_rpc_auth(self, url: str, username: str, password: str) -> bool:
        """Try JSON-RPC authentication."""
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                url,
                json={"method": "auth.login", "params": [username, password]},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    return False
                data = await response.json()
                if "result" in data and "token" in data["result"]:
                    self.token = data["result"]["token"]
                    self.connected = True
                    logger.info("Connected to Metasploit RPC")
                    return True
        return False

    async def _try_msgpack_auth(self, host: str, port: int, username: str, password: str) -> bool:
        """Try msgpack RPC authentication."""
        if not MSGPACK_AVAILABLE:
            return False

        if not await self._connect_msgpack(host, port, username, password):
            return False

        try:
            ver = await self._call("core.version")
            if ver and "version" in ver:
                return True
        except Exception as e:
            logger.warning("Msgpack auth worked but RPC call failed: %s", e)
        return False

    async def connect(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "",
    ) -> bool:
        """Connect to Metasploit RPC server."""
        self.host = host
        self.port = port
        logger.info("Connecting to Metasploit RPC at %s:%s", host, port)

        try:
            protocol = "https" if self.use_ssl else "http"
            url = f"{protocol}://{host}:{port}/api/"

            if await self._try_json_rpc_auth(url, username, password):
                return True

            if await self._try_msgpack_auth(host, port, username, password):
                return True

            logger.warning("Could not connect to Metasploit RPC")
            return False

        except Exception as e:
            logger.exception("Connection error: %s", e)
            return False

    async def _connect_msgpack(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
    ) -> bool:
        """Connect using msgpack RPC (Async)."""
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10,
            )

            # Send auth request
            request = msgpack.packb(["auth.login", username, password])
            writer.write(request)
            await writer.drain()

            # Receive response
            response = await asyncio.wait_for(reader.read(65535), timeout=10)
            result = msgpack.unpackb(response, raw=False)

            if "token" in result:
                self.token = result["token"]
                self.connected = True
                # Note: We close this temporary auth socket because MSFRPC
                # usually requires a new connection per request or HTTP persistence.
                # Keeping raw socket open for RPC commands is complex
                # without a full async msgpack client implementation.
                # For now, we assume if auth works, we fallback to HTTP/HTTPS which is supported.
                return True

            return False

        except Exception as e:
            logger.exception("Msgpack RPC error: %s", e)
            return False
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug("Error closing writer: %s", e)

    async def disconnect(self) -> None:
        """Disconnect from Metasploit RPC."""
        if self.connected and self.token:
            with contextlib.suppress(Exception):
                await self._call("auth.logout", [self.token])

        self.connected = False
        self.token = ""
        logger.info("Disconnected from Metasploit RPC")

    async def _call(
        self,
        method: str,
        params: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Call RPC method.

        Args:
            method: Method name
            params: Parameters

        Returns:
            Response dictionary

        """
        if not self.connected:
            msg = "Not connected to Metasploit RPC"
            raise ConnectionError(msg)

        params = params or []

        try:
            protocol = "https" if self.use_ssl else "http"
            url = f"{protocol}://{self.host}:{self.port}/api/"

            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    url,
                    json={"method": method, "token": self.token, "params": params},
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    return await response.json()

        except Exception as e:
            logger.exception("RPC call error: %s", e)
            return {"error": str(e)}

    async def list_payloads(self, search: str = "") -> list[str]:
        """List available payloads.

        Args:
            search: Search filter

        Returns:
            List of payload names

        """
        result = await self._call("module.payloads")
        payloads = result.get("result", {}).get("modules", [])

        if search:
            payloads = [p for p in payloads if search.lower() in p.lower()]

        return payloads

    async def list_sessions(self) -> list[MSFSession]:
        """List active sessions.

        Returns:
            List of MSFSession objects

        """
        result = await self._call("session.list")
        sessions = []

        for sid, info in result.get("result", {}).items():
            try:
                session_type = SessionType.SHELL
                if "meterpreter" in info.get("type", "").lower():
                    session_type = SessionType.METERPRETER
                elif "vnc" in info.get("type", "").lower():
                    session_type = SessionType.VNC

                sessions.append(
                    MSFSession(
                        session_id=int(sid),
                        session_type=session_type,
                        target_host=info.get("target_host", ""),
                        target_port=info.get("target_port", 0),
                        via_exploit=info.get("via_exploit", ""),
                        via_payload=info.get("via_payload", ""),
                        username=info.get("username", ""),
                        info=info.get("info", ""),
                    ),
                )
            except Exception as e:
                logger.exception("Error parsing session: %s", e)

        return sessions


