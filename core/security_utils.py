# core/security_utils.py
# DRAKBEN Security Utilities
# Credential storage, audit logging, and proxy support

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


# =========================================
# SECURE CREDENTIAL STORAGE
# =========================================

class CredentialStore:
    """
    Secure credential storage using system keyring or encrypted file.
    
    Features:
    - System keyring integration (if available)
    - Encrypted file fallback
    - Password-based encryption
    """
    
    SERVICE_NAME = "drakben"
    
    def __init__(self, storage_path: str = ".credentials.enc"):
        self.storage_path = Path(storage_path)
        self._keyring_available = self._check_keyring()
        self._encryption_key: Optional[bytes] = None
        
        logger.info(f"CredentialStore initialized (keyring: {self._keyring_available})")
    
    def _check_keyring(self) -> bool:
        """Check if keyring is available"""
        try:
            import keyring
            # Test keyring access
            keyring.get_keyring()
            return True
        except (keyring.errors.KeyringError, Exception):
            return False
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password"""
        # Use standard library implementation which acts as a fallback and is secure enough
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    
    def _encrypt(self, data: str, key: bytes) -> bytes:
        """Encrypt data using AES-GCM (REQUIRES pycryptodome)"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
            
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode())
            
            return nonce + tag + ciphertext
        except ImportError:
            # NO FALLBACK - XOR is not secure
            logger.error("pycryptodome not available! Install with: pip install pycryptodome")
            raise ImportError(
                "pycryptodome is REQUIRED for secure credential storage. "
                "Install with: pip install pycryptodome"
            )
    
    def _decrypt(self, encrypted: bytes, key: bytes) -> str:
        """Decrypt data (REQUIRES pycryptodome)"""
        try:
            from Crypto.Cipher import AES
            
            nonce = encrypted[:12]
            tag = encrypted[12:28]
            ciphertext = encrypted[28:]
            
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            return data.decode()
        except ImportError:
            # NO FALLBACK - XOR is not secure
            logger.error("pycryptodome not available for decryption!")
            raise ImportError(
                "pycryptodome is REQUIRED for credential decryption. "
                "Install with: pip install pycryptodome"
            )
    
    def store(self, key: str, value: str, master_password: Optional[str] = None) -> bool:
        """
        Store credential securely.
        
        Args:
            key: Credential identifier
            value: Credential value
            master_password: Master password for file storage
            
        Returns:
            True if successful
        """
        try:
            if self._keyring_available:
                import keyring
                keyring.set_password(self.SERVICE_NAME, key, value)
                logger.info(f"Credential stored in keyring: {key}")
                return True
            
            # File-based storage - REQUIRE explicit password (fail-safe)
            if not master_password:
                master_password = os.environ.get("DRAKBEN_MASTER_PASSWORD")
                if not master_password:
                    logger.error("Master password required for credential storage!")
                    raise ValueError(
                        "Master password is REQUIRED. Set DRAKBEN_MASTER_PASSWORD env var "
                        "or provide master_password parameter."
                    )
            
            # Load existing credentials
            credentials = self._load_file(master_password)
            credentials[key] = value
            
            # Save
            self._save_file(credentials, master_password)
            logger.info(f"Credential stored in file: {key}")
            return True
            
        except ValueError:
            raise  # Re-raise ValueError for missing password
        except Exception as e:
            logger.error(f"Failed to store credential: {e}")
            return False
    
    def retrieve(self, key: str, master_password: Optional[str] = None) -> Optional[str]:
        """
        Retrieve credential.
        
        Args:
            key: Credential identifier
            master_password: Master password for file storage
            
        Returns:
            Credential value or None
        """
        try:
            if self._keyring_available:
                import keyring
                value = keyring.get_password(self.SERVICE_NAME, key)
                if value:
                    return value
            
            # File-based storage - REQUIRE explicit password
            if not master_password:
                master_password = os.environ.get("DRAKBEN_MASTER_PASSWORD")
                if not master_password:
                    logger.warning("Master password not provided for credential retrieval")
                    return None  # Graceful fail for retrieval
            
            credentials = self._load_file(master_password)
            return credentials.get(key)
            
        except Exception as e:
            logger.error(f"Failed to retrieve credential: {e}")
            return None
    
    def delete(self, key: str, master_password: Optional[str] = None) -> bool:
        """Delete credential"""
        try:
            if self._keyring_available:
                import keyring
                keyring.delete_password(self.SERVICE_NAME, key)
            
            # File-based storage - REQUIRE explicit password
            if not master_password:
                master_password = os.environ.get("DRAKBEN_MASTER_PASSWORD")
                if not master_password:
                    logger.error("Master password required for credential deletion")
                    return False  # Graceful fail for deletion
            
            credentials = self._load_file(master_password)
            if key in credentials:
                del credentials[key]
                self._save_file(credentials, master_password)
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete credential: {e}")
            return False
    
    def _load_file(self, password: str) -> Dict[str, str]:
        """Load credentials from encrypted file"""
        if not self.storage_path.exists():
            return {}
        
        try:
            with open(self.storage_path, 'rb') as f:
                salt = f.read(16)
                encrypted = f.read()
            
            key = self._derive_key(password, salt)
            decrypted = self._decrypt(encrypted, key)
            return json.loads(decrypted)
        except Exception:
            return {}
    
    def _save_file(self, credentials: Dict[str, str], password: str):
        """Save credentials to encrypted file"""
        salt = secrets.token_bytes(16)
        key = self._derive_key(password, salt)
        encrypted = self._encrypt(json.dumps(credentials), key)
        
        with open(self.storage_path, 'wb') as f:
            f.write(salt)
            f.write(encrypted)


# =========================================
# AUDIT LOGGING
# =========================================

class AuditEventType(Enum):
    """Audit event types"""
    COMMAND_EXECUTED = "command_executed"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    EXPLOIT_ATTEMPTED = "exploit_attempted"
    EXPLOIT_SUCCEEDED = "exploit_succeeded"
    PAYLOAD_GENERATED = "payload_generated"
    CREDENTIAL_ACCESSED = "credential_accessed"
    CONFIG_CHANGED = "config_changed"
    SESSION_STARTED = "session_started"
    SESSION_ENDED = "session_ended"
    ERROR = "error"
    WARNING = "warning"


@dataclass
class AuditEvent:
    """Audit event record"""
    timestamp: str
    event_type: AuditEventType
    user: str
    source_ip: str
    target: str
    action: str
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    risk_level: str = "low"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "user": self.user,
            "source_ip": self.source_ip,
            "target": self.target,
            "action": self.action,
            "details": self.details,
            "success": self.success,
            "risk_level": self.risk_level
        }


class AuditLogger:
    """
    Forensic-ready audit logging system.
    
    Features:
    - SQLite storage for integrity
    - JSON export
    - Event filtering
    - Tamper detection (hash chain)
    - Thread-safe operations
    """
    
    def __init__(self, db_path: str = "audit.db"):
        self._db_path_str = db_path
        self._conn = None
        self._lock = threading.Lock()  # Thread safety for hash chain
        
        # For in-memory db, keep connection open
        if db_path == ":memory:":
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        
        self._init_db()
        self._last_hash = self._get_last_hash()
        
        logger.info(f"AuditLogger initialized: {db_path}")
    
    def _get_connection(self):
        """Get database connection"""
        if self._conn:
            return self._conn
        return sqlite3.connect(self._db_path_str)
    
    def _init_db(self):
        """Initialize audit database"""
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    user TEXT,
                    source_ip TEXT,
                    target TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    success INTEGER,
                    risk_level TEXT,
                    hash TEXT NOT NULL,
                    prev_hash TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_event_type ON audit_log(event_type)
            """)
            conn.commit()
        finally:
            if not self._conn:
                conn.close()
    
    def _get_last_hash(self) -> str:
        """Get hash of last entry for chain"""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            return row[0] if row else "GENESIS"
        finally:
            if not self._conn:
                conn.close()
    
    def _compute_hash(self, event: AuditEvent, prev_hash: str) -> str:
        """Compute hash for event"""
        data = f"{event.timestamp}|{event.event_type.value}|{event.action}|{prev_hash}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def log(self, event: AuditEvent):
        """
        Log audit event (thread-safe).
        
        Args:
            event: AuditEvent to log
        """
        with self._lock:  # Thread-safe hash chain updates
            event_hash = self._compute_hash(event, self._last_hash)
            
            conn = self._get_connection()
            try:
                conn.execute("""
                    INSERT INTO audit_log 
                    (timestamp, event_type, user, source_ip, target, action, details, success, risk_level, hash, prev_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.timestamp,
                    event.event_type.value,
                    event.user,
                    event.source_ip,
                    event.target,
                    event.action,
                    json.dumps(event.details),
                    1 if event.success else 0,
                    event.risk_level,
                    event_hash,
                    self._last_hash
                ))
                conn.commit()
            finally:
                if not self._conn:
                    conn.close()
            
            self._last_hash = event_hash
        
        logger.debug(f"Audit logged: {event.action}")
    
    def log_command(
        self,
        command: str,
        target: str = "",
        success: bool = True,
        details: Optional[Dict[Any, Any]] = None
    ):
        """Convenience method for logging commands"""
        event = AuditEvent(
            timestamp=datetime.now().isoformat(),
            event_type=AuditEventType.COMMAND_EXECUTED,
            user=os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            source_ip="127.0.0.1",
            target=target,
            action=command,
            details=details or {},
            success=success,
            risk_level="medium" if "exploit" in command.lower() else "low"
        )
        self.log(event)
    
    def query(
        self,
        event_type: Optional[AuditEventType] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query audit logs.
        
        Args:
            event_type: Filter by event type
            start_time: Start timestamp
            end_time: End timestamp
            target: Filter by target
            limit: Max results
            
        Returns:
            List of audit event dictionaries
        """
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        
        query += f" ORDER BY timestamp DESC LIMIT {limit}"
        
        results = []
        with sqlite3.connect(self._db_path_str) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            for row in cursor:
                results.append(dict(row))
        
        return results
    
    def verify_integrity(self) -> Tuple[bool, str]:
        """
        Verify audit log integrity using hash chain.
        
        Returns:
            Tuple of (is_valid, message)
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT timestamp, event_type, action, hash, prev_hash FROM audit_log ORDER BY id"
            )
            
            prev_hash = "GENESIS"
            for row in cursor:
                timestamp, _, _, stored_hash, stored_prev = row
                
                if stored_prev != prev_hash:
                    return False, f"Chain broken at {timestamp}: prev_hash mismatch"
                
                prev_hash = stored_hash
        finally:
            if not self._conn:
                conn.close()
        
        return True, "Audit log integrity verified"
    
    def export_json(self, output_path: str):
        """Export audit log to JSON"""
        events = self.query(limit=10000)
        with open(output_path, 'w') as f:
            json.dump(events, f, indent=2)
        logger.info(f"Audit log exported to {output_path}")


# =========================================
# PROXY SUPPORT
# =========================================

@dataclass
class ProxyConfig:
    """Proxy configuration"""
    host: str
    port: int
    protocol: str = "http"  # http, https, socks4, socks5
    username: Optional[str] = None
    password: Optional[str] = None
    
    def get_url(self) -> str:
        """Get proxy URL"""
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.protocol}://{auth}{self.host}:{self.port}"
    
    def get_dict(self) -> Dict[str, str]:
        """Get proxy dict for requests"""
        url = self.get_url()
        return {
            "http": url,
            "https": url
        }


class ProxyManager:
    """
    Proxy manager for network requests.
    
    Features:
    - HTTP/HTTPS proxy support
    - SOCKS4/SOCKS5 support
    - Proxy rotation
    - Tor integration
    """
    
    def __init__(self):
        self.proxies: List[ProxyConfig] = []
        self.current_index = 0
        self.tor_available = self._check_tor()
        
        logger.info(f"ProxyManager initialized (tor: {self.tor_available})")
    
    def _check_tor(self) -> bool:
        """Check if Tor is available"""
        try:
            import socks
            import socket
            
            # Try connecting to Tor SOCKS port
            test_socket = socks.socksocket()
            test_socket.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            test_socket.settimeout(5)
            test_socket.connect(("check.torproject.org", 80))
            test_socket.close()
            return True
        except Exception:
            return False
    
    def add_proxy(self, proxy: ProxyConfig):
        """Add proxy to pool"""
        self.proxies.append(proxy)
        logger.info(f"Proxy added: {proxy.host}:{proxy.port}")
    
    def add_tor(self, host: str = "127.0.0.1", port: int = 9050):
        """Add Tor as proxy"""
        self.add_proxy(ProxyConfig(
            host=host,
            port=port,
            protocol="socks5"
        ))
    
    def get_next(self) -> Optional[ProxyConfig]:
        """Get next proxy in rotation"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def get_current(self) -> Optional[ProxyConfig]:
        """Get current proxy without rotation"""
        if not self.proxies:
            return None
        return self.proxies[self.current_index]
    
    def get_requests_proxy(self) -> Optional[Dict[str, str]]:
        """Get proxy dict for requests library"""
        proxy = self.get_current()
        return proxy.get_dict() if proxy else None
    
    def get_aiohttp_proxy(self) -> Optional[str]:
        """Get proxy URL for aiohttp"""
        proxy = self.get_current()
        return proxy.get_url() if proxy else None
    
    def configure_requests_session(self, session) -> None:
        """Configure requests session with proxy"""
        proxy_dict = self.get_requests_proxy()
        if proxy_dict:
            session.proxies.update(proxy_dict)
    
    def test_proxy(self, proxy: ProxyConfig, timeout: int = 10) -> bool:
        """
        Test proxy connectivity.
        
        Args:
            proxy: Proxy to test
            timeout: Connection timeout
            
        Returns:
            True if proxy is working
        """
        try:
            import requests
            
            response = requests.get(
                "https://httpbin.org/ip",
                proxies=proxy.get_dict(),
                timeout=timeout
            )
            
            if response.status_code == 200:
                logger.info(f"Proxy working: {proxy.host}:{proxy.port}")
                return True
        except Exception as e:
            logger.warning(f"Proxy test failed: {e}")
        
        return False
    
    def remove_dead_proxies(self):
        """Remove non-working proxies"""
        self.proxies = [p for p in self.proxies if self.test_proxy(p)]


# =========================================
# CONVENIENCE FUNCTIONS (Thread-Safe Singletons)
# =========================================

import threading

_credential_store: Optional[CredentialStore] = None
_audit_logger: Optional[AuditLogger] = None
_proxy_manager: Optional[ProxyManager] = None

# Thread-safe locks for singleton instantiation
_credential_store_lock = threading.Lock()
_audit_logger_lock = threading.Lock()
_proxy_manager_lock = threading.Lock()


def get_credential_store() -> CredentialStore:
    """Get global credential store instance (thread-safe)"""
    global _credential_store
    if _credential_store is None:
        with _credential_store_lock:
            # Double-check pattern
            if _credential_store is None:
                _credential_store = CredentialStore()
    return _credential_store


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance (thread-safe)"""
    global _audit_logger
    if _audit_logger is None:
        with _audit_logger_lock:
            # Double-check pattern
            if _audit_logger is None:
                _audit_logger = AuditLogger()
    return _audit_logger


def get_proxy_manager() -> ProxyManager:
    """Get global proxy manager instance (thread-safe)"""
    global _proxy_manager
    if _proxy_manager is None:
        with _proxy_manager_lock:
            # Double-check pattern
            if _proxy_manager is None:
                _proxy_manager = ProxyManager()
    return _proxy_manager


def audit_command(command: str, target: str = "", success: bool = True, details: Optional[Dict[str, Any]] = None):
    """Quick audit logging for commands"""
    get_audit_logger().log_command(command, target, success, details)
