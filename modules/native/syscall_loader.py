"""DRAKBEN Syscall Loader
Author: @ahmetdrak
Description: Loads and manages the Rust-based Syscall Engine DLL.
             Handles compilation checking and FFI (Foreign Function Interface) bridging.
             Supports: SSN Cache, Indirect Syscall, Tartarus Gate, Full Args.
"""

import ctypes
import logging
import platform
from ctypes import c_int, c_size_t, c_uint32, c_void_p
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to the Rust source project
RUST_PROJECT_PATH = Path("modules/native/rust_syscalls")

# Expected DLL name based on OS
if platform.system() == "Windows":
    DLL_NAME = "drakben_syscalls.dll"
    TARGET_DIR = "release"
else:
    # On Kali/Linux, we might be cross-compiling or running locally
    DLL_NAME = "libdrakben_syscalls.so"
    TARGET_DIR = "release"


class SyscallLoader:
    """Bridge between Python Agent and Rust Syscall Engine."""

    def __init__(self) -> None:
        self.dll_path = self._find_dll()
        self.lib = None

        if self.dll_path:
            try:
                self.lib = ctypes.cdll.LoadLibrary(str(self.dll_path))
                self._setup_signatures()
                logger.info("Native Syscall Engine loaded from: %s", self.dll_path)
            except Exception as e:
                logger.exception("Failed to load Syscall DLL: %s", e)
        else:
            logger.warning(
                "Syscall DLL not found. Run 'cargo build --release' in modules/native/rust_syscalls",
            )

    def _find_dll(self) -> Path | None:
        """Search for the compiled DLL/SO file."""
        # 1. Check standard cargo output directory
        cargo_out = RUST_PROJECT_PATH / "target" / TARGET_DIR / DLL_NAME
        if cargo_out.exists():
            return cargo_out.resolve()

        # 2. Check current directory (for deployed agents)
        local_dll = Path(DLL_NAME)
        if local_dll.exists():
            return local_dll.resolve()

        return None

    def _setup_signatures(self) -> None:
        """Define argument and return types for Rust functions."""
        if not self.lib:
            return

        # fn check_health() -> i32
        self.lib.check_health.argtypes = []
        self.lib.check_health.restype = c_int

        # fn allocate_rwx(size: usize) -> *mut c_void
        self.lib.allocate_rwx.argtypes = [c_size_t]
        self.lib.allocate_rwx.restype = c_void_p

        # fn direct_syscall(ssn: u32) -> i32
        self.lib.direct_syscall.argtypes = [c_uint32]
        self.lib.direct_syscall.restype = c_int

        # fn resolve_ssn(func_hash: u32) -> i32
        self.lib.resolve_ssn.argtypes = [c_uint32]
        self.lib.resolve_ssn.restype = c_int

        # === NEW: SSN Cache ===
        # fn resolve_ssn_cached(func_hash: u32) -> i32
        self.lib.resolve_ssn_cached.argtypes = [c_uint32]
        self.lib.resolve_ssn_cached.restype = c_int

        # === NEW: Indirect Syscall ===
        # fn get_syscall_gadget() -> usize
        self.lib.get_syscall_gadget.argtypes = []
        self.lib.get_syscall_gadget.restype = c_size_t

        # fn indirect_syscall(ssn: u32, gadget_addr: usize) -> i32
        self.lib.indirect_syscall.argtypes = [c_uint32, c_size_t]
        self.lib.indirect_syscall.restype = c_int

        # === NEW: Tartarus Gate ===
        # fn resolve_ssn_tartarus(func_hash: u32) -> i32
        self.lib.resolve_ssn_tartarus.argtypes = [c_uint32]
        self.lib.resolve_ssn_tartarus.restype = c_int

        # === NEW: Full Argument Syscall ===
        # fn direct_syscall_args(ssn, arg1, arg2, arg3, arg4) -> i32
        self.lib.direct_syscall_args.argtypes = [
            c_uint32,
            c_size_t,
            c_size_t,
            c_size_t,
            c_size_t,
        ]
        self.lib.direct_syscall_args.restype = c_int

        # === NEW: Pre-computed Hashes ===
        self.lib.hash_nt_allocate_virtual_memory.argtypes = []
        self.lib.hash_nt_allocate_virtual_memory.restype = c_uint32

        self.lib.hash_nt_protect_virtual_memory.argtypes = []
        self.lib.hash_nt_protect_virtual_memory.restype = c_uint32

        self.lib.hash_nt_create_thread_ex.argtypes = []
        self.lib.hash_nt_create_thread_ex.restype = c_uint32

        self.lib.hash_nt_write_virtual_memory.argtypes = []
        self.lib.hash_nt_write_virtual_memory.restype = c_uint32

        # fn compute_hash(name_ptr: *const u8, name_len: usize) -> u32
        self.lib.compute_hash.argtypes = [ctypes.c_char_p, c_size_t]
        self.lib.compute_hash.restype = c_uint32

    def is_available(self) -> bool:
        """Check if engine is loaded and healthy."""
        if not self.lib:
            return False
        try:
            return self.lib.check_health() == 1337
        except (OSError, AttributeError):
            return False

    def allocate_memory(self, size: int) -> int:
        """Allocate RWX memory using Native Engine."""
        if self.lib:
            return self.lib.allocate_rwx(size)
        return 0

    def resolve_ssn(self, func_hash: int) -> int:
        """Resolve SSN using Halo's Gate technique."""
        if self.lib:
            return self.lib.resolve_ssn(func_hash)
        return -1

    def resolve_ssn_cached(self, func_hash: int) -> int:
        """Resolve SSN with caching (faster for repeated calls)."""
        if self.lib:
            return self.lib.resolve_ssn_cached(func_hash)
        return -1

    def resolve_ssn_tartarus(self, func_hash: int) -> int:
        """Resolve SSN using Tartarus Gate (enhanced hook detection)."""
        if self.lib:
            return self.lib.resolve_ssn_tartarus(func_hash)
        return -1

    def get_syscall_gadget(self) -> int:
        """Find syscall;ret gadget in ntdll for indirect syscalls."""
        if self.lib:
            return self.lib.get_syscall_gadget()
        return 0

    def indirect_syscall(self, ssn: int, gadget_addr: int = 0) -> int:
        """Execute indirect syscall (bypasses call stack analysis)."""
        if not self.lib:
            return -1
        if gadget_addr == 0:
            gadget_addr = self.get_syscall_gadget()
        return self.lib.indirect_syscall(ssn, gadget_addr)

    def direct_syscall(self, ssn: int) -> int:
        """Execute direct syscall (basic Hell's Gate)."""
        if self.lib:
            return self.lib.direct_syscall(ssn)
        return -1

    def direct_syscall_args(
        self,
        ssn: int,
        arg1: int = 0,
        arg2: int = 0,
        arg3: int = 0,
        arg4: int = 0,
    ) -> int:
        """Execute syscall with up to 4 arguments."""
        if self.lib:
            return self.lib.direct_syscall_args(ssn, arg1, arg2, arg3, arg4)
        return -1

    def compute_hash(self, func_name: str) -> int:
        """Compute djb2 hash for a function name."""
        if self.lib:
            name_bytes = func_name.encode("utf-8")
            return self.lib.compute_hash(name_bytes, len(name_bytes))
        return 0

    def get_common_hashes(self) -> dict[str, int]:
        """Get pre-computed hashes for common NT functions."""
        if not self.lib:
            return {}
        return {
            "NtAllocateVirtualMemory": self.lib.hash_nt_allocate_virtual_memory(),
            "NtProtectVirtualMemory": self.lib.hash_nt_protect_virtual_memory(),
            "NtCreateThreadEx": self.lib.hash_nt_create_thread_ex(),
            "NtWriteVirtualMemory": self.lib.hash_nt_write_virtual_memory(),
        }


# Singleton
_loader = None
_loader_lock = __import__("threading").Lock()


def get_syscall_loader() -> SyscallLoader:
    global _loader
    if _loader is None:
        with _loader_lock:
            if _loader is None:
                _loader = SyscallLoader()
    return _loader
