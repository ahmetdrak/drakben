"""
DRAKBEN Syscall Loader
Author: @ahmetdrak
Description: Loads and manages the Rust-based Syscall Engine DLL.
             Handles compilation checking and FFI (Foreign Function Interface) bridging.
"""

import ctypes
import logging
import platform
from ctypes import c_int, c_void_p
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
    """
    Bridge between Python Agent and Rust Syscall Engine.
    """

    def __init__(self):
        self.dll_path = self._find_dll()
        self.lib = None

        if self.dll_path:
            try:
                self.lib = ctypes.cdll.LoadLibrary(str(self.dll_path))
                self._setup_signatures()
                logger.info(f"Native Syscall Engine loaded from: {self.dll_path}")
            except Exception as e:
                logger.error(f"Failed to load Syscall DLL: {e}")
        else:
            logger.warning(
                "Syscall DLL not found. Run 'cargo build --release' in modules/native/rust_syscalls"
            )

    def _find_dll(self) -> Path:
        """Search for the compiled DLL/SO file"""
        # 1. Check standard cargo output directory
        cargo_out = RUST_PROJECT_PATH / "target" / TARGET_DIR / DLL_NAME
        if cargo_out.exists():
            return cargo_out.resolve()

        # 2. Check current directory (for deployed agents)
        local_dll = Path(DLL_NAME)
        if local_dll.exists():
            return local_dll.resolve()

        return None

    def _setup_signatures(self):
        """Define argument and return types for Rust functions"""
        if not self.lib:
            return

        # fn check_health() -> i32
        self.lib.check_health.argtypes = []
        self.lib.check_health.restype = c_int

        # fn allocate_rwx(size: usize) -> *mut c_void
        self.lib.allocate_rwx.argtypes = [ctypes.c_size_t]
        self.lib.allocate_rwx.restype = c_void_p

        # fn direct_syscall(ssn: u32) -> i32
        # Note: This basic signature doesn't handle extra args yet.
        self.lib.direct_syscall.argtypes = [ctypes.c_uint32]
        self.lib.direct_syscall.restype = c_int

    def is_available(self) -> bool:
        """Check if engine is loaded and healthy"""
        if not self.lib:
            return False
        try:
            return self.lib.check_health() == 1337
        except Exception:
            return False

    def allocate_memory(self, size: int) -> int:
        """Allocate RWX memory using Native Engine"""
        if self.lib:
            return self.lib.allocate_rwx(size)
        return 0


# Singleton
_loader = None


def get_syscall_loader() -> SyscallLoader:
    global _loader
    if _loader is None:
        _loader = SyscallLoader()
    return _loader
