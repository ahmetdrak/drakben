# modules/native - Low-level syscall operations for EDR bypass
"""Native syscall operations module.

Provides:
- SyscallEngine: Direct syscalls (Halo's Gate technique)
- SyscallLoader: Shellcode injection
"""

from modules.native.syscall_engine import SyscallEngine
from modules.native.syscall_loader import SyscallLoader

__all__ = ["SyscallEngine", "SyscallLoader"]
