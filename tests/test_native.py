"""Tests for modules/native — SyscallEngine and SyscallLoader.

These tests are mock-based since the native DLL/SO won't be present
in CI. Every public method is exercised through the "not available" path.
"""

from __future__ import annotations

import platform
from unittest.mock import MagicMock, patch

from modules.native.syscall_engine import SyscallEngine, get_syscall_engine
from modules.native.syscall_loader import SyscallLoader, get_syscall_loader

# ---------------------------------------------------------------------------
# SyscallEngine
# ---------------------------------------------------------------------------


class TestSyscallEngine:
    """SyscallEngine on non-Windows / no DLL."""

    def test_init(self):
        engine = SyscallEngine()
        assert engine.os_name == platform.system().lower()

    def test_is_supported_false_on_non_windows(self):
        engine = SyscallEngine()
        # On CI (Linux/macOS) or when DLLs are missing, should be False
        if platform.system() != "Windows":
            assert engine.is_supported() is False

    def test_allocate_memory_unsupported(self):
        engine = SyscallEngine()
        if not engine.is_supported():
            assert engine.allocate_memory(4096) == 0

    def test_write_memory_unsupported(self):
        engine = SyscallEngine()
        if not engine.is_supported():
            assert engine.write_memory(0, b"\x90") is False

    def test_write_memory_null_address(self):
        engine = SyscallEngine()
        assert engine.write_memory(0, b"\x90") is False

    def test_execute_shellcode_unsupported(self):
        engine = SyscallEngine()
        if not engine.is_supported():
            assert engine.execute_shellcode(b"\xcc") is False

    def test_free_memory_unsupported(self):
        engine = SyscallEngine()
        if not engine.is_supported():
            assert engine._free_memory(0, 0) is False

    def test_generate_syscall_stub(self):
        engine = SyscallEngine()
        stub = engine.generate_syscall_stub(0x18)
        # Must start with mov r10, rcx (0x4c 0x8b 0xd1)
        assert stub[:3] == b"\x4c\x8b\xd1"
        # Must end with syscall + ret (0x0f 0x05 0xc3)
        assert stub[-3:] == b"\x0f\x05\xc3"
        # SSN 0x18 packed as little-endian 4 bytes
        assert stub[4:8] == b"\x18\x00\x00\x00"

    def test_generate_syscall_stub_zero(self):
        engine = SyscallEngine()
        stub = engine.generate_syscall_stub(0)
        assert len(stub) == 11

    def test_singleton(self):
        # Reset singleton
        import modules.native.syscall_engine as mod
        mod._syscall_engine = None
        e1 = get_syscall_engine()
        e2 = get_syscall_engine()
        assert e1 is e2
        mod._syscall_engine = None  # cleanup


# ---------------------------------------------------------------------------
# SyscallLoader
# ---------------------------------------------------------------------------


class TestSyscallLoader:
    """SyscallLoader without native DLL."""

    def test_init_no_dll(self):
        loader = SyscallLoader()
        # DLL unlikely present in test environment
        assert loader.lib is None or loader.is_available()

    def test_is_available_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.is_available() is False

    def test_allocate_memory_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.allocate_memory(4096) == 0

    def test_resolve_ssn_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.resolve_ssn(0x1234) == -1

    def test_resolve_ssn_cached_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.resolve_ssn_cached(0x1234) == -1

    def test_resolve_ssn_tartarus_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.resolve_ssn_tartarus(0x1234) == -1

    def test_get_syscall_gadget_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.get_syscall_gadget() == 0

    def test_indirect_syscall_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.indirect_syscall(0x18) == -1

    def test_direct_syscall_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.direct_syscall(0x18) == -1

    def test_direct_syscall_args_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.direct_syscall_args(0x18, 1, 2, 3, 4) == -1

    def test_compute_hash_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.compute_hash("NtAllocateVirtualMemory") == 0

    def test_get_common_hashes_no_dll(self):
        loader = SyscallLoader()
        if loader.lib is None:
            assert loader.get_common_hashes() == {}

    def test_singleton(self):
        import modules.native.syscall_loader as mod
        mod._loader = None
        l1 = get_syscall_loader()
        l2 = get_syscall_loader()
        assert l1 is l2
        mod._loader = None


# ---------------------------------------------------------------------------
# Mock-based tests (exercise code paths even without DLL)
# ---------------------------------------------------------------------------


class TestSyscallLoaderMocked:
    """Exercise SyscallLoader paths via mocked DLL."""

    def test_is_available_healthy(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.check_health.return_value = 1337
        assert loader.is_available() is True

    def test_is_available_unhealthy(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.check_health.return_value = 0
        assert loader.is_available() is False

    def test_allocate_memory_mocked(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.allocate_rwx.return_value = 0xDEAD
        assert loader.allocate_memory(4096) == 0xDEAD

    def test_resolve_ssn_mocked(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.resolve_ssn.return_value = 0x18
        assert loader.resolve_ssn(0x1234) == 0x18

    def test_direct_syscall_mocked(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.direct_syscall.return_value = 0
        assert loader.direct_syscall(0x18) == 0

    def test_indirect_syscall_mocked(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.get_syscall_gadget.return_value = 0xBEEF
        loader.lib.indirect_syscall.return_value = 0
        assert loader.indirect_syscall(0x18) == 0

    def test_compute_hash_mocked(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.compute_hash.return_value = 12345
        assert loader.compute_hash("NtAllocateVirtualMemory") == 12345

    def test_get_common_hashes_mocked(self):
        loader = SyscallLoader()
        loader.lib = MagicMock()
        loader.lib.hash_nt_allocate_virtual_memory.return_value = 1
        loader.lib.hash_nt_protect_virtual_memory.return_value = 2
        loader.lib.hash_nt_create_thread_ex.return_value = 3
        loader.lib.hash_nt_write_virtual_memory.return_value = 4
        hashes = loader.get_common_hashes()
        assert hashes["NtAllocateVirtualMemory"] == 1
        assert hashes["NtCreateThreadEx"] == 3


class TestSyscallEngineMocked:
    """Exercise SyscallEngine Windows paths via mocks."""

    def test_allocate_memory_mocked(self):
        engine = SyscallEngine()
        engine.is_windows = True
        engine.is_64bit = True
        engine.ntdll = MagicMock()
        engine.kernel32 = MagicMock()
        engine.kernel32.VirtualAlloc.return_value = 0xAAAA
        assert engine.allocate_memory(4096) == 0xAAAA

    def test_write_memory_mocked(self):
        engine = SyscallEngine()
        engine.is_windows = True
        engine.is_64bit = True
        engine.ntdll = MagicMock()
        engine.kernel32 = MagicMock()
        # Mock ctypes.memmove to avoid real memory access
        with patch("ctypes.memmove") as mock_memmove:
            result = engine.write_memory(0x1000, b"\x90\x90")
            assert result is True
            mock_memmove.assert_called_once_with(0x1000, b"\x90\x90", 2)

    def test_free_memory_mocked(self):
        engine = SyscallEngine()
        engine.is_windows = True
        engine.is_64bit = True
        engine.ntdll = MagicMock()
        engine.kernel32 = MagicMock()
        engine.kernel32.VirtualFree.return_value = 1
        assert engine._free_memory(0x1000, 4096) is True

    def test_free_memory_failure_mocked(self):
        engine = SyscallEngine()
        engine.is_windows = True
        engine.is_64bit = True
        engine.ntdll = MagicMock()
        engine.kernel32 = MagicMock()
        engine.kernel32.VirtualFree.return_value = 0
        assert engine._free_memory(0x1000, 4096) is False
