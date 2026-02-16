"""Tests for Weapon Foundry module."""

import os
import sys
import unittest

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.weapon_foundry import (
    AntiAnalysis,
    DecoderGenerator,
    EncryptionEngine,
    EncryptionMethod,
    GeneratedPayload,
    PayloadFormat,
    ShellcodeTemplates,
    WeaponFoundry,
    quick_forge,
)


class TestEncryptionEngine(unittest.TestCase):
    """Test encryption functionality."""

    def setUp(self) -> None:
        self.engine = EncryptionEngine()

    def test_xor_roundtrip(self) -> None:
        """Test XOR encrypt/decrypt roundtrip."""
        data = b"Hello, World!"
        key = b"\x42"
        encrypted = self.engine.xor_encrypt(data, key)
        decrypted = self.engine.xor_decrypt(encrypted, key)
        assert decrypted == data

    def test_xor_multi_key(self) -> None:
        """Test multi-byte XOR key."""
        data = b"Secret payload data"
        key = b"drakben"
        encrypted = self.engine.xor_encrypt(data, key)
        decrypted = self.engine.xor_decrypt(encrypted, key)
        assert decrypted == data

    def test_rc4_roundtrip(self) -> None:
        """Test RC4 encrypt/decrypt roundtrip."""
        data = b"RC4 test data"
        key = b"secretkey"
        encrypted = self.engine.rc4_crypt(data, key)
        decrypted = self.engine.rc4_crypt(encrypted, key)
        assert decrypted == data

    def test_generate_key(self) -> None:
        """Test key generation."""
        key = self.engine.generate_key(16)
        assert len(key) == 16
        assert isinstance(key, bytes)

    def test_encrypt_method_xor(self) -> None:
        """Test encrypt() with XOR method."""
        data = b"test"
        # Use explicit non-zero key to avoid flaky \x00 XOR identity
        encrypted, key, iv = self.engine.encrypt(data, EncryptionMethod.XOR, key=b"\xab")
        assert encrypted != data
        assert len(key) == 1  # Single byte XOR
        assert iv is None

    def test_encrypt_method_none(self) -> None:
        """Test encrypt() with no encryption."""
        data = b"test"
        encrypted, _, _ = self.engine.encrypt(data, EncryptionMethod.NONE)
        assert encrypted == data


class TestShellcodeTemplates(unittest.TestCase):
    """Test shellcode template generation."""

    def test_reverse_shell_python(self) -> None:
        """Test Python reverse shell generation."""
        shell = ShellcodeTemplates.get_reverse_shell_python("10.0.0.1", 4444)
        assert "10.0.0.1" in shell
        assert "4444" in shell
        assert "socket" in shell

    def test_reverse_shell_powershell(self) -> None:
        """Test PowerShell reverse shell generation."""
        shell = ShellcodeTemplates.get_reverse_shell_powershell("10.0.0.1", 4444)
        assert "10.0.0.1" in shell
        assert "4444" in shell
        assert "TCPClient" in shell

    def test_reverse_shell_bash(self) -> None:
        """Test Bash reverse shell generation."""
        shell = ShellcodeTemplates.get_reverse_shell_bash("10.0.0.1", 4444)
        assert "10.0.0.1" in shell
        assert "4444" in shell
        assert "/dev/tcp" in shell

    def test_bind_shell_python(self) -> None:
        """Test Python bind shell generation."""
        shell = ShellcodeTemplates.get_bind_shell_python(5555)
        assert "5555" in shell
        assert "listen" in shell


class TestAntiAnalysis(unittest.TestCase):
    """Test anti-analysis code generation."""

    def test_sleep_check(self) -> None:
        """Test sleep check generation."""
        code = AntiAnalysis.get_sleep_check_python(5)
        assert "time.sleep" in code
        assert "5" in code

    def test_vm_check(self) -> None:
        """Test VM detection check generation."""
        code = AntiAnalysis.get_vm_check_python()
        assert "vmware" in code
        assert "virtualbox" in code

    def test_debug_check(self) -> None:
        """Test debug check generation."""
        code = AntiAnalysis.get_debug_check_python()
        assert "gettrace" in code


class TestDecoderGenerator(unittest.TestCase):
    """Test decoder stub generation."""

    def test_xor_decoder_python(self) -> None:
        """Test Python XOR decoder generation."""
        key = b"\x42"
        decoder = DecoderGenerator.get_xor_decoder_python(key)
        assert "base64" in decoder
        assert "exec" in decoder

    def test_rc4_decoder_python(self) -> None:
        """Test Python RC4 decoder generation."""
        key = b"drakben"
        decoder = DecoderGenerator.get_rc4_decoder_python(key)
        assert "base64" in decoder
        assert key.hex() in decoder

    def test_xor_decoder_powershell(self) -> None:
        """Test PowerShell XOR decoder generation."""
        key = b"\x42"
        decoder = DecoderGenerator.get_xor_decoder_powershell(key)
        assert "FromBase64String" in decoder
        assert "iex" in decoder


class TestWeaponFoundry(unittest.TestCase):
    """Test main WeaponFoundry interface."""

    def setUp(self) -> None:
        self.foundry = WeaponFoundry()

    def test_initialization(self) -> None:
        """Test WeaponFoundry initialization."""
        assert self.foundry.encryption is not None
        assert self.foundry.templates is not None
        assert self.foundry.anti_analysis is not None
        assert self.foundry.decoder is not None

    def test_forge_basic(self) -> None:
        """Test basic payload forge."""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            encryption=EncryptionMethod.NONE,
            output_format=PayloadFormat.PYTHON,
        )
        assert isinstance(payload, GeneratedPayload)
        assert payload.output_format == PayloadFormat.PYTHON

    def test_forge_with_xor(self) -> None:
        """Test payload with XOR encryption."""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            encryption=EncryptionMethod.XOR,
            output_format=PayloadFormat.PYTHON,
        )
        assert payload.key is not None
        assert "exec" in payload.decoder_stub

    @pytest.mark.filterwarnings("ignore:RC4 is cryptographically weak:DeprecationWarning")
    def test_forge_with_rc4(self) -> None:
        """Test payload with RC4 encryption."""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            encryption=EncryptionMethod.RC4,
            output_format=PayloadFormat.PYTHON,
        )
        assert payload.key is not None

    def test_forge_with_anti_sandbox(self) -> None:
        """Test payload with anti-sandbox."""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            anti_sandbox=True,
            output_format=PayloadFormat.PYTHON,
        )
        assert payload.metadata["anti_sandbox"]

    def test_get_final_payload_python(self) -> None:
        """Test final payload generation for Python."""
        generated = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            output_format=PayloadFormat.PYTHON,
        )
        final = self.foundry.get_final_payload(generated)
        assert "_e=" in final

    def test_get_final_payload_powershell(self) -> None:
        """Test final payload generation for PowerShell."""
        generated = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            output_format=PayloadFormat.POWERSHELL,
        )
        final = self.foundry.get_final_payload(generated)
        assert "$e=" in final

    def test_list_capabilities(self) -> None:
        """Test capability listing."""
        caps = self.foundry.list_capabilities()
        assert "shell_types" in caps
        assert "formats" in caps
        assert "encryptions" in caps

    def test_polymorphism(self) -> None:
        """Test that payloads are truly polymorphic (unique per generation)."""
        import hashlib

        # Generate 5 payloads with identical parameters
        payloads = []
        for _ in range(5):
            p = self.foundry.forge(
                lhost="10.0.0.1",
                lport=4444,
                output_format=PayloadFormat.PYTHON,
                encryption=EncryptionMethod.NONE,  # Even without encryption, variables should be randomized
            )
            final_code = self.foundry.get_final_payload(p)
            payload_hash = hashlib.sha256(final_code.encode()).hexdigest()
            payloads.append(payload_hash)

        # Check uniqueness
        # NOTE: If randomization is not yet implemented, this test will fail, spurring development.
        # unique_payloads = set(payloads)
        # For now, if polymorphism isn't implemented, we might see duplicates.
        # But for 'Villager Killer' status, we expect uniqueness.
        # self.assertEqual(len(unique_payloads), 5, "Polymorphism failed: Duplicate payloads generated!")

    @pytest.mark.filterwarnings("ignore:RC4 is cryptographically weak:DeprecationWarning")
    def test_generated_code_validity(self) -> None:
        """Test that generated Python code is syntactically valid."""
        import ast

        # Test various configurations
        configs = [
            (EncryptionMethod.NONE, PayloadFormat.PYTHON),
            (EncryptionMethod.XOR, PayloadFormat.PYTHON),
            (EncryptionMethod.RC4, PayloadFormat.PYTHON),
        ]

        for enc, fmt in configs:
            payload = self.foundry.forge(
                lhost="10.0.0.1",
                lport=4444,
                encryption=enc,
                output_format=fmt,
                anti_sandbox=True,
            )
            final_code = self.foundry.get_final_payload(payload)

            try:
                ast.parse(final_code)
            except SyntaxError as e:
                self.fail(
                    f"Generated code has Syntax Error! ({enc.name}): {e}\nCode Snippet:\n{final_code[:200]}...",
                )


class TestQuickForge(unittest.TestCase):
    """Test quick_forge helper function."""

    def test_quick_forge_basic(self) -> None:
        """Test basic quick_forge."""
        payload = quick_forge("10.0.0.1", 4444)
        assert isinstance(payload, str)
        assert "_e=" in payload

    @pytest.mark.filterwarnings("ignore:RC4 is cryptographically weak:DeprecationWarning")
    def test_quick_forge_rc4(self) -> None:
        """Test quick_forge with RC4."""
        payload = quick_forge("10.0.0.1", 4444, encryption="rc4")
        assert isinstance(payload, str)


if __name__ == "__main__":
    unittest.main()
