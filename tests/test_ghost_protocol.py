"""Tests for Ghost Protocol module"""
import unittest
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ghost_protocol import (
    PolymorphicTransformer,
    StringEncryptor,
    SecureCleanup,
    GhostProtocol,
    obfuscate,
    get_ghost_protocol,
)


class TestPolymorphicTransformer(unittest.TestCase):
    """Test AST-based code transformation"""
    
    def setUp(self):
        self.transformer = PolymorphicTransformer(
            obfuscate_names=True,
            inject_dead_code=False,  # Disable for predictable tests
            encrypt_strings=False
        )
    
    def test_simple_transform(self):
        """Test basic transformation works"""
        code = "x = 5\ny = x + 1\nprint(y)"
        result = self.transformer.transform(code)
        self.assertIsInstance(result, str)
        self.assertIn("=", result)  # Assignment still exists
    
    def test_function_transform(self):
        """Test function transformation"""
        code = """
def calculate(value):
    result = value * 2
    return result
"""
        result = self.transformer.transform(code)
        self.assertIn("def ", result)
        self.assertIn("return", result)
    
    def test_preserves_builtins(self):
        """Test that builtin names are preserved"""
        code = "print(len([1, 2, 3]))"
        result = self.transformer.transform(code)
        self.assertIn("print", result)
        self.assertIn("len", result)
    
    def test_preserves_keywords(self):
        """Test that Python keywords are preserved"""
        code = "if True:\n    pass"
        result = self.transformer.transform(code)
        self.assertIn("if", result)
        self.assertIn("True", result)
    
    def test_syntax_error_returns_original(self):
        """Test that syntax errors return original code"""
        bad_code = "def foo( missing paren"
        result = self.transformer.transform(bad_code)
        self.assertEqual(result, bad_code)


class TestStringEncryptor(unittest.TestCase):
    """Test string encryption utilities"""
    
    def test_xor_roundtrip(self):
        """Test XOR encrypt/decrypt roundtrip"""
        original = "Hello, Drakben!"
        encrypted = StringEncryptor.xor_encrypt(original)
        decrypted = StringEncryptor.xor_decrypt(encrypted)
        self.assertEqual(decrypted, original)
    
    def test_rot13_roundtrip(self):
        """Test ROT13 roundtrip (self-inverse)"""
        original = "Hello World"
        encrypted = StringEncryptor.rot13(original)
        decrypted = StringEncryptor.rot13(encrypted)
        self.assertEqual(decrypted, original)
    
    def test_chunk_and_join(self):
        """Test string chunking"""
        text = "HelloWorld"
        chunks, _ = StringEncryptor.chunk_and_join(text)
        self.assertGreater(len(chunks), 0)
        self.assertEqual("".join(chunks), text)


class TestSecureCleanup(unittest.TestCase):
    """Test secure deletion and anti-forensics"""
    
    def test_secure_delete(self):
        """Test secure file deletion"""
        # Create a temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"sensitive data")
            filepath = f.name
        
        self.assertTrue(os.path.exists(filepath))
        
        # Securely delete it
        result = SecureCleanup.secure_delete(filepath, passes=1)
        
        self.assertTrue(result)
        self.assertFalse(os.path.exists(filepath))
    
    def test_secure_delete_nonexistent(self):
        """Test secure delete of non-existent file returns True"""
        result = SecureCleanup.secure_delete("/nonexistent/path/file.txt")
        self.assertTrue(result)  # Non-existent files are "already deleted"
    
    def test_timestomp(self):
        """Test timestamp manipulation"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            filepath = f.name
        
        try:
            result = SecureCleanup.timestomp(filepath)
            self.assertTrue(result)
            
            # Check timestamp was modified
            stat = os.stat(filepath)
            self.assertEqual(stat.st_mtime, 1577836800)  # 2020-01-01
        finally:
            os.remove(filepath)


class TestGhostProtocol(unittest.TestCase):
    """Test main GhostProtocol interface"""
    
    def test_initialization(self):
        """Test GhostProtocol initialization"""
        ghost = GhostProtocol()
        self.assertIsNotNone(ghost.transformer)
        self.assertIsNotNone(ghost.encryptor)
        self.assertIsNotNone(ghost.cleanup)
    
    def test_obfuscate_code(self):
        """Test code obfuscation through main interface"""
        ghost = GhostProtocol(enable_dead_code=False)
        code = "x = 10\nprint(x)"
        result = ghost.obfuscate_code(code)
        self.assertIsInstance(result, str)
    
    def test_encrypt_decrypt_xor(self):
        """Test string encryption/decryption XOR"""
        ghost = GhostProtocol()
        original = "secret message"
        encrypted = ghost.encrypt_string(original, "xor")
        decrypted = ghost.decrypt_string(encrypted, "xor")
        self.assertEqual(decrypted, original)
    
    def test_encrypt_decrypt_base64(self):
        """Test string encryption/decryption base64"""
        ghost = GhostProtocol()
        original = "secret message"
        encrypted = ghost.encrypt_string(original, "base64")
        decrypted = ghost.decrypt_string(encrypted, "base64")
        self.assertEqual(decrypted, original)
    
    def test_singleton(self):
        """Test get_ghost_protocol returns same instance"""
        ghost1 = get_ghost_protocol()
        ghost2 = get_ghost_protocol()
        self.assertIs(ghost1, ghost2)
    
    def test_cleanup_session(self):
        """Test session cleanup"""
        ghost = GhostProtocol()
        
        # Create temp files
        files = []
        for _ in range(3):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(b"temp data")
                files.append(f.name)
        
        # Cleanup
        deleted = ghost.cleanup_session(files)
        
        self.assertEqual(deleted, 3)
        for f in files:
            self.assertFalse(os.path.exists(f))


class TestObfuscateFunction(unittest.TestCase):
    """Test module-level obfuscate function"""
    
    def test_quick_obfuscate(self):
        """Test quick obfuscate function"""
        code = "message = 'hello'\nprint(message)"
        result = obfuscate(code)
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
