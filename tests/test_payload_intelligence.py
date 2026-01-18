"""
Test suite for core.payload_intelligence module
"""

import pytest
from core.payload_intelligence import PayloadIntelligence


class TestPayloadIntelligence:
    """Test cases for PayloadIntelligence class"""
    
    def test_payload_generation(self):
        """Test basic payload generation"""
        payload_gen = PayloadIntelligence()
        
        payload = payload_gen.generate_reverse_shell("192.168.1.10", 4444, shell_type="bash")
        
        assert payload is not None
        assert "192.168.1.10" in payload
        assert "4444" in payload
    
    def test_obfuscation_base64(self):
        """Test base64 obfuscation"""
        payload_gen = PayloadIntelligence()
        
        original = "echo 'test'"
        obfuscated = payload_gen.obfuscate(original, method="base64")
        
        assert obfuscated != original
        assert len(obfuscated) > len(original)
    
    def test_obfuscation_hex(self):
        """Test hex obfuscation"""
        payload_gen = PayloadIntelligence()
        
        original = "whoami"
        obfuscated = payload_gen.obfuscate(original, method="hex")
        
        assert obfuscated != original
    
    def test_payload_types(self):
        """Test different payload types"""
        payload_gen = PayloadIntelligence()
        
        types = ["bash", "python", "powershell", "perl"]
        
        for ptype in types:
            payload = payload_gen.generate_reverse_shell("10.0.0.1", 4444, shell_type=ptype)
            assert payload is not None
    
    def test_sqli_payload_generation(self):
        """Test SQL injection payload generation"""
        payload_gen = PayloadIntelligence()
        
        sqli = payload_gen.generate_sqli_payload(injection_type="union")
        
        assert "UNION" in sqli or "union" in sqli
        assert "SELECT" in sqli or "select" in sqli
