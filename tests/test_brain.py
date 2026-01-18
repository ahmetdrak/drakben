"""
Test suite for llm.brain module
"""

import pytest
from unittest.mock import Mock, patch
from llm.brain import DrakbenBrain


class TestDrakbenBrain:
    """Test cases for DrakbenBrain LLM integration"""
    
    def test_brain_initialization(self):
        """Test brain initializes correctly"""
        brain = DrakbenBrain()
        assert brain is not None
        assert hasattr(brain, 'think')
    
    def test_think_method(self):
        """Test think method"""
        brain = DrakbenBrain()
        
        # Should work in offline mode
        result = brain.think("scan 192.168.1.100")
        assert result is not None
        assert "intent" in result
    
    def test_fallback_mode(self):
        """Test fallback mode when API unavailable"""
        brain = DrakbenBrain()
        
        # Should work in offline mode
        result = brain.think("help")
        assert result is not None
        assert "reply" in result or "intent" in result
    
    def test_turkish_command(self):
        """Test Turkish command processing"""
        brain = DrakbenBrain()
        
        turkish_command = "tarama yap"
        result = brain.think(turkish_command)
        
        assert result is not None
    
    def test_english_command(self):
        """Test English command processing"""
        brain = DrakbenBrain()
        
        english_command = "scan target"
        result = brain.think(english_command)
        
        assert result is not None
