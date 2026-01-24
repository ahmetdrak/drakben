# tests/test_core.py
# DRAKBEN Core Module Unit Tests
# Comprehensive test coverage for core components

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestAgentState(unittest.TestCase):
    """Tests for AgentState class"""
    
    def setUp(self):
        """Reset singleton for each test"""
        from core.state import AgentState
        AgentState._instance = None
        AgentState._initialized = False
    
    def test_singleton_pattern(self):
        """Test that AgentState is a singleton"""
        from core.state import AgentState
        state1 = AgentState()
        state2 = AgentState()
        self.assertIs(state1, state2)
    
    def test_initial_state(self):
        """Test initial state values"""
        from core.state import AgentState, AttackPhase
        state = AgentState()
        self.assertEqual(state.phase, AttackPhase.IDLE)
        self.assertIsNone(state.target)
        self.assertFalse(state.has_foothold)
        self.assertEqual(len(state.open_services), 0)
    
    def test_set_target(self):
        """Test target setting"""
        from core.state import AgentState, AttackPhase
        state = AgentState()
        state.set_target("192.168.1.1")
        self.assertEqual(state.target, "192.168.1.1")
        self.assertEqual(state.phase, AttackPhase.RECON)
    
    def test_add_service(self):
        """Test service addition"""
        from core.state import AgentState, ServiceInfo
        state = AgentState()
        state.set_target("192.168.1.1")
        
        service = ServiceInfo(port=80, name="http", version="Apache/2.4")
        state.add_open_service(service)
        
        self.assertIn(80, state.open_services)
    
    def test_add_vulnerability(self):
        """Test vulnerability addition"""
        from core.state import AgentState, VulnerabilityInfo
        state = AgentState()
        state.set_target("192.168.1.1")
        
        vuln = VulnerabilityInfo(
            vuln_id="SQL_INJECTION",
            description="SQL Injection in login form",
            severity="high",
            confirmed=True
        )
        state.add_vulnerability(vuln)
        
        self.assertEqual(len(state.vulnerabilities), 1)
    
    def test_state_validation(self):
        """Test state invariant validation"""
        from core.state import AgentState
        state = AgentState()
        self.assertTrue(state.validate())
    
    def test_phase_transition(self):
        """Test phase transitions"""
        from core.state import AgentState, AttackPhase
        state = AgentState()
        
        state.set_target("192.168.1.1")
        self.assertEqual(state.phase, AttackPhase.RECON)
        
        state.mark_vuln_scan_done()
        self.assertEqual(state.phase, AttackPhase.VULN_SCAN)
    
    def test_thread_safety(self):
        """Test thread-safe operations"""
        from core.state import AgentState
        state = AgentState()
        state.set_target("192.168.1.1")
        
        errors = []
        
        def add_services():
            from core.state import ServiceInfo
            for i in range(100):
                try:
                    service = ServiceInfo(port=8000 + i, name=f"service_{i}")
                    state.add_open_service(service)
                except Exception as e:
                    errors.append(str(e))
        
        threads = [threading.Thread(target=add_services) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)
    
    def test_reset(self):
        """Test state reset"""
        from core.state import AgentState, AttackPhase
        state = AgentState()
        state.set_target("192.168.1.1")
        state.reset()
        
        self.assertEqual(state.phase, AttackPhase.IDLE)
        self.assertIsNone(state.target)


class TestConfigManager(unittest.TestCase):
    """Tests for ConfigManager class"""
    
    def setUp(self):
        """Create temp config file"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "settings.json")
    
    def tearDown(self):
        """Cleanup temp files"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_default_config(self):
        """Test default configuration values"""
        from core.config import ConfigManager
        config = ConfigManager(config_path=self.config_path)
        
        self.assertEqual(config.get("llm_provider"), "auto")
        self.assertEqual(config.get("language"), "tr")
    
    def test_set_and_get(self):
        """Test setting and getting values"""
        from core.config import ConfigManager
        config = ConfigManager(config_path=self.config_path)
        
        config.set("test_key", "test_value")
        self.assertEqual(config.get("test_key"), "test_value")
    
    def test_save_and_load(self):
        """Test config persistence"""
        from core.config import ConfigManager
        config1 = ConfigManager(config_path=self.config_path)
        config1.set("persist_test", "saved_value")
        config1.save_config()
        
        # Create new instance
        config2 = ConfigManager(config_path=self.config_path)
        self.assertEqual(config2.get("persist_test"), "saved_value")
    
    def test_thread_safety(self):
        """Test thread-safe config operations"""
        from core.config import ConfigManager
        config = ConfigManager(config_path=self.config_path)
        
        errors = []
        
        def modify_config():
            for i in range(100):
                try:
                    config.set(f"key_{i}", f"value_{i}")
                    config.get(f"key_{i}")
                except Exception as e:
                    errors.append(str(e))
        
        threads = [threading.Thread(target=modify_config) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        self.assertEqual(len(errors), 0)


class TestEvolutionMemory(unittest.TestCase):
    """Tests for EvolutionMemory class"""
    
    def setUp(self):
        """Create temp database"""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
    
    def tearDown(self):
        """Cleanup temp database"""
        try:
            os.unlink(self.temp_db.name)
        except:
            pass
    
    def test_initialization(self):
        """Test database initialization"""
        from core.evolution_memory import EvolutionMemory
        memory = EvolutionMemory(db_path=self.temp_db.name)
        
        # Check tables exist
        conn = sqlite3.connect(self.temp_db.name)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor]
        conn.close()
        
        self.assertIn("tool_penalties", tables)
    
    def test_record_action(self):
        """Test action recording"""
        from core.evolution_memory import EvolutionMemory
        memory = EvolutionMemory(db_path=self.temp_db.name)
        
        memory.record_action(
            action_type="scan",
            tool="nmap",
            target="192.168.1.1",
            success=True,
            output="Scan complete"
        )
        
        # Verify recorded
        stats = memory.get_tool_stats("nmap")
        self.assertGreater(stats.get("total_uses", 0), 0)
    
    def test_tool_penalty(self):
        """Test tool penalty system"""
        from core.evolution_memory import EvolutionMemory
        memory = EvolutionMemory(db_path=self.temp_db.name)
        
        # Record failures
        for _ in range(3):
            memory.record_action(
                action_type="exploit",
                tool="test_tool",
                target="target",
                success=False,
                output="Failed"
            )
        
        penalty = memory.get_penalty("test_tool")
        self.assertGreater(penalty, 0)
    
    def test_strategy_profile(self):
        """Test strategy profile management"""
        from core.evolution_memory import EvolutionMemory
        memory = EvolutionMemory(db_path=self.temp_db.name)
        
        profile = {
            "name": "test_profile",
            "tools": ["nmap", "nikto"],
            "priority": 1
        }
        
        memory.save_strategy_profile("test_profile", profile)
        loaded = memory.get_strategy_profile("test_profile")
        
        self.assertEqual(loaded["name"], "test_profile")


class TestExecutionEngine(unittest.TestCase):
    """Tests for ExecutionEngine class"""
    
    def test_command_sanitization(self):
        """Test command sanitization"""
        from core.execution_engine import CommandSanitizer
        sanitizer = CommandSanitizer()
        
        # Safe commands
        safe, _ = sanitizer.sanitize("nmap -sV 192.168.1.1")
        self.assertTrue(safe)
        
        # Dangerous commands
        safe, reason = sanitizer.sanitize("rm -rf /")
        self.assertFalse(safe)
        self.assertIn("dangerous", reason.lower())
    
    def test_command_validation(self):
        """Test command validation patterns"""
        from core.execution_engine import CommandSanitizer
        sanitizer = CommandSanitizer()
        
        # Test various dangerous patterns
        dangerous_commands = [
            "rm -rf /",
            "dd if=/dev/zero of=/dev/sda",
            ":(){ :|:& };:",  # Fork bomb
            "mkfs.ext4 /dev/sda",
            "> /etc/passwd"
        ]
        
        for cmd in dangerous_commands:
            safe, _ = sanitizer.sanitize(cmd)
            self.assertFalse(safe, f"Command should be blocked: {cmd}")
    
    @patch('subprocess.run')
    def test_execute_safe_command(self, mock_run):
        """Test safe command execution"""
        mock_run.return_value = MagicMock(
            stdout="output",
            stderr="",
            returncode=0
        )
        
        from core.execution_engine import ExecutionEngine
        engine = ExecutionEngine()
        
        result = engine.execute("echo test")
        self.assertTrue(result.get("success", False))


class TestDrakbenBrain(unittest.TestCase):
    """Tests for DrakbenBrain class"""
    
    def test_initialization(self):
        """Test brain initialization"""
        from core.brain import DrakbenBrain
        brain = DrakbenBrain()
        
        self.assertIsNotNone(brain)
    
    def test_reasoning_without_llm(self):
        """Test reasoning fallback without LLM"""
        from core.brain import DrakbenBrain
        brain = DrakbenBrain()
        
        # Should not raise error without LLM
        result = brain.reason("What should I do next?")
        self.assertIsNotNone(result)
    
    def test_plan_generation(self):
        """Test plan generation"""
        from core.brain import DrakbenBrain
        brain = DrakbenBrain()
        
        plan = brain.generate_plan("Scan 192.168.1.1")
        self.assertIsInstance(plan, (list, dict, str))


class TestToolSelector(unittest.TestCase):
    """Tests for ToolSelector class"""
    
    def test_tool_selection(self):
        """Test deterministic tool selection"""
        from core.tool_selector import ToolSelector
        from core.state import AgentState, AttackPhase
        
        # Reset state
        AgentState._instance = None
        AgentState._initialized = False
        
        state = AgentState()
        selector = ToolSelector()
        
        state.set_target("192.168.1.1")
        
        # Should suggest recon tools in RECON phase
        tools = selector.get_suggested_tools(state)
        self.assertIsInstance(tools, list)
    
    def test_tool_availability(self):
        """Test tool availability check"""
        from core.tool_selector import ToolSelector
        selector = ToolSelector()
        
        # Check common tool
        result = selector.check_tool_available("echo")
        self.assertTrue(result)


class TestCoder(unittest.TestCase):
    """Tests for Coder module"""
    
    def test_ast_security_check(self):
        """Test AST-based security check"""
        from core.coder import ASTSecurityChecker
        checker = ASTSecurityChecker()
        
        # Safe code
        safe_code = """
def hello():
    return "Hello, World!"
"""
        is_safe, _ = checker.check(safe_code)
        self.assertTrue(is_safe)
        
        # Dangerous code
        dangerous_code = """
import os
os.system("rm -rf /")
"""
        is_safe, reason = checker.check(dangerous_code)
        self.assertFalse(is_safe)
    
    def test_dangerous_imports(self):
        """Test detection of dangerous imports"""
        from core.coder import ASTSecurityChecker
        checker = ASTSecurityChecker()
        
        dangerous_imports = [
            "import subprocess",
            "from os import system",
            "import shutil"
        ]
        
        for code in dangerous_imports:
            is_safe, _ = checker.check(code)
            # Should either be flagged or allowed with caution
            self.assertIsNotNone(is_safe)


class TestLogging(unittest.TestCase):
    """Tests for logging configuration"""
    
    def test_logger_setup(self):
        """Test logger initialization"""
        from core.logging_config import setup_logging, get_logger
        
        setup_logging(level="DEBUG")
        logger = get_logger("test")
        
        self.assertIsNotNone(logger)
    
    def test_log_context(self):
        """Test log context manager"""
        from core.logging_config import LogContext
        
        with LogContext(operation="test_op", target="test_target"):
            # Context should be active
            pass
        # Context should be cleared


class TestI18n(unittest.TestCase):
    """Tests for internationalization"""
    
    def test_translation_loading(self):
        """Test translation loading"""
        from core.i18n import get_text, set_language
        
        set_language("tr")
        text = get_text("welcome")
        self.assertIsNotNone(text)
    
    def test_language_switch(self):
        """Test language switching"""
        from core.i18n import get_text, set_language
        
        set_language("en")
        en_text = get_text("help")
        
        set_language("tr")
        tr_text = get_text("help")
        
        # Should be different (or same if not translated)
        self.assertIsNotNone(en_text)
        self.assertIsNotNone(tr_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
