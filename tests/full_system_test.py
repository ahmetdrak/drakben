import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import json
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.refactored_agent import RefactoredDrakbenAgent
from core.brain import ContinuousReasoning, ExecutionContext
from core.tool_parsers import parse_nmap_output, _smart_truncate
from core.self_healer import SelfHealer
from core.planner import Planner
from modules.ad_attacks import ActiveDirectoryAttacker

# Configure logging to show only critical info during tests
logging.basicConfig(level=logging.CRITICAL)

class TestDrakbenSystem(unittest.TestCase):
    """
    Comprehensive System Test for DRAKBEN Agent.
    Tests all major components: Brain, Planner, Healer, Parsers, AD Module.
    """

    def setUp(self):
        # Mock LLM Client
        self.mock_llm = MagicMock()
        self.mock_llm.query.return_value = '{"success": true, "response": "Mocked response"}'
        
        # Initialize Brain with Mock LLM
        self.brain = ContinuousReasoning(llm_client=self.mock_llm)
        self.context = ExecutionContext()

    def test_01_brain_fast_path(self):
        """Test Step 1: Brain Fast Path (Latency Fix)"""
        print("\n[TEST] 🧠 Brain Fast Path / Caching...")
        
        # Test Simple Greeting (Should NOT call LLM)
        self.mock_llm.query.reset_mock()
        result = self.brain.analyze("merhaba", self.context)
        
        self.assertEqual(result["intent"], "chat")
        self.assertTrue("Fast-path" in result["reasoning"])
        self.mock_llm.query.assert_not_called()
        print("✅ Fast path worked for 'merhaba' (No LLM call)")

        # Test Complex Request (Should call LLM)
        self.brain.analyze("target 192.168.1.1 scan ports", self.context)
        self.mock_llm.query.assert_called()
        print("✅ Normal path worked for complex request (LLM called)")

    def test_02_planner_fallback(self):
        """Test Step 2: Planner Fallback Logic"""
        print("\n[TEST] 📋 Planner Fallback...")
        
        planner = Planner()
        # Mock memory to simulate "no profile found" or empty DB
        planner.memory = MagicMock()
        
        # Test fallback plan creation
        plan_id = planner.create_plan_for_target("127.0.0.1")
        self.assertTrue(plan_id.startswith("plan_"))
        self.assertTrue(len(planner.steps) > 0)
        self.assertEqual(planner.steps[0].tool, "nmap_port_scan")
        print("✅ Default plan created successfully when no profile exists")

    def test_03_smart_truncation(self):
        """Test Step 3: Smart Truncation (Token Saver)"""
        print("\n[TEST] ✂️ Smart Truncation...")
        
        # Create a massive fake output
        huge_output = "Header Info\n" + ("Useless Line\n" * 1000) + "80/tcp open http\n" + ("Useless Footer\n" * 500)
        
        # Truncate
        truncated = _smart_truncate(huge_output, ["open"])
        
        self.assertTrue(len(truncated) < len(huge_output))
        self.assertIn("80/tcp open http", truncated)
        # Context lines mean some useless lines WILL remain, so we check if count is drastically reduced
        self.assertTrue(truncated.count("Useless Line") < 50) 
        print(f"✅ Truncation reduced {len(huge_output)} chars to {len(truncated)} chars")

    def test_04_self_healing_diagnosis(self):
        """Test Step 4: Self Healer Diagnosis"""
        print("\n[TEST] 🚑 Self Healer Diagnosis...")
        
        # Mock Agent
        mock_agent = MagicMock()
        mock_agent.brain = self.brain
        healer = SelfHealer(mock_agent)
        
        # Test "Command not found"
        diagnosis = healer._diagnose_error("bash: nmap: command not found", 127)
        self.assertEqual(diagnosis["type"], "missing_tool")
        print("✅ Correctly diagnosed 'missing_tool'")
        
        # Test "Permission denied"
        diagnosis = healer._diagnose_error("error: permission denied trying to bind port 80", 1)
        self.assertEqual(diagnosis["type"], "permission_denied")
        print("✅ Correctly diagnosed 'permission_denied'")

    @patch("core.self_healer.SelfHealer._heal_missing_tool")
    def test_05_healing_logic_flow(self, mock_heal_missing):
        """Test Step 5: Healing Logic Integration"""
        print("\n[TEST] 🔄 Healing Flow...")
        
        # Configure the mock to return a tuple (healed, result)
        mock_heal_missing.return_value = (True, MagicMock(exit_code=0))
        
        mock_agent = MagicMock()
        mock_agent.executor.terminal.execute.return_value.exit_code = 127
        mock_agent.executor.terminal.execute.return_value.stderr = "nmap: command not found"
        
        healer = SelfHealer(mock_agent)
        
        # Call handle failure
        # We assume format_result_callback just returns the dict
        healer.handle_tool_failure("nmap", "nmap -sS target", 
                                 mock_agent.executor.terminal.execute.return_value, 
                                 {}, lambda r, a: {})
        
        # Verify our mock was called (proving the logic flowed to the specific healer)
        mock_heal_missing.assert_called()
        print("✅ Healing flow logic verified")

    def test_06_ad_module(self):
        """Test Step 6: Active Directory Module"""
        print("\n[TEST] 🏢 AD Module...")
        
        ad_attacker = ActiveDirectoryAttacker()
        
        # Test Plan Generation
        plan = ad_attacker.get_attack_plan("corp.local", "10.0.0.5")
        self.assertEqual(len(plan), 2)
        self.assertEqual(plan[0]["tool"], "kerbrute")
        self.assertEqual(plan[1]["tool"], "impacket")
        print("✅ AD Attack Plan generated correctly")

    def test_07_agent_full_init(self):
        """Test Step 7: Full Agent Initialization"""
        print("\n[TEST] 🤖 Full Agent Initialization...")
        
        # Mock dependencies to prevent real file/DB access issues during test
        with patch('core.refactored_agent.get_evolution_memory'), \
             patch('core.refactored_agent.DrakbenLogger'):
            
            mock_config = MagicMock()
            mock_config.llm_client = self.mock_llm
            
            agent = RefactoredDrakbenAgent(config_manager=mock_config)
            self.assertIsNotNone(agent.healer)
            self.assertIsNotNone(agent.ad_attacker)
            self.assertIsNotNone(agent.planner)
            print("✅ Agent initialized with all new modules (Healer, AD, Planner)")

if __name__ == '__main__':
    unittest.main()

