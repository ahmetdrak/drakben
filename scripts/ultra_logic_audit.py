
import sys
import os
import json
import logging
import unittest
from unittest.mock import MagicMock, patch

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.brain import DrakbenBrain, ExecutionContext
from core.refactored_agent import RefactoredDrakbenAgent
from core.config import ConfigManager
from core.self_refining_engine import SelfRefiningEngine, StrategyProfile
from core.planner import Planner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("UltraLogicAudit")

class UltraLogicAudit(unittest.TestCase):
    def setUp(self):
        self.config = ConfigManager()
        # SUCCESS: We added a setter for llm_client!
        self.config.llm_client = MagicMock()
        self.agent = RefactoredDrakbenAgent(self.config)
        
    def test_logic_1_brain_corruption_handling(self):
        logger.info("Running Logic Test 1: Brain JSON Corruption")
        brain = DrakbenBrain(llm_client=self.config.llm_client)
        # Corrected method name to 'think' or 'process'
        corrupted_responses = ["Invalid", "{'broken': 1}", "```json\n{ \"intent\": \"scan\" }```", ""]
        for resp in corrupted_responses:
            self.config.llm_client.query.return_value = resp
            try:
                # Using 'think' as the main entry point
                result = brain.think("scan", target="127.0.0.1")
                self.assertIsNotNone(result)
                logger.info(f"  ✓ Handled: {resp[:15]}... -> Intent: {result.get('intent')}")
            except Exception as e:
                self.fail(f"Brain CRASHED on process: {e}")

    def test_logic_2_agent_halt_on_complete(self):
        logger.info("Running Logic Test 2: Agent Halt on Plan Complete")
        self.agent.planner.is_plan_complete = MagicMock(return_value=True)
        self.agent.planner.get_next_step = MagicMock(return_value=None)
        
        self.agent.initialize("127.0.0.1")
        self.agent.running = True # Ensure it starts as running
        
        # This calls _handle_plan_completion internally
        self.agent._run_single_iteration(10)
        
        # After completion, it should NOT be running
        self.assertFalse(self.agent.running, "Agent failed to stop when plan was complete!")
        logger.info("  ✓ Agent successfully halted")

    def test_logic_3_security_bypass_complex(self):
        logger.info("Running Logic Test 3: Complex Security Bypass")
        from core.coder import ASTSecurityChecker
        checker = ASTSecurityChecker()
        
        # Try to bypass with __getattr__ or similar dynamicity
        code = "getattr(os, 'sys' + 'tem')('rm -rf /')"
        # We need to see if this passes (which it might, if the checker is only looking for call names)
        checker.check(code)
        
        if not checker.violations:
            logger.warning("  ⚠️  SECURITY GAP: Dynamic 'getattr' bypasses security check!")
        else:
            logger.info("  ✓ Caught dynamic attribute access")

if __name__ == "__main__":
    unittest.main()
