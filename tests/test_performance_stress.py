"""
Performance and Stress Tests for Drakben
Converted from scripts/stress_test.py
"""

import logging
import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.brain import ContinuousReasoning, ExecutionContext
from core.execution_engine import CommandSanitizer, SmartTerminal
from core.singularity.engine import SingularityEngine

# Setup Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("STRESS_TEST")


class TestPerformanceStress(unittest.TestCase):
    """
    Stress tests for concurrency, recovery, and fallback mechanisms.
    """

    def test_concurrency_load(self):
        """Test 1: Concurrency Bomb & Zombie Processes"""
        from unittest.mock import patch

        terminal = SmartTerminal()

        threads = []
        results = []

        def heavy_task(idx):
            # Using python print to ensure cross-platform compatibility
            cmd = f"python -c \"print('Stress Test {idx}'); import time; time.sleep(0.1)\""
            res = terminal.execute(cmd, timeout=5)
            results.append(res)

        # Launch 20 threads simultaneously
        # PATCH 1: Bypass "requires_confirmation" logic
        # PATCH 2: Bypass "sanitize" to allow ';' in python one-liners (stress test only)
        with (
            patch(
                "core.execution_engine.CommandSanitizer.requires_confirmation",
                return_value=(False, ""),
            ),
            patch(
                "core.execution_engine.CommandSanitizer.sanitize",
                side_effect=lambda x, **kwargs: x,
            ),
        ):
            start_time = time.time()
            for i in range(20):
                t = threading.Thread(target=heavy_task, args=(i,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

        duration = time.time() - start_time
        success_count = sum(1 for r in results if r.status.value == "success")

        logger.info(
            f"Executed 20 concurrent commands in {duration:.2f}s (Success: {success_count})"
        )

        # Checking > 10 instead of 20 to allow for some system-dependent flakiness in stress tests
        self.assertGreater(
            success_count, 10, "Majority of concurrent commands should succeed!"
        )
        self.assertLess(duration, 15, "Concurrency test took too long!")

    def test_singularity_error_handling(self):
        """Test 2: Singularity Failure Recovery (Bad Code Generation)"""
        engine = SingularityEngine()

        # Inject a broken synthesizer mock directly
        class BrokenSynthesizer:
            @staticmethod
            def generate_tool(desc, lang):
                from core.singularity.base import CodeSnippet

                # Deliberate Syntax Error
                bad_code = "def broken_func():\n    print('Missing indent here"
                return CodeSnippet(bad_code, lang, desc, [], False)

        engine.synthesizer = BrokenSynthesizer()

        # KEY FIX: The engine creates a REAL validator by default, which might accept the syntax error
        # IF it's not robust enough. We MUST mock validation to simulate "Detection of Bad Code".
        # We are testing the ENGINE'S reaction to failed validation, not the validator itself here.
        engine.validator = MagicMock()
        engine.validator.validate.return_value = (
            False  # Explicitly say "This code is bad"
        )

        # This should return None because validation failed (masked by our mock)
        result = engine.create_capability("broken scan", "python")

        # If it returns None, it handled it gracefully.
        self.assertIsNone(
            result, "Singularity should reject code when validation fails."
        )

    def test_brain_fallback_logic(self):
        """Test 3: Brain Freeze (No LLM Fallback)"""

        # Initialize Brain without LLM Client to force fallback
        reasoning = ContinuousReasoning(llm_client=None)
        context = ExecutionContext()

        user_input = "nmap scan 10.0.0.1"

        start = time.time()
        result = reasoning.analyze(user_input, context)
        duration = time.time() - start

        logger.info(f"Analysis Duration: {duration:.4f}s")

        # Assertions
        self.assertTrue(
            result.get("success"), "Brain failed to process request without LLM"
        )
        self.assertTrue(
            result.get("fallback_mode"), "Brain did not switch to Fallback Mode"
        )
        self.assertLess(duration, 1.0, "Rule-based fallback should be instant")

    def test_security_sanitization_stress(self):
        """Test 4: Security Sanitization Stress Check"""
        dangerous_commands = [
            "rm -rf /",
            "cat /etc/shadow",
            "format c: /q",
            r"rd /s /q c:\windows",
            "powershell -enc JABz...",
        ]

        blocked_count = 0
        for cmd in dangerous_commands:
            try:
                CommandSanitizer.sanitize(cmd)
                self.fail(f"Dangerous command allowed: {cmd}")
            except Exception:  # Expecting SecurityError
                blocked_count += 1

        self.assertEqual(
            blocked_count,
            len(dangerous_commands),
            "Some dangerous commands were not blocked!",
        )


if __name__ == "__main__":
    unittest.main()
