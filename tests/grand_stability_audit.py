
import asyncio
import os
import sys
import psutil
import json
import logging
import random
import time
from unittest.mock import MagicMock, AsyncMock

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.brain import ContinuousReasoning, ExecutionContext
from core.tool_parsers import _smart_truncate, parse_nmap_output
from core.state import AgentState, VulnerabilityInfo, ServiceInfo
from core.execution_engine import ExecutionEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("Audit")

class StabilityAudit:
    def __init__(self):
        self.results = {"passed": 0, "failed": 0, "warnings": 0}
        self.process = psutil.Process(os.getpid())

    def log_result(self, name, success, msg=""):
        status = "✅ PASS" if success else "❌ FAIL"
        if success: self.results["passed"] += 1
        else: self.results["failed"] += 1
        print(f"[{status}] {name}: {msg}")

    def test_llm_fuzzing(self):
        print("\n--- 1. LLM Resilience Fuzzing ---")
        mock_llm = MagicMock()
        brain = ContinuousReasoning(llm_client=mock_llm)
        context = ExecutionContext()
        
        fuzz_payloads = [
            (None, "None response"),
            ("", "Empty string"),
            ("Not JSON at all", "Random text"),
            ('{"intent": "chat"', "Partial JSON"),
            ('{"intent": "chat", "extra": "data"}', "Missing required fields"),
            ('{"success": true, "intent": "scan", "steps": []}', "Valid but empty"),
            ('Here is the JSON: {"success": true, "intent": "chat", "response": "hi"}', "Mixed text/JSON")
        ]

        for payload, desc in fuzz_payloads:
            mock_llm.query.return_value = payload
            try:
                # Mock reasoning.analyze to test its internal json parsing
                result = brain.analyze("hello", context)
                success = isinstance(result, dict) and "intent" in result
                self.log_result(f"Fuzz: {desc}", success, f"Result: {result.get('intent', 'ERROR')}")
            except Exception as e:
                self.log_result(f"Fuzz: {desc}", False, f"Crashed: {e}")

    def test_token_and_memory_stress(self):
        print("\n--- 2. Token & Memory Stress ---")
        # 1MB of nmap-like output
        massive_output = "80/tcp open http\n" + ("Useless line " * 10 + "\n") * 50000 
        
        start_mem = self.process.memory_info().rss / 1024 / 1024
        truncated = _smart_truncate(massive_output, ["open"])
        end_mem = self.process.memory_info().rss / 1024 / 1024
        
        success = len(truncated) < 5000 # Should be very small
        leak_check = (end_mem - start_mem) < 50 # Should not spike more than 50MB for this ops
        
        self.log_result("Smart Truncate Efficiency", success, f"Reduced {len(massive_output)} to {len(truncated)}")
        self.log_result("Memory Stability", leak_check, f"Mem growth: {end_mem - start_mem:.2f}MB")

    def test_cross_platform_parsing(self):
        print("\n--- 3. Cross-Platform Parsing Verification ---")
        # Test Nmap with different line endings and spacing
        variants = [
            "80/tcp  open  http  Apache\r\n", # Windows Style
            "443/tcp open  https\n",          # Linux Style
            "  22/tcp open ssh  OpenSSH 8.2\n", # Extra spacing
            "8080/tcp open  http-proxy\n"      # No version
        ]
        
        for v in variants:
            res = parse_nmap_output(v)
            success = len(res) > 0 and res[0]["port"] in [80, 443, 22, 8080]
            self.log_result(f"Parse Variant: {v.strip()}", success)

    def test_state_persistence(self):
        print("\n--- 4. Agent State Persistence Audit ---")
        # AgentState is a singleton, reset for test
        from core.state import reset_state
        state = reset_state("127.0.0.1")
        
        # Add a service first so vulnerabilities can be linked
        state.update_services([ServiceInfo(port=80, protocol="tcp", service="http")])

        # Simulate many updates
        for i in range(1000):
            vuln = VulnerabilityInfo(
                vuln_id=f"CVE-{i}",
                service="http",
                port=80,
                severity="HIGH",
                exploitable=True
            )
            state.add_vulnerability(vuln)
        
        self.log_result("Vulnerabilities Count", len(state.vulnerabilities) == 1000)
        
        # Test footprint
        mem_kb = sys.getsizeof(state.vulnerabilities) / 1024
        self.log_result("State Memory Footprint", mem_kb < 1000, f"Size: {mem_kb:.2f}KB")

    async def run_all_async(self):
        print("=== DRAKBEN GRAND STABILITY AUDIT ===")
        self.test_llm_fuzzing()
        self.test_token_and_memory_stress()
        self.test_cross_platform_parsing()
        self.test_state_persistence()
        
        print(f"\nAudit Summary: {self.results['passed']} Passed, {self.results['failed']} Failed")
        return self.results['failed'] == 0

if __name__ == "__main__":
    audit = StabilityAudit()
    success = asyncio.run(audit.run_all_async())
    sys.exit(0 if success else 1)
