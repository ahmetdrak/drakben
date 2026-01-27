
import asyncio
import threading
import time
import sys
import os
import logging
from dataclasses import asdict
from typing import List

# Setup project path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.state import AgentState, AttackPhase, ServiceInfo, VulnerabilityInfo, reset_state
from core.planner import Planner, StepStatus, PlanStep
from core.refactored_agent import RefactoredDrakbenAgent
from core.config import ConfigManager

# Configure Logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("NuclearTest")

class NuclearTest:
    def __init__(self):
        self.results = []

    def log_result(self, name, status, message=""):
        self.results.append({"name": name, "status": status, "message": message})
        icon = "✅" if status else "❌"
        print(f"{icon} {name}: {message}")

    def test_thread_safety_stress(self):
        """Stress test the AgentState singleton with concurrent modifications"""
        state = reset_state("127.0.0.1")
        threads = []
        errors = []

        def worker(thread_id):
            try:
                for i in range(100):
                    state.update_services([
                        ServiceInfo(port=1000+thread_id*100+i, protocol="tcp", service="stress")
                    ])
                    state.add_vulnerability(VulnerabilityInfo(
                        vuln_id=f"VULN_{thread_id}_{i}", service="stress", port=1000, severity="HIGH", exploitable=True
                    ))
            except Exception as e:
                errors.append(e)

        for i in range(10): # 10 threads
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        success = len(errors) == 0 and len(state.open_services) == 1000
        self.log_result("Thread Safety Stress", success, f"Processed 1000 concurrent updates. Errors: {len(errors)}")

    def test_planner_dependency_cascade(self):
        """Test if planner correctly handles a deep dependency chain with a failure in the middle"""
        planner = Planner()
        target = "10.0.0.1"
        plan_id = f"test_cascade_{int(time.time())}"
        
        # Create a manually forced plan with 5 steps
        steps = []
        for i in range(1, 6):
            steps.append({
                "step_id": f"step_{i}",
                "action": f"action_{i}",
                "tool": f"tool_{i}",
                "target": target,
                "depends_on": [f"step_{i-1}"] if i > 1 else [],
                "status": "pending",
                "max_retries": 1,
                "retry_count": 0
            })
        
        planner.memory.create_plan("test", steps, plan_id=plan_id)
        planner.load_plan(plan_id)

        # 1. Execute step 1 success
        planner.get_next_step()
        planner.mark_step_success("step_1", "ok")

        # 2. Execute step 2 failure (no more retries)
        planner.get_next_step()
        planner.mark_step_failed("step_2", "CRITICAL ERROR") # Trigger failure

        # 3. Check if planner allows step 3
        s3 = planner.get_next_step()
        
        # In current logic, if step 2 fails, step 3 (which depends on 2) should NOT be returned by get_next_step
        success = s3 is None or s3.step_id != "step_3"
        self.log_result("Planner Dependency Cascade", success, "Blocked downstream steps after upstream failure.")

    def test_state_invariant_enforcement(self):
        """Manually violate invariants and ensure validate() catches them"""
        state = reset_state("10.0.0.1")
        
        # Violation: post_exploit done but no foothold
        state.post_exploit_completed.add("dump_hashes")
        v1 = state.validate()
        r1 = any("Post-exploit attempted without foothold" in v for v in state.invariant_violations)
        
        # Reset and another violation: Exploit phase but no services
        state = reset_state("10.0.0.2")
        state.phase = AttackPhase.EXPLOIT
        v2 = state.validate()
        r2 = any("Exploit phase without discovered services" in v for v in state.invariant_violations)
        
        success = (not v1 and r1) and (not v2 and r2)
        self.log_result("State Invariant Enforcement", success, "Caught logical inconsistencies in state.")

    def test_loop_protection_limits(self):
        """Ensure agent halt logic triggers on repeated tool calls"""
        state = reset_state("10.0.0.3")
        
        # Simulate 4 identical tool calls (consecutive limit is 3, needs 4 calls to get 3 successive 'same' events)
        for _ in range(4):
            state.record_tool_call("nmap")
        
        should_halt, reason = state.should_halt()
        success = should_halt and "times consecutively" in reason
        self.log_result("Loop Protection (Same Tool)", success, f"Halted after repetitions. Reason: {reason}")

    def test_hallucination_detection_accuracy(self):
        """Test the hallucination checker with deceptive outputs"""
        state = reset_state("10.0.0.4")
        
        # Deceptive output: exit code 1 but LLM claims 'SUCCESS!'
        h1 = state.check_hallucination("exploit_tool", 1, "Exploit finished successfully!", True)
        
        # Deceptive output: exploit claimed success but NO 'shell' or 'session' in output
        h2 = state.check_hallucination("msf_exploit", 0, "Exploit completed. Target hit.", True)
        
        # Real success: should NOT be a hallucination
        h3 = state.check_hallucination("msf_exploit", 0, "Session 1 opened!", True)
        
        success = h1 and h2 and not h3
        self.log_result("Hallucination Detection", success, "Correctly identified deceptive LLM claims.")

    def run_all(self):
        print("\n☢️  DRAKBEN NUCLEAR STRESS TEST - ZERO ASSUMPTION MODE ☢️\n")
        self.test_thread_safety_stress()
        self.test_planner_dependency_cascade()
        self.test_state_invariant_enforcement()
        self.test_loop_protection_limits()
        self.test_hallucination_detection_accuracy()
        
        failed = [t for t in self.results if not t['status']]
        if not failed:
            print("\n✅ NUCLEAR TEST COMPLETE: THE CORE IS STABLE. NO LEAKS DETECTED.\n")
        else:
            print(f"\n❌ NUCLEAR TEST FAILED: {len(failed)} critical vulnerabilities in logic!\n")
            sys.exit(1)

if __name__ == "__main__":
    NuclearTest().run_all()
