
import unittest
import os
import json
import time
import threading
import math
from unittest.mock import MagicMock, patch
from core.state import AgentState, AttackPhase, ServiceInfo, VulnerabilityInfo, reset_state
from core.evolution_memory import EvolutionMemory, get_evolution_memory
from core.execution_engine import SmartTerminal, CommandSanitizer, ExecutionStatus
from core.refactored_agent import RefactoredDrakbenAgent
from core.config import ConfigManager

class FormalAuditTest(unittest.TestCase):
    def setUp(self):
        # Use a fresh target for each test to avoid interference
        self.target = "1.1.1.1"
        reset_state(self.target)

    def test_logic_01_state_reinit_wipeout(self):
        """Audit: Does AgentState(target) reset existing state?"""
        state = AgentState(self.target)
        state.phase = AttackPhase.RECON
        state.update_services([ServiceInfo(port=80, protocol="tcp", service="http")])
        
        # Call constructor again with the same target
        new_state = AgentState(self.target)
        
        # If it re-initialized, services would be 0
        if len(new_state.open_services) == 0:
            print("❌ LOGIC ERROR 1: AgentState(target) wiped out the state!")
            self.fail("State wipeout on re-initialization")
        else:
            print("✅ State preserved on re-initialization.")

    def test_logic_02_field_loss_on_recovery(self):
        """Audit: Are non-core fields lost during save/load (recovery)?"""
        state = AgentState(self.target)
        state.record_tool_call("nmap")
        state.record_tool_call("nmap")
        state.hallucination_flags.append("test_hallucination")
        state.iteration_count = 5
        
        # Save and load
        state.save()
        
        # Create a clean state instance (forcing a reload in a real scenario, here we simulate)
        # Note: AgentState is a singleton, so we need to bypass or reload fields
        clean_state_data = state.to_dict()
        
        # Check if history and flags were even in the dict
        # Based on my audit, they are NOT in to_dict() or from_dict()
        if "tool_call_history" not in clean_state_data:
             print("❌ LOGIC ERROR 2: tool_call_history missing from to_dict (persistence loss)!")
        
        if len(state.hallucination_flags) > 0 and "hallucination_flags" not in clean_state_data:
             print("❌ LOGIC ERROR 2: hallucination_flags missing from to_dict (persistence loss)!")

    def test_logic_03_evolution_heuristic_ignore(self):
        """Audit: Does update_penalty ignore the database heuristic?"""
        try:
            # Create a test DB
            db_path = "test_evolution.db"
            if os.path.exists(db_path): os.remove(db_path)
            
            ev = EvolutionMemory(db_path)
            # Change the heuristic in DB
            ev.set_heuristic("penalty_increment", 50.0)
            
            # Record a failure
            ev.update_penalty("test_tool", success=False)
            
            # Check penalty
            penalty = ev.get_tool_penalty("test_tool")
            
            # It SHOULD be 50.0 if it uses the heuristic, but 10.0 if hardcoded
            if math.isclose(penalty, 10.0):
                print("❌ LOGIC ERROR 10: update_penalty used hardcoded increment (10.0) instead of DB heuristic (50.0)!")
            elif math.isclose(penalty, 0.0):
                print("❌ Something went wrong, penalty is 0")
            else:
                print(f"✅ Penalty system uses heuristic: {penalty}")
        finally:
            if os.path.exists(db_path): os.remove(db_path)

    def test_logic_04_terminal_thread_safety(self):
        """Audit: Does SmartTerminal handle concurrent execution process tracking?"""
        term = SmartTerminal()
        
        # We'll mock process creation to verify the overlap.
        with patch.object(term, '_create_process') as mock_create:
            mock_proc1 = MagicMock()
            mock_proc1.pid = 123
            mock_proc2 = MagicMock()
            mock_proc2.pid = 456
            
            # Thread 1 starts proc1
            def thread1_work():
                term.current_process = mock_proc1
                # Wait for signal to cancel
                time.sleep(0.5)
                term.cancel_current()

            # Thread 2 starts proc2
            def thread2_work():
                term.current_process = mock_proc2
                # thread 2 does NOT cancel, just exists
            
            t1 = threading.Thread(target=thread1_work)
            t2 = threading.Thread(target=thread2_work)
            
            t1.start()
            time.sleep(0.1) # Ensure t1 sets current_process
            t2.start()
            t1.join()
            t2.join()
            
            # Did t1.cancel_current() kill proc1?
            if mock_proc1.kill.called or mock_proc1.terminate.called:
                print("✅ Thread safe: cancelled own process.")
            else:
                # On Windows _terminate_process_group calls taskkill but we mocked .kill/.terminate too?
                # Actually _terminate_process_group calls process.kill() if taskkill fails/windows
                # In mock, we check if it was called.
                print("❌ LOGIC ERROR 7: SmartTerminal.cancel_current() failed to kill own process!")
                self.fail("Thread safety failure")
            
            # Did it kill proc2?
            if mock_proc2.kill.called or mock_proc2.terminate.called:
                print("❌ LOGIC ERROR 7: SmartTerminal killed another thread's process!")
                self.fail("Cross-thread process killing")
            else:
                 print("✅ Thread safe: did not kill other thread's process.")

    def test_logic_05_foothold_false_positive(self):
        """Audit: Can deceptive output trigger a foothold?"""
        config = MagicMock(spec=ConfigManager)
        agent = RefactoredDrakbenAgent(config)
        agent.state = reset_state(self.target)
        
        # Deceptive result: a tool called "exploit_something" outputting innocent text that contains "shell"
        # e.g. a vulnerability scanner script that mentions "Checking for shell injection..."
        deceptive_result = {
            "success": True,
            "stdout": "Scanning... found script: check_shell_cmd.sh",
            "stderr": ""
        }
        
        agent._update_state_from_result("vuln_scanner_meta", deceptive_result, "Finished scan")
        
        # If it was incorrectly dispatched to _process_exploit_result (which it would be if tool name has exploit, 
        # or if dispatching logic is vague)
        
        # Let's test _process_exploit_result specifically
        agent._process_exploit_result("vulnerability_scanner", deceptive_result)
        
        if agent.state.has_foothold:
             print("❌ LOGIC ERROR 6: Deceptive output 'shell' in stdout triggered a false foothold!")
        else:
             print("✅ Foothold detection resisted the simple 'shell' keyword check (or was lucky).")

    def test_all_logic_audit(self):
        """Manual execution of the test suite (CLI helper)"""
        print("\n🔍 DRAKBEN FORMAL LOGIC AUDIT - ZERO ASSUMPTIONS 🔍\n")
        self.setUp()
        
        tests = [
            ("State Re-init Wipeout", self.test_logic_01_state_reinit_wipeout),
            ("Persistence Field Loss", self.test_logic_02_field_loss_on_recovery),
            ("Heuristic System Bypass", self.test_logic_03_evolution_heuristic_ignore),
            ("Terminal Thread Safety", self.test_logic_04_terminal_thread_safety),
            ("Foothold False Positive", self.test_logic_05_foothold_false_positive)
        ]
        
        for name, func in tests:
            try:
                func()
            except AssertionError as e:
                print(f"❌ FAILED: {name} - {e}")
            except Exception as e:
                print(f"💥 CRASHED: {name} - {e}")
                
        print("\n--- AUDIT COMPLETE ---\n")

if __name__ == "__main__":
    audit = FormalAuditTest()
    audit.test_all_logic_audit()
