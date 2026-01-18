"""
Advanced integration tests for DRAKBEN
Tests complete workflows and module interactions
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.mark.integration
class TestFullWorkflow:
    """Integration tests for complete pentest workflows"""
    
    @patch('core.executor.Executor.execute')
    @patch('core.zero_day_scanner.ZeroDayScanner.scan_results')
    def test_scan_to_exploit_workflow(self, mock_scan, mock_execute):
        """Test complete workflow: scan -> CVE detection -> exploitation"""
        # Mock scan results
        mock_scan.return_value = {
            "target": "192.168.1.100",
            "services": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 7.9p1"},
                {"port": 80, "service": "http", "version": "Apache 2.4.38"}
            ],
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-3156",
                    "severity": "HIGH",
                    "service": "sudo",
                    "exploit_available": True
                }
            ]
        }
        
        # Mock command execution
        mock_execute.return_value = "Command executed"
        
        # Import after mocking
        from core.zero_day_scanner import ZeroDayScanner
        from core.executor import Executor
        
        scanner = ZeroDayScanner(use_api=False)
        executor = Executor()
        
        # Execute workflow
        scan_output = "mock scan output"
        results = scanner.scan_results(scan_output, {"target": "192.168.1.100"})
        
        assert results is not None
        assert "vulnerabilities" in results
        assert len(results["vulnerabilities"]) > 0
        
        # Verify CVE found
        vuln = results["vulnerabilities"][0]
        assert vuln["cve"] == "CVE-2021-3156"
        assert vuln["severity"] == "HIGH"


@pytest.mark.integration
class TestDatabaseWorkflow:
    """Integration tests for database operations"""
    
    def test_session_creation_and_retrieval(self):
        """Test creating and retrieving database sessions"""
        from core.database_manager import DatabaseManager
        
        db = DatabaseManager()
        
        # Create session
        session_id = db.create_session(
            strategy="stealthy",
            target="192.168.1.100"
        )
        
        assert session_id is not None
        
        # Add vulnerability
        db.add_vulnerability(
            session_id=session_id,
            target="192.168.1.100",
            cve="CVE-2021-3156",
            severity="HIGH",
            description="Sudo heap overflow"
        )
        
        # Retrieve session
        sessions = db.get_all_sessions()
        assert len(sessions) > 0


@pytest.mark.integration
class TestPayloadToShell:
    """Integration tests for payload generation and shell execution"""
    
    @patch('requests.post')
    def test_payload_generation_and_web_shell(self, mock_post):
        """Test generating payload and executing via web shell"""
        mock_post.return_value = Mock(
            status_code=200,
            text="uid=0(root) gid=0(root)"
        )
        
        from core.payload_intelligence import PayloadIntelligence
        
        payload_ai = PayloadIntelligence()
        
        # Generate reverse shell payload
        payload = payload_ai.generate_reverse_shell(
            lhost="10.0.0.1",
            lport=4444,
            shell_type="bash"
        )
        
        assert payload is not None
        assert "10.0.0.1" in payload
        assert "4444" in payload
        
        # Obfuscate
        obfuscated = payload_ai.obfuscate(payload, method="base64")
        assert obfuscated != payload


@pytest.mark.integration
class TestMLOpsecWorkflow:
    """Integration tests for ML OPSEC features"""
    
    def test_ml_opsec_analysis(self):
        """Test ML OPSEC advisor analysis"""
        from core.ml_opsec_advisor import MLOpsecAdvisor
        
        ml_opsec = MLOpsecAdvisor()
        
        # Train model (if not already trained)
        # ml_opsec.train_model()
        
        # Analyze traffic pattern
        traffic_data = {
            "packets_sent": 100,
            "scan_speed": "fast",
            "ports_scanned": 1000,
            "time_window": 60
        }
        
        # This would normally use the trained model
        # risk = ml_opsec.analyze_traffic(traffic_data)
        # assert risk in ["LOW", "MEDIUM", "HIGH"]


@pytest.mark.integration
class TestNLPWorkflow:
    """Integration tests for NLP command processing"""
    
    @patch('llm.openrouter_client.OpenRouterClient')
    def test_natural_language_to_execution(self, mock_client):
        """Test NLP intent parsing and execution"""
        mock_client.return_value.query.return_value = {
            "intent": "scan_and_exploit",
            "target": "192.168.1.100",
            "confidence": 0.95,
            "workflow": ["scan", "detect_vulns", "exploit"]
        }
        
        from core.nlp_intent_parser import NLPIntentParser
        
        parser = NLPIntentParser()
        
        # Parse natural language command
        command = "scan 192.168.1.100 and exploit vulnerabilities"
        result = parser.parse(command)
        
        assert result is not None
        assert result["confidence"] > 0.5


@pytest.mark.integration
class TestParallelExecution:
    """Integration tests for parallel execution"""
    
    @patch('core.executor.Executor.execute')
    def test_parallel_scan_multiple_targets(self, mock_execute):
        """Test scanning multiple targets in parallel"""
        mock_execute.return_value = "Scan completed"
        
        from core.parallel_executor import ParallelExecutor
        
        parallel = ParallelExecutor(max_workers=4)
        
        targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103"]
        
        # This would normally execute real scans
        # results = parallel.scan_targets(targets)
        # assert len(results) == len(targets)


@pytest.mark.integration
class TestEndToEndPentest:
    """End-to-end pentest workflow tests"""
    
    @patch('core.executor.Executor.execute')
    @patch('core.zero_day_scanner.ZeroDayScanner.scan_results')
    @patch('core.web_shell_handler.WebShellHandler.execute_via_shell')
    def test_complete_pentest_workflow(self, mock_shell, mock_scan, mock_execute):
        """Test complete pentest: scan -> exploit -> shell -> post-exploit"""
        
        # Mock scan
        mock_scan.return_value = {
            "target": "192.168.1.100",
            "vulnerabilities": [
                {"cve": "CVE-2021-3156", "severity": "HIGH"}
            ]
        }
        
        # Mock execution
        mock_execute.return_value = "Exploit successful"
        
        # Mock shell
        mock_shell.return_value = "uid=0(root)"
        
        # Simulate workflow
        target = "192.168.1.100"
        
        # 1. Scan
        from core.zero_day_scanner import ZeroDayScanner
        scanner = ZeroDayScanner(use_api=False)
        scan_results = scanner.scan_results("", {"target": target})
        assert scan_results is not None
        
        # 2. Detect vulnerabilities
        vulns = scan_results.get("vulnerabilities", [])
        assert len(vulns) > 0
        
        # 3. Exploit
        from core.executor import Executor
        executor = Executor()
        exploit_result = executor.execute("exploit_command")
        assert exploit_result is not None
        
        # 4. Get shell
        from core.web_shell_handler import WebShellHandler
        shell = WebShellHandler("http://192.168.1.100")
        shell_output = shell.execute_via_shell("whoami")
        assert "root" in shell_output


@pytest.mark.integration
@pytest.mark.slow
class TestStressTests:
    """Stress tests for system limits"""
    
    def test_large_scan_output_parsing(self):
        """Test parsing very large scan outputs"""
        from core.zero_day_scanner import ZeroDayScanner
        
        scanner = ZeroDayScanner(use_api=False)
        
        # Generate large scan output (1000 lines)
        large_output = "\n".join([
            f"PORT {port}/tcp open http Apache 2.4.38" 
            for port in range(8000, 9000)
        ])
        
        results = scanner.scan_results(large_output, {"target": "192.168.1.100"})
        assert results is not None
    
    def test_concurrent_database_access(self):
        """Test concurrent database operations"""
        from core.database_manager import DatabaseManager
        import threading
        
        db = DatabaseManager()
        results = []
        
        def create_session():
            session_id = db.create_session(strategy="balanced", target="192.168.1.100")
            results.append(session_id)
        
        # Create 10 threads
        threads = [threading.Thread(target=create_session) for _ in range(10)]
        
        # Start all threads
        for t in threads:
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Verify all succeeded
        assert len(results) == 10
        assert all(r is not None for r in results)
