# tests/test_modules.py
# DRAKBEN Module Unit Tests
# Tests for recon, exploit, payload, and other modules

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestReconModule(unittest.TestCase):
    """Tests for Recon module"""
    
    def setUp(self):
        """Reset state singleton"""
        from core.state import AgentState, reset_state
        # Reset state fully
        reset_state("test_target")
    
    def test_domain_extraction(self):
        """Test domain extraction from URL"""
        from modules.recon import extract_domain
        
        test_cases = [
            ("https://example.com/path", "example.com"),
            ("http://sub.example.com:8080/", "sub.example.com"),
            ("example.com", "example.com"),
            ("https://192.168.1.1:443/", "192.168.1.1"),
        ]
        
        for url, expected in test_cases:
            result = extract_domain(url)
            self.assertEqual(result, expected)
    
    @patch('aiohttp.ClientSession')
    def test_passive_recon(self, mock_session):
        """Test passive recon function"""
        from modules.recon import passive_recon
        
        # Mock response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {"Server": "Apache/2.4"}
        mock_response.text = AsyncMock(return_value="<html></html>")
        
        mock_session_instance = MagicMock()
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session_instance.get = MagicMock(return_value=mock_response)
        mock_session.return_value = mock_session_instance
        
        # Run test
        async def run_test():
            result = await passive_recon("https://example.com")
            return result
        
        result = asyncio.run(run_test())
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("target"), "https://example.com")
    
    def test_cms_detection_patterns(self):
        """Test CMS detection patterns"""
        from modules.recon import detect_cms
        
        test_html = '<meta name="generator" content="WordPress 5.9">'
        cms = detect_cms(test_html, {})
        
        self.assertIsNotNone(cms)
    
    def test_technology_detection(self):
        """Test technology detection from headers"""
        from modules.recon import detect_technologies
        
        headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/8.0",
            "X-AspNet-Version": "4.0"
        }
        
        techs = detect_technologies("", headers)
        self.assertIsInstance(techs, list)


class TestExploitModule(unittest.TestCase):
    """Tests for Exploit module"""
    
    def setUp(self):
        """Reset state singleton"""
        from core.state import AgentState, reset_state
        reset_state("test_target")
    
    def test_precondition_check_no_state(self):
        """Test precondition check without state"""
        from modules.exploit import check_exploit_preconditions
        
        can_exploit, _ = check_exploit_preconditions(None, "target", "sqli")
        self.assertFalse(can_exploit)
    
    def test_precondition_check_no_target(self):
        """Test precondition check without target"""
        from modules.exploit import check_exploit_preconditions
        from core.state import AgentState
        
        state = AgentState()
        can_exploit, _ = check_exploit_preconditions(state, "", "sqli")
        self.assertFalse(can_exploit)
    
    def test_precondition_check_wrong_phase(self):
        """Test precondition check in wrong phase"""
        from modules.exploit import check_exploit_preconditions
        from core.state import AgentState, AttackPhase, get_state
        
        state = get_state()
        state.target = "192.168.1.1" # Manually set target
        # State is in RECON phase, not EXPLOIT
        
        can_exploit, reason = check_exploit_preconditions(state, "192.168.1.1:80", "sqli")
        self.assertFalse(can_exploit)
        self.assertIn("phase", reason.lower())    
    
    def test_retry_config(self):
        """Test RetryConfig defaults"""
        from modules.exploit import RetryConfig
        
        config = RetryConfig()
        self.assertEqual(config.max_retries, 3)
        self.assertEqual(config.base_delay, 1.0)
    
    def test_exploit_suggestion(self):
        """Test exploit suggestion"""
        from modules.exploit import suggest_exploit
        
        vuln_types = ["sql_injection", "xss", "lfi", "rce"]
        
        for vuln in vuln_types:
            suggestion = suggest_exploit(vuln)
            self.assertIsInstance(suggestion, (dict, str, type(None)))


class TestPayloadModule(unittest.TestCase):
    """Tests for Payload module"""
    
    def setUp(self):
        """Reset state singleton"""
        from core.state import AgentState, reset_state
        reset_state("test_target")
    
    def test_precondition_check_no_foothold(self):
        """Test payload precondition without foothold"""
        from modules.payload import check_payload_preconditions
        from core.state import AgentState, get_state
        
        state = get_state()
        state.target = "192.168.1.1"
        
        can_execute, reason = check_payload_preconditions(state)
        self.assertFalse(can_execute)
        self.assertIn("foothold", reason.lower())

    def test_payload_generation(self):
        """Test payload generation"""
        from modules.payload import generate_payload
        from core.state import AgentState, get_state
        
        state = get_state()
        # Ensure preconditions met
        state.target = "192.168.1.1"
        state.update_services([]) # Mock scan done
        state.set_foothold("test") # Mock foothold
        
        payload = generate_payload(state, "reverse_shell_bash", lhost="192.168.1.100", lport=4444)
        self.assertIsInstance(payload, dict)
        self.assertTrue(payload.get("success", False))
        self.assertIn("192.168.1.100", payload["code"])
        self.assertIn("4444", payload["code"])


class TestCVEDatabase(unittest.TestCase):
    """Tests for CVE Database module"""
    
    def setUp(self):
        """Create temp database"""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
    
    def tearDown(self):
        """Cleanup temp database"""
        try:
            os.unlink(self.temp_db.name)
        except Exception:
            pass
    
    def test_database_initialization(self):
        """Test CVE database initialization"""
        from modules.cve_database import CVEDatabase
        
        db = CVEDatabase(db_path=self.temp_db.name)
        stats = db.get_cache_stats()
        
        self.assertIn("cve_entries", stats)
        self.assertEqual(stats["cve_entries"], 0)
    
    def test_severity_classification(self):
        """Test CVSS severity classification"""
        from modules.cve_database import CVEDatabase, CVSSSeverity
        
        db = CVEDatabase(db_path=self.temp_db.name)
        
        test_cases = [
            (0.0, CVSSSeverity.NONE),
            (2.5, CVSSSeverity.LOW),
            (5.0, CVSSSeverity.MEDIUM),
            (7.5, CVSSSeverity.HIGH),
            (9.5, CVSSSeverity.CRITICAL),
        ]
        
        for score, expected in test_cases:
            result = db._get_severity(score)
            self.assertEqual(result, expected)
    
    def test_keyword_extraction(self):
        """Test keyword extraction"""
        from modules.cve_database import CVEDatabase
        
        db = CVEDatabase(db_path=self.temp_db.name)
        
        text = "SQL injection vulnerability in Apache HTTP Server allows remote attackers"
        keywords = db._extract_keywords(text)
        
        self.assertIn("injection", keywords)
        self.assertIn("vulnerability", keywords)
    
    def test_cache_operations(self):
        """Test cache save/load operations"""
        from modules.cve_database import CVEDatabase, CVEEntry, CVSSSeverity
        
        db = CVEDatabase(db_path=self.temp_db.name)
        
        entry = CVEEntry(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            severity=CVSSSeverity.CRITICAL,
            published_date="2021-12-10",
            last_modified="2021-12-15",
            references=["https://example.com"],
            cpe_matches=["cpe:2.3:a:apache:log4j:*"],
            weaknesses=["CWE-917"]
        )
        
        db._save_to_cache(entry)
        loaded = db._get_from_cache("CVE-2021-44228")
        
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.cve_id, "CVE-2021-44228")


class TestReportGenerator(unittest.TestCase):
    """Tests for Report Generator module"""
    
    def setUp(self):
        """Create temp directory"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Cleanup temp directory"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_report_initialization(self):
        """Test report generator initialization"""
        from modules.report_generator import ReportGenerator, ReportConfig
        
        config = ReportConfig(
            title="Test Report",
            author="Test Author"
        )
        generator = ReportGenerator(config)
        
        self.assertEqual(generator.config.title, "Test Report")
    
    def test_add_finding(self):
        """Test adding findings"""
        from modules.report_generator import ReportGenerator, Finding, FindingSeverity
        
        generator = ReportGenerator()
        finding = Finding(
            title="SQL Injection",
            severity=FindingSeverity.HIGH,
            description="SQL injection in login form",
            affected_asset="https://example.com/login"
        )
        
        generator.add_finding(finding)
        self.assertEqual(len(generator.findings), 1)
    
    def test_statistics_calculation(self):
        """Test statistics calculation"""
        from modules.report_generator import ReportGenerator, Finding, FindingSeverity
        
        generator = ReportGenerator()
        generator.add_finding(Finding(
            title="Critical Bug",
            severity=FindingSeverity.CRITICAL,
            description="Critical",
            affected_asset="target"
        ))
        generator.add_finding(Finding(
            title="High Bug",
            severity=FindingSeverity.HIGH,
            description="High",
            affected_asset="target"
        ))
        
        stats = generator.get_statistics()
        
        self.assertEqual(stats["total_findings"], 2)
        self.assertEqual(stats["severity_breakdown"]["critical"], 1)
        self.assertEqual(stats["severity_breakdown"]["high"], 1)
    
    def test_html_generation(self):
        """Test HTML report generation"""
        from modules.report_generator import ReportGenerator, Finding, FindingSeverity, ReportFormat
        
        generator = ReportGenerator()
        generator.set_target("https://example.com")
        generator.add_finding(Finding(
            title="XSS",
            severity=FindingSeverity.MEDIUM,
            description="Cross-site scripting",
            affected_asset="https://example.com/search"
        ))
        
        output_path = os.path.join(self.temp_dir, "report.html")
        result = generator.generate(ReportFormat.HTML, output_path)
        
        self.assertTrue(os.path.exists(result))
        
        with open(result, 'r') as f:
            content = f.read()
            self.assertIn("XSS", content)
            self.assertIn("example.com", content)
    
    def test_markdown_generation(self):
        """Test Markdown report generation"""
        from modules.report_generator import ReportGenerator, ReportFormat
        
        generator = ReportGenerator()
        generator.set_target("192.168.1.1")
        
        output_path = os.path.join(self.temp_dir, "report.md")
        result = generator.generate(ReportFormat.MARKDOWN, output_path)
        
        self.assertTrue(os.path.exists(result))
    
    def test_json_generation(self):
        """Test JSON report generation"""
        from modules.report_generator import ReportGenerator, ReportFormat
        
        generator = ReportGenerator()
        generator.set_target("192.168.1.1")
        
        output_path = os.path.join(self.temp_dir, "report.json")
        result = generator.generate(ReportFormat.JSON, output_path)
        
        self.assertTrue(os.path.exists(result))
        
        with open(result, 'r') as f:
            data = json.load(f)
            self.assertIn("metadata", data)
            self.assertIn("findings", data)


class TestLLMClient(unittest.TestCase):
    """Tests for LLM client"""
    
    def test_cache_operations(self):
        """Test LLM cache operations"""
        from llm.openrouter_client import LLMCache
        
        cache = LLMCache()
        
        # Test set and get
        cache.set("prompt1", "system", "model1", "response1")
        result = cache.get("prompt1", "system", "model1")
        
        self.assertEqual(result, "response1")
    
    def test_cache_miss(self):
        """Test cache miss"""
        from llm.openrouter_client import LLMCache
        
        cache = LLMCache()
        result = cache.get("nonexistent", "system", "model")
        
        self.assertIsNone(result)
    
    def test_rate_limiter(self):
        """Test rate limiter"""
        from llm.openrouter_client import RateLimiter
        
        limiter = RateLimiter()
        
        # Should allow immediate call
        acquired = limiter.acquire()
        self.assertTrue(acquired)
    
    def test_cache_hit_rate(self):
        """Test cache hit rate calculation"""
        from llm.openrouter_client import LLMCache
        
        cache = LLMCache()
        
        # Add some entries
        cache.set("p1", "s", "m1", "r1")
        cache.set("p2", "s", "m1", "r2")
        
        # Get hits
        cache.get("p1", "s", "m1")
        cache.get("p2", "s", "m1")
        
        # Get miss
        cache.get("p3", "s", "m1")
        
        stats = cache.get_stats()
        hit_rate = stats["hit_rate"]
        self.assertGreaterEqual(hit_rate, 0)
        self.assertLessEqual(hit_rate, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
