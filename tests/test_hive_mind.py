"""Tests for Hive Mind module"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.hive_mind import (
    ADAnalyzer,
    AttackPath,
    Credential,
    CredentialHarvester,
    CredentialType,
    HiveMind,
    LateralMover,
    MovementTechnique,
    NetworkHost,
    NetworkMapper,
    get_hive_mind,
    quick_recon,
)


class TestCredentialHarvester(unittest.TestCase):
    """Test credential harvesting"""

    def setUp(self):
        self.harvester = CredentialHarvester()

    def test_initialization(self):
        """Test harvester initialization"""
        self.assertIsNotNone(self.harvester.harvested)
        self.assertEqual(len(self.harvester.harvested), 0)

    def test_harvest_ssh_keys(self):
        """Test SSH key harvesting"""
        # This will find keys if they exist on the system
        keys = self.harvester.harvest_ssh_keys()
        self.assertIsInstance(keys, list)

    def test_harvest_known_hosts(self):
        """Test known_hosts parsing"""
        hosts = self.harvester.harvest_known_hosts()
        self.assertIsInstance(hosts, list)

    def test_harvest_environment(self):
        """Test environment variable harvesting"""
        # Set a test env var
        os.environ["TEST_PASSWORD_VAR"] = "test_secret_123"

        creds = self.harvester.harvest_environment()

        # Clean up
        del os.environ["TEST_PASSWORD_VAR"]

        # Should have found our test credential
        found = any(
            c.source == "environment" and "TEST_PASSWORD" in c.username for c in creds
        )
        self.assertTrue(found)

    def test_get_all_credentials(self):
        """Test getting all harvested credentials"""
        # Add a test credential
        cred = Credential(
            username="testuser",
            domain="testdomain",
            credential_type=CredentialType.PASSWORD,
            value="testpass",
            source="test",
        )
        self.harvester.harvested.append(cred)

        all_creds = self.harvester.get_all_credentials()
        self.assertEqual(len(all_creds), 1)
        self.assertEqual(all_creds[0].username, "testuser")


class TestNetworkMapper(unittest.TestCase):
    """Test network mapping functionality"""

    def setUp(self):
        self.mapper = NetworkMapper()

    def test_initialization(self):
        """Test mapper initialization"""
        self.assertEqual(len(self.mapper.discovered_hosts), 0)

    def test_get_local_interfaces(self):
        """Test getting local network interfaces"""
        interfaces = self.mapper.get_local_interfaces()
        self.assertIsInstance(interfaces, list)

    def test_get_local_subnet(self):
        """Test subnet calculation"""
        subnet = self.mapper.get_local_subnet("192.168.1.100")
        self.assertIn("192.168.1", subnet)
        self.assertIn("/24", subnet)

    def test_guess_service(self):
        """Test service name guessing"""
        self.assertEqual(self.mapper._guess_service(22), "ssh")
        self.assertEqual(self.mapper._guess_service(80), "http")
        self.assertEqual(self.mapper._guess_service(443), "https")
        self.assertEqual(self.mapper._guess_service(3389), "rdp")
        self.assertEqual(self.mapper._guess_service(445), "microsoft-ds")

    def test_is_windows_host(self):
        """Test Windows host detection"""
        windows_host = NetworkHost(ip="192.168.1.1", ports=[135, 445, 3389])
        linux_host = NetworkHost(ip="192.168.1.2", ports=[22, 80])

        self.assertTrue(self.mapper.is_windows_host(windows_host))
        self.assertFalse(self.mapper.is_windows_host(linux_host))

    def test_is_linux_host(self):
        """Test Linux host detection"""
        linux_host = NetworkHost(ip="192.168.1.2", ports=[22, 80])
        windows_host = NetworkHost(ip="192.168.1.1", ports=[135, 445])

        self.assertTrue(self.mapper.is_linux_host(linux_host))
        self.assertFalse(self.mapper.is_linux_host(windows_host))

    def test_find_pivot_points(self):
        """Test pivot point detection"""
        pivot = NetworkHost(ip="192.168.1.1", ports=[22, 80, 443, 8080])
        non_pivot = NetworkHost(ip="192.168.1.2", ports=[80])

        self.mapper.discovered_hosts["192.168.1.1"] = pivot
        self.mapper.discovered_hosts["192.168.1.2"] = non_pivot

        pivots = self.mapper.find_pivot_points()
        self.assertEqual(len(pivots), 1)
        self.assertEqual(pivots[0].ip, "192.168.1.1")


class TestADAnalyzer(unittest.TestCase):
    """Test Active Directory analysis"""

    def setUp(self):
        self.analyzer = ADAnalyzer()

    def test_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNone(self.analyzer.domain_info)
        self.assertEqual(len(self.analyzer.attack_paths), 0)

    def test_detect_domain(self):
        """Test domain detection"""
        # This will return None if not on a domain
        domain = self.analyzer.detect_domain()
        # Just verify it returns something (string or None)
        self.assertTrue(domain is None or isinstance(domain, str))

    def test_get_kerberoastable_users(self):
        """Test kerberoastable user patterns"""
        users = self.analyzer.get_kerberoastable_users()
        self.assertIsInstance(users, list)
        self.assertGreater(len(users), 0)

    def test_calculate_attack_path(self):
        """Test attack path calculation"""
        source = "192.168.1.1"
        target = "192.168.1.100"

        hosts = {
            source: NetworkHost(ip=source, ports=[22]),
            target: NetworkHost(ip=target, ports=[22, 80]),
        }

        path = self.analyzer.calculate_attack_path(
            source=source, target=target, available_creds=[], discovered_hosts=hosts
        )

        self.assertIsNotNone(path)
        self.assertEqual(path.source, source)
        self.assertEqual(path.target, target)

    def test_cyclic_attack_path(self):
        """Test detection and prevention of infinite attack loops (A->B->A)"""
        # Set up a circular graph
        hosts = {
            "HostA": NetworkHost(ip="10.0.0.1", ports=[22]),  # Has key to B
            "HostB": NetworkHost(ip="10.0.0.2", ports=[22]),  # Has key to A
        }

        # This implementation requires the mocked logic to support graph traversal
        # Since the current 'calculate_attack_path' is a placeholder,
        # we will verify that it doesn't crash or return an infinite list

        path = self.analyzer.calculate_attack_path("HostA", "HostB", [], hosts)

        if path:
            # Ensure no duplicates in hops
            self.assertEqual(
                len(path.hops), len(set(path.hops)), "Cycle detected in attack path!"
            )

    def test_scope_enforcement(self):
        """Test that attack paths do not include out-of-scope targets"""
        source = "192.168.1.1"
        target = "8.8.8.8"  # Out of scope

        # If we explicitly define authorized_scope (to be implemented), this should fail
        # For now, we ensure the function handles unknown targets gracefully

        hosts = {source: NetworkHost(ip=source)}

        path = self.analyzer.calculate_attack_path(source, target, [], hosts)

        # Should detect target is unreachable or not in discovered hosts
        self.assertIsNone(
            path, "Attack path generated for unknown/out-of-scope target!"
        )


class TestLateralMover(unittest.TestCase):
    """Test lateral movement engine"""

    def setUp(self):
        self.mover = LateralMover()

    def test_initialization(self):
        """Test mover initialization"""
        self.assertEqual(len(self.mover.successful_moves), 0)
        self.assertEqual(len(self.mover.failed_moves), 0)

    def test_generate_pth_command(self):
        """Test Pass-the-Hash command generation"""
        cmd = self.mover.generate_pth_command(
            target="192.168.1.100",
            username="administrator",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee",
        )

        self.assertIn("psexec.py", cmd)
        self.assertIn("192.168.1.100", cmd)
        self.assertIn("-hashes", cmd)

    def test_generate_pth_command_with_domain(self):
        """Test PTH command with domain username"""
        cmd = self.mover.generate_pth_command(
            target="192.168.1.100",
            username="DOMAIN\\administrator",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee",
        )

        self.assertIn("DOMAIN/administrator", cmd)

    def test_generate_ptt_command(self):
        """Test Pass-the-Ticket command generation"""
        cmd = self.mover.generate_ptt_command(
            target="192.168.1.100", ticket_path="/tmp/ticket.ccache"
        )

        self.assertIn("KRB5CCNAME", cmd)
        self.assertIn("-k", cmd)
        self.assertIn("-no-pass", cmd)

    def test_get_movement_stats(self):
        """Test movement statistics"""
        stats = self.mover.get_movement_stats()

        self.assertIn("successful", stats)
        self.assertIn("failed", stats)
        self.assertIn("techniques_used", stats)
        self.assertIn("targets_compromised", stats)


class TestHiveMind(unittest.TestCase):
    """Test main HiveMind orchestrator"""

    def setUp(self):
        self.hive = HiveMind()

    def test_initialization(self):
        """Test HiveMind initialization"""
        self.assertIsNotNone(self.hive.harvester)
        self.assertIsNotNone(self.hive.mapper)
        self.assertIsNotNone(self.hive.ad_analyzer)
        self.assertIsNotNone(self.hive.mover)
        self.assertFalse(self.hive.initialized)

    def test_initialize(self):
        """Test HiveMind initialization process"""
        results = self.hive.initialize()

        self.assertIn("interfaces", results)
        self.assertIn("domain", results)
        self.assertIn("credentials_found", results)
        self.assertTrue(self.hive.initialized)

    def test_get_status(self):
        """Test status retrieval"""
        status = self.hive.get_status()

        self.assertIn("initialized", status)
        self.assertIn("current_host", status)
        self.assertIn("credentials", status)
        self.assertIn("discovered_hosts", status)

    def test_find_attack_paths_empty(self):
        """Test attack path finding with no hosts"""
        paths = self.hive.find_attack_paths()
        self.assertIsInstance(paths, list)

    def test_singleton(self):
        """Test get_hive_mind returns same instance"""
        hive1 = get_hive_mind()
        hive2 = get_hive_mind()
        self.assertIs(hive1, hive2)


class TestQuickRecon(unittest.TestCase):
    """Test quick_recon helper function"""

    def test_quick_recon(self):
        """Test quick reconnaissance function"""
        results = quick_recon()

        self.assertIn("interfaces", results)
        self.assertIn("domain", results)
        self.assertIn("credentials_found", results)


class TestDataClasses(unittest.TestCase):
    """Test data class creation"""

    def test_credential_creation(self):
        """Test Credential dataclass"""
        cred = Credential(
            username="admin",
            domain="example.com",
            credential_type=CredentialType.PASSWORD,
            value="password123",
            source="test",
        )

        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.credential_type, CredentialType.PASSWORD)
        self.assertTrue(cred.valid)

    def test_network_host_creation(self):
        """Test NetworkHost dataclass"""
        host = NetworkHost(ip="192.168.1.1", hostname="server1", ports=[22, 80, 443])

        self.assertEqual(host.ip, "192.168.1.1")
        self.assertEqual(len(host.ports), 3)
        self.assertFalse(host.compromised)

    def test_attack_path_creation(self):
        """Test AttackPath dataclass"""
        path = AttackPath(
            source="192.168.1.1",
            target="192.168.1.100",
            hops=["192.168.1.50", "192.168.1.100"],
            techniques=[MovementTechnique.SSH, MovementTechnique.PSEXEC],
            credentials_needed=["ssh_key", "admin_hash"],
            probability=0.75,
        )

        self.assertEqual(len(path.hops), 2)
        self.assertEqual(path.probability, 0.75)


if __name__ == "__main__":
    unittest.main()
