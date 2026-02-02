"""Tests for Hive Mind module."""

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
    """Test credential harvesting."""

    def setUp(self) -> None:
        self.harvester = CredentialHarvester()

    def test_initialization(self) -> None:
        """Test harvester initialization."""
        assert self.harvester.harvested is not None
        assert len(self.harvester.harvested) == 0

    def test_harvest_ssh_keys(self) -> None:
        """Test SSH key harvesting."""
        # This will find keys if they exist on the system
        keys = self.harvester.harvest_ssh_keys()
        assert isinstance(keys, list)

    def test_harvest_known_hosts(self) -> None:
        """Test known_hosts parsing."""
        hosts = self.harvester.harvest_known_hosts()
        assert isinstance(hosts, list)

    def test_harvest_environment(self) -> None:
        """Test environment variable harvesting."""
        # Set a test env var
        os.environ["TEST_PASSWORD_VAR"] = "test_secret_123"

        creds = self.harvester.harvest_environment()

        # Clean up
        del os.environ["TEST_PASSWORD_VAR"]

        # Should have found our test credential
        found = any(
            c.source == "environment" and "TEST_PASSWORD" in c.username for c in creds
        )
        assert found

    def test_get_all_credentials(self) -> None:
        """Test getting all harvested credentials."""
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
        assert len(all_creds) == 1
        assert all_creds[0].username == "testuser"


class TestNetworkMapper(unittest.TestCase):
    """Test network mapping functionality."""

    def setUp(self) -> None:
        self.mapper = NetworkMapper()

    def test_initialization(self) -> None:
        """Test mapper initialization."""
        assert len(self.mapper.discovered_hosts) == 0

    def test_get_local_interfaces(self) -> None:
        """Test getting local network interfaces."""
        interfaces = self.mapper.get_local_interfaces()
        assert isinstance(interfaces, list)

    def test_get_local_subnet(self) -> None:
        """Test subnet calculation."""
        subnet = self.mapper.get_local_subnet("192.168.1.100")
        assert "192.168.1" in subnet
        assert "/24" in subnet

    def test_guess_service(self) -> None:
        """Test service name guessing."""
        assert self.mapper._guess_service(22) == "ssh"
        assert self.mapper._guess_service(80) == "http"
        assert self.mapper._guess_service(443) == "https"
        assert self.mapper._guess_service(3389) == "rdp"
        assert self.mapper._guess_service(445) == "microsoft-ds"

    def test_is_windows_host(self) -> None:
        """Test Windows host detection."""
        windows_host = NetworkHost(ip="192.168.1.1", ports=[135, 445, 3389])
        linux_host = NetworkHost(ip="192.168.1.2", ports=[22, 80])

        assert self.mapper.is_windows_host(windows_host)
        assert not self.mapper.is_windows_host(linux_host)

    def test_is_linux_host(self) -> None:
        """Test Linux host detection."""
        linux_host = NetworkHost(ip="192.168.1.2", ports=[22, 80])
        windows_host = NetworkHost(ip="192.168.1.1", ports=[135, 445])

        assert self.mapper.is_linux_host(linux_host)
        assert not self.mapper.is_linux_host(windows_host)

    def test_find_pivot_points(self) -> None:
        """Test pivot point detection."""
        pivot = NetworkHost(ip="192.168.1.1", ports=[22, 80, 443, 8080])
        non_pivot = NetworkHost(ip="192.168.1.2", ports=[80])

        self.mapper.discovered_hosts["192.168.1.1"] = pivot
        self.mapper.discovered_hosts["192.168.1.2"] = non_pivot

        pivots = self.mapper.find_pivot_points()
        assert len(pivots) == 1
        assert pivots[0].ip == "192.168.1.1"


class TestADAnalyzer(unittest.TestCase):
    """Test Active Directory analysis."""

    def setUp(self) -> None:
        self.analyzer = ADAnalyzer()

    def test_initialization(self) -> None:
        """Test analyzer initialization."""
        assert self.analyzer.domain_info is None
        assert len(self.analyzer.attack_paths) == 0

    def test_detect_domain(self) -> None:
        """Test domain detection."""
        # This will return None if not on a domain
        domain = self.analyzer.detect_domain()
        # Just verify it returns something (string or None)
        assert domain is None or isinstance(domain, str)

    def test_get_kerberoastable_users(self) -> None:
        """Test kerberoastable user patterns."""
        users = self.analyzer.get_kerberoastable_users()
        assert isinstance(users, list)
        assert len(users) > 0

    def test_calculate_attack_path(self) -> None:
        """Test attack path calculation."""
        source = "192.168.1.1"
        target = "192.168.1.100"

        hosts = {
            source: NetworkHost(ip=source, ports=[22]),
            target: NetworkHost(ip=target, ports=[22, 80]),
        }

        path = self.analyzer.calculate_attack_path(
            source=source,
            target=target,
            available_creds=[],
            discovered_hosts=hosts,
        )

        assert path is not None
        assert path.source == source
        assert path.target == target

    def test_cyclic_attack_path(self) -> None:
        """Test detection and prevention of infinite attack loops (A->B->A)."""
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
            assert len(path.hops) == len(set(path.hops)), (
                "Cycle detected in attack path!"
            )

    def test_scope_enforcement(self) -> None:
        """Test that attack paths do not include out-of-scope targets."""
        source = "192.168.1.1"
        target = "8.8.8.8"  # Out of scope

        # If we explicitly define authorized_scope (to be implemented), this should fail
        # For now, we ensure the function handles unknown targets gracefully

        hosts = {source: NetworkHost(ip=source)}

        path = self.analyzer.calculate_attack_path(source, target, [], hosts)

        # Should detect target is unreachable or not in discovered hosts
        assert path is None, "Attack path generated for unknown/out-of-scope target!"


class TestLateralMover(unittest.TestCase):
    """Test lateral movement engine."""

    def setUp(self) -> None:
        self.mover = LateralMover()

    def test_initialization(self) -> None:
        """Test mover initialization."""
        assert len(self.mover.successful_moves) == 0
        assert len(self.mover.failed_moves) == 0

    def test_generate_pth_command(self) -> None:
        """Test Pass-the-Hash command generation."""
        cmd = self.mover.generate_pth_command(
            target="192.168.1.100",
            username="administrator",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee",
        )

        assert "psexec.py" in cmd
        assert "192.168.1.100" in cmd
        assert "-hashes" in cmd

    def test_generate_pth_command_with_domain(self) -> None:
        """Test PTH command with domain username."""
        cmd = self.mover.generate_pth_command(
            target="192.168.1.100",
            username="DOMAIN\\administrator",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee",
        )

        assert "DOMAIN/administrator" in cmd

    def test_generate_ptt_command(self) -> None:
        """Test Pass-the-Ticket command generation."""
        cmd = self.mover.generate_ptt_command(
            target="192.168.1.100",
            ticket_path="/tmp/ticket.ccache",
        )

        assert "KRB5CCNAME" in cmd
        assert "-k" in cmd
        assert "-no-pass" in cmd

    def test_get_movement_stats(self) -> None:
        """Test movement statistics."""
        stats = self.mover.get_movement_stats()

        assert "successful" in stats
        assert "failed" in stats
        assert "techniques_used" in stats
        assert "targets_compromised" in stats


class TestHiveMind(unittest.TestCase):
    """Test main HiveMind orchestrator."""

    def setUp(self) -> None:
        self.hive = HiveMind()

    def test_initialization(self) -> None:
        """Test HiveMind initialization."""
        assert self.hive.harvester is not None
        assert self.hive.mapper is not None
        assert self.hive.ad_analyzer is not None
        assert self.hive.mover is not None
        assert not self.hive.initialized

    def test_initialize(self) -> None:
        """Test HiveMind initialization process."""
        results = self.hive.initialize()

        assert "interfaces" in results
        assert "domain" in results
        assert "credentials_found" in results
        assert self.hive.initialized

    def test_get_status(self) -> None:
        """Test status retrieval."""
        status = self.hive.get_status()

        assert "initialized" in status
        assert "current_host" in status
        assert "credentials" in status
        assert "discovered_hosts" in status

    def test_find_attack_paths_empty(self) -> None:
        """Test attack path finding with no hosts."""
        paths = self.hive.find_attack_paths()
        assert isinstance(paths, list)

    def test_singleton(self) -> None:
        """Test get_hive_mind returns same instance."""
        hive1 = get_hive_mind()
        hive2 = get_hive_mind()
        assert hive1 is hive2


class TestQuickRecon(unittest.TestCase):
    """Test quick_recon helper function."""

    def test_quick_recon(self) -> None:
        """Test quick reconnaissance function."""
        results = quick_recon()

        assert "interfaces" in results
        assert "domain" in results
        assert "credentials_found" in results


class TestDataClasses(unittest.TestCase):
    """Test data class creation."""

    def test_credential_creation(self) -> None:
        """Test Credential dataclass."""
        cred = Credential(
            username="admin",
            domain="example.com",
            credential_type=CredentialType.PASSWORD,
            value="password123",
            source="test",
        )

        assert cred.username == "admin"
        assert cred.credential_type == CredentialType.PASSWORD
        assert cred.valid

    def test_network_host_creation(self) -> None:
        """Test NetworkHost dataclass."""
        host = NetworkHost(ip="192.168.1.1", hostname="server1", ports=[22, 80, 443])

        assert host.ip == "192.168.1.1"
        assert len(host.ports) == 3
        assert not host.compromised

    def test_attack_path_creation(self) -> None:
        """Test AttackPath dataclass."""
        path = AttackPath(
            source="192.168.1.1",
            target="192.168.1.100",
            hops=["192.168.1.50", "192.168.1.100"],
            techniques=[MovementTechnique.SSH, MovementTechnique.PSEXEC],
            credentials_needed=["ssh_key", "admin_hash"],
            probability=0.75,
        )

        assert len(path.hops) == 2
        assert path.probability == 0.75


if __name__ == "__main__":
    unittest.main()
