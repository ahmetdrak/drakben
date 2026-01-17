# core/system_profile.py
# Drakben System Profile Modülü - Yerel Sistem + Hedef Profilleme

import asyncio
import socket
import platform
import subprocess
import os
import datetime

# -------------------------
# Yerel Sistem Bilgisi
# -------------------------
def local_system_info():
    """
    Drakben'in çalıştığı sistem hakkında bilgi toplar.
    """
    try:
        return {
            "timestamp": str(datetime.datetime.utcnow()),
            "cwd": os.getcwd(),              # bulunduğu dizin
            "user": os.getlogin(),           # kullanıcı
            "system": platform.system(),     # işletim sistemi
            "release": platform.release(),   # sürüm
            "version": platform.version(),   # kernel versiyonu
            "architecture": platform.machine(),
            "python": platform.python_version()
        }
    except Exception as e:
        return {"error": str(e)}

def run_shell_command(cmd):
    """
    Yerel sistemde shell komutu çalıştırır.
    """
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {e}"

# -------------------------
# Hedef Sistem Profilleme
# -------------------------
async def profile_target(target_host, ports=[80, 443, 22, 21, 25, 3306]):
    print(f"[SystemProfile] {target_host} için sistem profilleme başlatılıyor...")

    result = {
        "host": target_host,
        "os_guess": None,
        "open_ports": [],
        "services": {},
        "fingerprints": {}
    }

    # Basit OS tahmini
    result["os_guess"] = platform.system()

    # Port taraması
    for port in ports:
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(2)
            if conn.connect_ex((target_host, port)) == 0:
                result["open_ports"].append(port)
                try:
                    banner = conn.recv(1024).decode(errors="ignore")
                    result["services"][port] = banner.strip()
                except:
                    result["services"][port] = "No banner"
            conn.close()
        except Exception as e:
            result["services"][port] = f"Error: {e}"

    # Nmap fingerprint (opsiyonel)
    try:
        cmd = ["nmap", "-O", "-p", ",".join(map(str, ports)), target_host]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        result["fingerprints"]["nmap"] = proc.stdout
    except Exception as e:
        result["fingerprints"]["nmap"] = f"Nmap error: {e}"

    return result
