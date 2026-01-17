# modules/auth_bypass.py
import subprocess

def brute_force_login(url, userlist, passlist, mode="stealth"):
    if mode == "stealth":
        cmd = f"hydra -l admin -P {passlist} {url} http-post-form"
    else:
        cmd = f"hydra -L {userlist} -P {passlist} {url} http-post-form"
    return subprocess.getoutput(cmd)

def jwt_attack(token, mode="stealth"):
    if mode == "stealth":
        return f"Test: JWT alg=none → {token}"
    else:
        return f"Test: JWT brute-force secret → {token}"
