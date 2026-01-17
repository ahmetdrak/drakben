# modules/crypto.py
import subprocess

def crack_hash(hash_file, wordlist, mode="stealth"):
    if mode == "stealth":
        cmd = f"john --wordlist={wordlist} --format=raw-md5 {hash_file}"
    else:
        cmd = f"hashcat -a 0 -m 0 {hash_file} {wordlist}"
    return subprocess.getoutput(cmd)

def ssl_scan(target):
    cmd = f"sslscan {target}"
    return subprocess.getoutput(cmd)
