# modules/fuzzer.py
import subprocess

def fuzz_params(url, wordlist, mode="stealth"):
    if mode == "stealth":
        cmd = f"ffuf -u {url}?FUZZ=test -w {wordlist} -t 5"
    else:
        cmd = f"ffuf -u {url}?FUZZ=test -w {wordlist} -t 50 -mc all"
    return subprocess.getoutput(cmd)
