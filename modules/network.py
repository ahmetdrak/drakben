# modules/network.py
import subprocess

def arp_spoof(target, gateway, iface="eth0"):
    cmd = f"arpspoof -i {iface} -t {target} {gateway}"
    return subprocess.getoutput(cmd)

def sniff_packets(iface="eth0", count=50):
    cmd = f"tcpdump -i {iface} -c {count}"
    return subprocess.getoutput(cmd)

def mitm_proxy(port=8080):
    cmd = f"mitmproxy -p {port}"
    return subprocess.getoutput(cmd)
