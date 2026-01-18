# modules/payload.py
# Drakben Payload Modülü - İleri Seviye

import asyncio
import socket
import subprocess
from modules import ai_bridge

# -------------------------
# Reverse Shell Payload
# -------------------------
async def reverse_shell(target_ip="127.0.0.1", target_port=4444):
    print(f"[Payload] Reverse shell baslatiliyor: {target_ip}:{target_port}")
    try:
        reader, writer = await asyncio.open_connection(target_ip, target_port)
        writer.write(b"Drakben reverse shell connection established.\n")
        await writer.drain()
        return {"type": "ReverseShell", "success": True, "ip": target_ip, "port": target_port}
    except Exception as e:
        return {"type": "ReverseShell", "success": False, "error": str(e)}

# -------------------------
# Bind Shell Payload
# -------------------------
async def bind_shell(listen_ip="0.0.0.0", listen_port=5555):
    print(f"[Payload] Bind shell dinleniyor: {listen_ip}:{listen_port}")
    try:
        server = await asyncio.start_server(handle_client, listen_ip, listen_port)
        await server.start_serving()
        return {"type": "BindShell", "success": True, "ip": listen_ip, "port": listen_port}
    except Exception as e:
        return {"type": "BindShell", "success": False, "error": str(e)}

async def handle_client(reader, writer):
    writer.write(b"Drakben bind shell connection established.\n")
    await writer.drain()

# -------------------------
# Command Execution Payload
# -------------------------
def execute_command(cmd="id"):
    print(f"[Payload] Komut çalıştırılıyor: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return {"type": "CommandExec", "stdout": result.stdout, "stderr": result.stderr}
    except Exception as e:
        return {"type": "CommandExec", "error": str(e)}

# -------------------------
# AI Destekli Payload Önerisi
# -------------------------
async def ai_payload_advice(exploit_output):
    print("[Payload] AI öneri motoru çalışıyor...")
    advice = await ai_bridge.analyze_payload_output(exploit_output)
    return {"type": "AI", "advice": advice}
