import logging
import json
from typing import Dict

logger = logging.getLogger(__name__)

class AgentExtensionsMixin:
    """Extensions for the Drakben Agent (Mixin Pattern)"""

    def _execute_metasploit(self, args: Dict) -> Dict:
        """Execute Metasploit module via wrapper"""
        try:
            from modules.metasploit import MetasploitBridge
            
            # Initialize if needed (singleton pattern preferred in real usage, but instantiating for now)
            msf = MetasploitBridge()
            
            # 'module' and 'options' are expected in args
            module = args.get("module")
            options = args.get("options", {})
            
            if not module:
                return {"success": False, "error": "Metasploit module name required"}
                
            self.console.print(f"🔥 Launching Metasploit: {module}", style="red")
            result = msf.execute_module(module, options)
            
            return {
                "success": result.get("success", False),
                "output": result.get("output", ""),
                "session_id": result.get("session_id")
            }
        except ImportError:
             return {"success": False, "error": "modules.metasploit not found"}
        except Exception as e:
            logger.exception("Metasploit error")
            return {"success": False, "error": f"Metasploit execution failed: {e}"}

    def _execute_ad_attacks(self, tool_name: str, args: Dict) -> Dict:
        """Execute Active Directory attacks (Native)"""
        try:
            from modules.ad_attacks import ActiveDirectoryAttacker
            attacker = ActiveDirectoryAttacker()
            
            domain = args.get("domain")
            target_ip = args.get("target_ip")
            
            if not domain or not target_ip:
                 return {"success": False, "error": "Domain and Target IP required for AD attacks"}

            result = {}
            if tool_name == "ad_asreproast":
                # Async shim
                import asyncio
                user_file = args.get("user_file")
                result = asyncio.run(attacker.run_asreproast(domain, target_ip, user_file))
                
            elif tool_name == "ad_smb_spray":
                # Async shim
                import asyncio
                user_file = args.get("user_file")
                password = args.get("password")
                if not user_file or not password:
                    return {"success": False, "error": "User file and password required for spray"}
                    
                result = asyncio.run(attacker.run_smb_spray(domain, target_ip, user_file, password))
            
            else:
                return {"success": False, "error": f"Unknown AD tool: {tool_name}"}
                
            return {
                "success": result.get("success", False),
                "output": json.dumps(result, indent=2),
                "data": result
            }

        except ImportError:
            return {"success": False, "error": "modules.ad_attacks not found"}
        except Exception as e:
            logger.exception("AD Attack error")
            return {"success": False, "error": f"AD Attack failed: {e}"}
