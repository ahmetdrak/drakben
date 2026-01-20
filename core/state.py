# core/state.py
# DRAKBEN State Abstraction - TEK GERÇEKLIK KAYNAĞ (SINGLE SOURCE OF TRUTH)
# ZORUNLU: Tüm modüller SADECE bu API üzerinden state'e erişir/günceller

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
import time


class AttackPhase(Enum):
    """Saldırı fazları - deterministik akış"""
    INIT = "init"
    RECON = "recon"
    VULN_SCAN = "vulnerability_scan"
    EXPLOIT = "exploit"
    FOOTHOLD = "foothold"
    POST_EXPLOIT = "post_exploit"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ServiceInfo:
    """Servis bilgisi özeti"""
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    tested: bool = False
    vulnerable: bool = False
    exploit_attempted: bool = False


@dataclass
class CredentialInfo:
    """Credential bilgisi"""
    username: str
    service: str = ""
    password: Optional[str] = None
    hash: Optional[str] = None
    verified: bool = False


@dataclass
class VulnerabilityInfo:
    """Zafiyet bilgisi"""
    vuln_id: str
    service: str
    port: int
    severity: str  # low, medium, high, critical
    exploitable: bool
    exploit_attempted: bool = False
    exploit_success: bool = False


class AgentState:
    """
    DRAKBEN Agent State - TEK GERÇEKLIK KAYNAĞ
    
    KURALLAR:
    1. Tüm state güncellemeleri bu class üzerinden
    2. YASAK: Raw log, tool output, tool isimleri
    3. SADECE: Anlamlı özet, deterministik state
    4. Her güncelleme sonrası validate() çağrılmalı
    5. State kirliliği = SYSTEM HALT
    """
    
    def __init__(self, target: Optional[str] = None):
        # Core state
        self.target: Optional[str] = target
        self.phase: AttackPhase = AttackPhase.INIT
        self.iteration_count: int = 0
        self.max_iterations: int = 15
        
        # Attack surface tracking
        self.open_services: Dict[int, ServiceInfo] = {}  # port -> ServiceInfo
        self.tested_attack_surface: Set[str] = set()  # "port:service" tuples
        self.remaining_attack_surface: Set[str] = set()  # "port:service" tuples
        
        # Vulnerability tracking
        self.vulnerabilities: List[VulnerabilityInfo] = []
        
        # Credentials
        self.credentials: List[CredentialInfo] = []
        
        # Foothold state
        self.has_foothold: bool = False
        self.foothold_method: Optional[str] = None
        self.foothold_timestamp: Optional[float] = None
        
        # Post-exploit state
        self.post_exploit_completed: Set[str] = set()  # completed post-exploit actions
        
        # Execution tracking
        self.last_observation: str = ""  # Son tool observation (özet, raw değil)
        self.state_changes_history: List[Dict] = []  # Son 3 state değişikliği
        
        # Invariant violation tracking
        self.invariant_violations: List[str] = []
        
    def snapshot(self) -> Dict:
        """State snapshot al - LLM'ye gönderilecek özet"""
        return {
            "target": self.target,
            "phase": self.phase.value,
            "iteration": f"{self.iteration_count}/{self.max_iterations}",
            "open_services_count": len(self.open_services),
            "tested_count": len(self.tested_attack_surface),
            "remaining_count": len(self.remaining_attack_surface),
            "vulnerabilities_count": len(self.vulnerabilities),
            "has_foothold": self.has_foothold,
            "last_observation": self.last_observation[:200]  # Max 200 char
        }
    
    def update_services(self, services: List[ServiceInfo]):
        """Servis keşfi sonrası state güncelle"""
        for svc in services:
            self.open_services[svc.port] = svc
            surface_key = f"{svc.port}:{svc.service}"
            if surface_key not in self.tested_attack_surface:
                self.remaining_attack_surface.add(surface_key)
        
        self._record_change("services_discovered", len(services))
    
    def mark_surface_tested(self, port: int, service: str):
        """Bir attack surface test edildi olarak işaretle"""
        surface_key = f"{port}:{service}"
        self.tested_attack_surface.add(surface_key)
        self.remaining_attack_surface.discard(surface_key)
        
        if port in self.open_services:
            self.open_services[port].tested = True
        
        self._record_change("surface_tested", surface_key)
    
    def add_vulnerability(self, vuln: VulnerabilityInfo):
        """Zafiyet keşfedildi"""
        self.vulnerabilities.append(vuln)
        
        # Mark service as vulnerable
        if vuln.port in self.open_services:
            self.open_services[vuln.port].vulnerable = True
        
        self._record_change("vulnerability_found", vuln.vuln_id)
    
    def mark_exploit_attempted(self, port: int, success: bool):
        """Exploit denemesi kaydet"""
        if port in self.open_services:
            self.open_services[port].exploit_attempted = True
        
        # Update vulnerability state
        for vuln in self.vulnerabilities:
            if vuln.port == port and not vuln.exploit_attempted:
                vuln.exploit_attempted = True
                vuln.exploit_success = success
                break
        
        self._record_change("exploit_attempted", {"port": port, "success": success})
    
    def set_foothold(self, method: str):
        """Foothold elde edildi"""
        self.has_foothold = True
        self.foothold_method = method
        self.foothold_timestamp = time.time()
        self.phase = AttackPhase.FOOTHOLD
        
        self._record_change("foothold_achieved", method)
    
    def add_credential(self, cred: CredentialInfo):
        """Credential elde edildi"""
        self.credentials.append(cred)
        self._record_change("credential_found", cred.username)
    
    def mark_post_exploit_done(self, action: str):
        """Post-exploit aksiyonu tamamlandı"""
        self.post_exploit_completed.add(action)
        self._record_change("post_exploit_completed", action)
    
    def set_observation(self, observation: str):
        """Son observation'ı kaydet - MAX 500 karakter"""
        self.last_observation = observation[:500]
    
    def increment_iteration(self):
        """Iteration sayısını artır"""
        self._record_change("iteration", self.iteration_count + 1)
        self.iteration_count += 1
    
    def get_available_attack_surface(self) -> List[str]:
        """Henüz test edilmemiş attack surface'leri al"""
        return list(self.remaining_attack_surface)
    
    def should_halt(self) -> tuple[bool, str]:
        """Sistem halt etmeli mi?"""
        # Max iteration
        if self.iteration_count >= self.max_iterations:
            return True, "Max iteration reached"
        
        # Invariant violation
        if self.invariant_violations:
            return True, f"Invariant violation: {self.invariant_violations[0]}"
        
        # State stagnation check - son 3 iteration'da değişim var mı?
        if len(self.state_changes_history) >= 3:
            last_3 = self.state_changes_history[-3:]
            # Eğer son 3 change aynı ve sadece iteration artışıysa -> stagnant
            if all(c.get("type") == "iteration" for c in last_3):
                return True, "State stagnation detected"
        
        # Success check
        if self.phase == AttackPhase.COMPLETE:
            return True, "Attack complete"
        
        if self.phase == AttackPhase.FAILED:
            return True, "Attack failed"
        
        return False, ""
    
    def validate(self) -> bool:
        """
        State invariant kontrolü - HER LOOP SONUNDA ÇAĞRILMALI
        
        Returns:
            True if valid, False if invariant violated
        """
        violations = []
        
        # Invariant 1: Foothold olmadan post-exploit yasak
        if not self.has_foothold and self.post_exploit_completed:
            violations.append("Post-exploit attempted without foothold")
        
        # Invariant 2: Exploit phase'e geçmeden önce en az 1 servis bulunmalı
        if self.phase == AttackPhase.EXPLOIT and len(self.open_services) == 0:
            violations.append("Exploit phase without discovered services")
        
        # Invariant 3: Max iteration aşılamaz
        if self.iteration_count > self.max_iterations:
            violations.append("Max iteration exceeded")
        
        # Invariant 4: Tested surface, open services'in subset'i olmalı
        for tested in self.tested_attack_surface:
            port_str = tested.split(":")[0]
            try:
                port = int(port_str)
                if port not in self.open_services:
                    violations.append(f"Tested surface {tested} not in open services")
            except ValueError:
                violations.append(f"Invalid tested surface format: {tested}")
        
        # Invariant 5: Remaining surface da open services'in subset'i
        for remaining in self.remaining_attack_surface:
            port_str = remaining.split(":")[0]
            try:
                port = int(port_str)
                if port not in self.open_services:
                    violations.append(f"Remaining surface {remaining} not in open services")
            except ValueError:
                violations.append(f"Invalid remaining surface format: {remaining}")
        
        if violations:
            self.invariant_violations.extend(violations)
            return False
        
        return True
    
    def _record_change(self, change_type: str, data):
        """State değişikliğini kaydet (son 5 değişiklik)"""
        change = {
            "type": change_type,
            "data": data,
            "iteration": self.iteration_count,
            "timestamp": time.time()
        }
        self.state_changes_history.append(change)
        
        # Keep only last 5
        if len(self.state_changes_history) > 5:
            self.state_changes_history = self.state_changes_history[-5:]
    
    def to_dict(self) -> Dict:
        """Full state'i dict'e çevir (debug/logging için)"""
        return {
            "target": self.target,
            "phase": self.phase.value,
            "iteration_count": self.iteration_count,
            "open_services": {k: asdict(v) for k, v in self.open_services.items()},
            "tested_attack_surface": list(self.tested_attack_surface),
            "remaining_attack_surface": list(self.remaining_attack_surface),
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "credentials": [asdict(c) for c in self.credentials],
            "has_foothold": self.has_foothold,
            "foothold_method": self.foothold_method,
            "post_exploit_completed": list(self.post_exploit_completed),
            "state_changes_history": self.state_changes_history[-5:],
            "invariant_violations": self.invariant_violations
        }
    
    def from_dict(self, data: Dict):
        """Dict'ten state yükle (session recovery için)"""
        self.target = data.get("target")
        self.phase = AttackPhase(data.get("phase", "init"))
        self.iteration_count = data.get("iteration_count", 0)
        # ... other fields as needed
        # Not implemented fully - for future session recovery feature
        pass


def get_state() -> AgentState:
    """Global state instance getter (singleton pattern)"""
    if not hasattr(get_state, "_instance"):
        get_state._instance = AgentState()
    return get_state._instance


def reset_state(target: Optional[str] = None):
    """State'i reset et - yeni run için"""
    get_state._instance = AgentState(target)
    return get_state._instance
