# core/plugins/base.py
# DRAKBEN Plugin Base Classes

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional
import asyncio


class PluginKind(Enum):
    """Plugin kategorileri"""
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOIT = "exploit"
    PAYLOAD = "payload"
    BYPASS = "bypass"
    POST = "post"


@dataclass
class PluginResult:
    """Plugin çalıştırma sonucu"""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    output: str = ""
    next_steps: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "data": self.data,
            "errors": self.errors,
            "warnings": self.warnings,
            "output": self.output,
            "next_steps": self.next_steps
        }


@dataclass
class PluginSpec:
    """Plugin metadata specification"""
    plugin_id: str
    kind: PluginKind
    name: str
    version: str
    description: str
    capabilities: List[str]
    requires_approval: bool = False
    timeout: int = 300  # seconds
    
    @classmethod
    def from_dict(cls, data: Dict) -> "PluginSpec":
        return cls(
            plugin_id=data["plugin_id"],
            kind=PluginKind(data["kind"]),
            name=data["name"],
            version=data["version"],
            description=data["description"],
            capabilities=data.get("capabilities", []),
            requires_approval=data.get("requires_approval", False),
            timeout=data.get("timeout", 300)
        )


class PluginBase(ABC):
    """
    Tüm plugin'lerin base class'ı
    Her plugin bu sınıfı extend etmeli
    """
    
    def __init__(self, spec: PluginSpec):
        self.spec = spec
        self.initialized = False
        self._context: Dict[str, Any] = {}
    
    @property
    def plugin_id(self) -> str:
        return self.spec.plugin_id
    
    @property
    def kind(self) -> PluginKind:
        return self.spec.kind
    
    @property
    def requires_approval(self) -> bool:
        return self.spec.requires_approval
    
    def set_context(self, context: Dict[str, Any]):
        """Set execution context (target, credentials, etc.)"""
        self._context = context
    
    def get_context(self, key: str, default=None):
        """Get context value"""
        return self._context.get(key, default)
    
    async def initialize(self) -> bool:
        """Initialize plugin (check dependencies, etc.)"""
        self.initialized = True
        return True
    
    @abstractmethod
    async def execute(self, **kwargs) -> PluginResult:
        """
        Ana çalıştırma metodu - Her plugin implement etmeli
        
        Args:
            **kwargs: Plugin-specific arguments
            
        Returns:
            PluginResult with execution results
        """
        pass
    
    async def cleanup(self):
        """Cleanup after execution"""
        pass
    
    def validate_args(self, **kwargs) -> List[str]:
        """Validate arguments before execution"""
        return []  # Return list of errors, empty if valid


class ReconPlugin(PluginBase):
    """Base class for reconnaissance plugins"""
    
    async def execute(self, target: str, **kwargs) -> PluginResult:
        """Execute recon on target"""
        if not target:
            return PluginResult(
                success=False,
                errors=["Target is required for recon"]
            )
        return await self._do_recon(target, **kwargs)
    
    @abstractmethod
    async def _do_recon(self, target: str, **kwargs) -> PluginResult:
        pass


class ExploitPlugin(PluginBase):
    """Base class for exploit plugins"""
    
    async def execute(self, target: str, vulnerability: str = None, **kwargs) -> PluginResult:
        """Execute exploit on target"""
        if not target:
            return PluginResult(
                success=False,
                errors=["Target is required for exploit"]
            )
        return await self._do_exploit(target, vulnerability, **kwargs)
    
    @abstractmethod
    async def _do_exploit(self, target: str, vulnerability: str, **kwargs) -> PluginResult:
        pass


class PayloadPlugin(PluginBase):
    """Base class for payload generation plugins"""
    
    async def execute(self, payload_type: str, lhost: str = None, lport: int = 4444, **kwargs) -> PluginResult:
        """Generate payload"""
        return await self._generate_payload(payload_type, lhost, lport, **kwargs)
    
    @abstractmethod
    async def _generate_payload(self, payload_type: str, lhost: str, lport: int, **kwargs) -> PluginResult:
        pass
