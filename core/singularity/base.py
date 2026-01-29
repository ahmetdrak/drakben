"""
DRAKBEN Singularity - Core Interfaces
Defines the abstract base classes for self-improvement modules.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

@dataclass
class CodeSnippet:
    """Represents a generated code fragment"""
    code: str
    language: str
    purpose: str
    dependencies: List[str]
    is_validated: bool = False
    
@dataclass
class MutationResult:
    """Result of a mutation attempt"""
    original_hash: str
    new_hash: str
    success: bool
    bypassed_engines: List[str]

class ISynthesizer(ABC):
    """Interface for code generation engines"""
    
    @abstractmethod
    def generate_tool(self, description: str) -> CodeSnippet:
        """Generate code for a requested tool"""
        pass
    
    @abstractmethod
    def refactor_code(self, code: str) -> CodeSnippet:
        """Improve existing code"""
        pass

class IValidator(ABC):
    """Interface for code validation sandbox"""
    
    @abstractmethod
    def validate(self, snippet: CodeSnippet) -> bool:
        """Test if code is safe and working"""
        pass

class IMutationEngine(ABC):
    """Interface for polymorphic mutation"""
    
    @abstractmethod
    def mutate(self, payload: str) -> MutationResult:
        """Apply mutation strategies"""
        pass
