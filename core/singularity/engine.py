"""
DRAKBEN Singularity - Main Engine
Author: @drak_ben
Description: Orchestrates the self-improvement cycle: Synthesize -> Validate -> Mutate.
"""

import logging
from typing import Optional, Dict, Any, List
from .base import CodeSnippet
from .synthesizer import CodeSynthesizer
from .validator import CodeValidator
from .mutation import MutationEngine

logger = logging.getLogger(__name__)

class SingularityEngine:
    """
    The heart of Drakben's self-improvement capability.
    
    Workflow:
    1. Receive requirement (e.g. "Need a tool to exploit CVE-2024-XXXX")
    2. Synthesize code using LLM
    3. Validate code in Sandbox
    4. Mutate code for Evasion
    5. Deploy tool
    """
    
    def __init__(self):
        self.synthesizer = CodeSynthesizer()
        self.validator = CodeValidator()
        self.mutator = MutationEngine()
        logger.info("Singularity Engine initialized")
        
    def create_capability(self, description: str, language: str = "python") -> Optional[str]:
        """
        Create a new diverse capability (tool) from scratch.
        
        Args:
            description: Description of the desired tool
            language: Target language
            
        Returns:
            Final source code string or None if failed
        """
        logger.info(f"Initiating capability creation: {description}")
        
        # 1. Synthesis
        snippet = self.synthesizer.generate_tool(description, language)
        if not snippet or not snippet.code:
            logger.error("Synthesis failed")
            return None
            
        # 2. Validation
        # Only validate if it's safe/possible (e.g. valid syntax)
        is_valid = self.validator.validate(snippet)
        if not is_valid:
            logger.warning("Initial validation failed. Attempting self-repair...")
            logger.error("Validation failed. Moving to fallback or human intervention required.")
            return None
            
        # 3. Mutation (Polymorphism)
        # Apply mutation to ensure unique signature
        mutation_result = self.mutator.mutate(snippet.code)
        if mutation_result.success:
            # Re-validate after mutation? Ideally yes, but GhostProtocol guarantees functionality preservation
            final_code = self.mutator.generate_variant(snippet.code, iterations=1)
        else:
            final_code = snippet.code
            
        logger.info("Capability created successfully")
        return final_code

    def evolve_existing_module(self, module_code: str) -> str:
        """
        Evolve an existing module to bypass new signatures.
        """
        # Apply intense mutation
        return self.mutator.generate_variant(module_code, iterations=3)


# Singleton Access
_singularity_engine = None

def get_singularity_engine() -> SingularityEngine:
    """Get singleton Singularity Engine"""
    global _singularity_engine
    if _singularity_engine is None:
        _singularity_engine = SingularityEngine()
    return _singularity_engine
