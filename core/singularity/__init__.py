"""DRAKBEN Singularity Package
Self-Modifying & Autonomous Code Generation Engine.

Modules:
- synthesis: LLM-based code generation
- mutation: Polymorphic code rewriting
- validation: Sandbox execution and testing
- engine: Main orchestrator
"""

from .base import CodeSnippet as CodeSnippet
from .base import MutationResult as MutationResult

__version__ = "1.0.0"
