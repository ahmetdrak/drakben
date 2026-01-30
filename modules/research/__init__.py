"""
DRAKBEN Research Package - Surgical Strike
Zero-day discovery, smart fuzzing, and automated exploit generation.
"""

from .analyzer import TargetAnalyzer as TargetAnalyzer
from .exploit_crafter import ExploitCrafter as ExploitCrafter
from .fuzzer import SmartFuzzer as SmartFuzzer
from .symbolic import SymbolicExecutor as SymbolicExecutor

__version__ = "1.0.0"
