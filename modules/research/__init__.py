"""
DRAKBEN Research Package - Surgical Strike
Zero-day discovery, smart fuzzing, and automated exploit generation.
"""

from .fuzzer import SmartFuzzer
from .analyzer import TargetAnalyzer
from .exploit_crafter import ExploitCrafter
from .symbolic import SymbolicExecutor

__version__ = "1.0.0"
