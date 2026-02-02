"""DRAKBEN Social Engineering Package
Modules for OSINT, Profiling, and spear-phishing campaigns.
"""

from .mfa_bypass import MFABypass as MFABypass
from .osint import OSINTSpider as OSINTSpider
from .phishing import PhishingGenerator as PhishingGenerator
from .profiler import PsychoProfiler as PsychoProfiler

__version__ = "1.0.0"
