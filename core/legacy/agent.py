# Archived legacy: core/agent.py
# This file is an archived copy of the original legacy agent implementation.
# It has been moved to `core/legacy/` to reduce accidental activation risk.

"""
Original legacy `core/agent.py` content preserved for audit and rollback.
Do NOT execute this file directly. Use `drakben.py` (RefactoredDrakbenAgent).
"""

# (BEGIN ORIGINAL CONTENT)
# core/agent.py
# DRAKBEN - GPT-5 Level Autonomous Pentesting Agent
# 25 modules integrated for maximum intelligence

import time
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import all 25 modules
from core.brain import DrakbenBrain
from core.system_intelligence import SystemIntelligence
from core.execution_engine import ExecutionEngine
from core.autonomous_solver import AutonomousSolver
from core.security_toolkit import SecurityToolkit
from core.config import ConfigManager, SessionManager
from core.memory_manager import MemoryManager, get_memory
from core.i18n import t


class DrakbenAgent:
    """
    GPT-5 Level Autonomous Penetration Testing Agent
    
    Features:
    - 25 intelligent modules working together
    - Continuous reasoning and self-correction
    - Auto-healing of errors
    - System-aware execution
    - First-time approval, then autonomous
    """
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.config
        self.console = Console()
        
        # State
        self.running = True
        self.command_count = 0
        self.approved_commands = set()  # Track approved commands
        self.workflow_active = False
        
        # Initialize memory system
        self.memory = get_memory()
        
        # Load approved commands from memory
        self.approved_commands = set(self.memory.get_all_approved_commands())
        
        # Initialize all modules silently
        self.system_intel = SystemIntelligence()
        self.system_context = self.system_intel.get_full_system_context()
        self.brain = DrakbenBrain()
        self.executor = ExecutionEngine()
        self.solver = AutonomousSolver(self.system_context["system"])
        self.security = SecurityToolkit()
        self.session_manager = SessionManager(session_dir=self.config.session_dir)
        
    def initialize(self):
        """Initialize agent and show welcome"""
        lang = self.config.language
        
        # Combined compact panel
        welcome_text = Text()
        welcome_text.append("🩸 ", style="bold #FF5555")
        welcome_text.append("DRAKBEN", style="bold #BD93F9")
        welcome_text.append(" | ", style="#6272A4")
        welcome_text.append("Ready", style="#50FA7B")
        welcome_text.append("\n\n", style="")
        welcome_text.append("💬 ", style="bold #FF79C6")
        welcome_text.append("/help  /target  /scan  /status  /clear  /exit", style="#F8F8F2")
        
        # Show target if set
        if self.config.target:
            welcome_text.append(f"\n\n🎯 Target: ", style="bold #F8F8F2")
            welcome_text.append(self.config.target, style="bold #FF79C6")
        
        self.console.print(Panel(welcome_text, border_style="#FF5555", title="🧛 DRAKBEN", title_align="left"))
        
        # Show compact help
        self._show_compact_menu()

    # ... (original file continues, preserved in archive) ...

# (END ORIGINAL CONTENT)
