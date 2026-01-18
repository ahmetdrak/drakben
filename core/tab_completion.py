"""
Tab completion helper for DRAKBEN
Provides readline-based autocomplete functionality
"""

import os
import glob
from typing import List

try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False
    readline = None


class DrakbenCompleter:
    """Tab completion for DRAKBEN commands"""
    
    # Core commands
    COMMANDS = [
        "setup", "target", "strategy", "scan", "scan_parallel",
        "exploit", "payload", "enum", "web_shell", "ssh_shell",
        "reverse_shell", "post_exp", "lateral", "auto_mode",
        "auto_pentest", "ai_memory", "ml_analyze", "ml_evasion",
        "ml_summary", "results", "chain", "help", "clear", "exit",
        "quickhelp", "status", "history"
    ]
    
    # Strategy options
    STRATEGIES = ["stealthy", "balanced", "aggressive"]
    
    # Payload types
    PAYLOAD_TYPES = ["bash", "python", "powershell", "perl", "php"]
    
    def __init__(self):
        self.matches = []
    
    def complete(self, text: str, state: int) -> str:
        """Complete function for readline"""
        if state == 0:
            # First call: build match list
            if text:
                self.matches = [cmd for cmd in self.COMMANDS if cmd.startswith(text)]
            else:
                self.matches = self.COMMANDS[:]
        
        # Return match or None
        try:
            return self.matches[state]
        except IndexError:
            return None
    
    def path_completer(self, text: str, state: int) -> str:
        """Path completion for file arguments"""
        if state == 0:
            if os.path.sep in text:
                # Directory path
                self.matches = glob.glob(text + '*')
            else:
                # Current directory
                self.matches = glob.glob('*')
        
        try:
            return self.matches[state]
        except IndexError:
            return None
    
    def setup_readline(self):
        """Configure readline with tab completion"""
        # Enable tab completion
        readline.parse_and_bind("tab: complete")
        
        # Set completer
        readline.set_completer(self.complete)
        
        # Set word delimiters
        readline.set_completer_delims(' \t\n;')
        
        # Enable history
        try:
            readline.read_history_file(".drakben_history")
        except FileNotFoundError:
            pass
        
        # Save history on exit
        import atexit
        atexit.register(readline.write_history_file, ".drakben_history")


def setup_tab_completion():
    """Initialize tab completion"""
    try:
        completer = DrakbenCompleter()
        completer.setup_readline()
        return True
    except Exception as e:
        print(f"⚠️  Tab completion unavailable: {e}")
        return False
