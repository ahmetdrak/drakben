#!/usr/bin/env python3
# drakben.py
# DRAKBEN - Autonomous Pentesting Agent
# Dracula Theme Edition

import os
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Load environment variables from config/api.env
from dotenv import load_dotenv
env_file = PROJECT_ROOT / "config" / "api.env"
if env_file.exists():
    load_dotenv(env_file)

from rich.console import Console  # noqa: E402

# from core.refactored_agent import RefactoredDrakbenAgent
from core.config import ConfigManager  # noqa: E402
from core.logging_config import setup_logging, get_logger  # noqa: E402

# Initialize logging
setup_logging(
    level="INFO",
    log_dir="logs",
    log_to_file=True,
    log_to_console=False,  # Rich handles console output
    use_colors=True
)
logger = get_logger("main")


def clear_screen():
    """Clear terminal screen"""
    os.system("clear" if os.name != "nt" else "cls")


def show_banner():
    """Show DRAKBEN ASCII banner - Dracula Theme"""
    clear_screen()

    # Windows UTF-8 support
    if os.name == "nt":
        import sys

        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    banner = r"""
    ██████╗ ██████╗  █████╗ ██╗  ██╗██████╗ ███████╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝████╗  ██║
    ██║  ██║██████╔╝███████║█████╔╝ ██████╔╝█████╗  ██╔██╗ ██║
    ██║  ██║██╔══██╗██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝███████╗██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
    """

    console = Console(force_terminal=True)
    console.print(banner, style="bold #FF5555")  # Dracula red
    console.print(
        "    [*] DRAKBEN - Autonomous Pentest Framework", style="bold #BD93F9"
    )  # Dracula purple
    console.print("    [*] Kali Linux | AI-Powered | Auto-Exploit", style="#F8F8F2")
    console.print()


def check_environment():
    """Check basic environment requirements"""
    console = Console()

    # Check Python version
    if sys.version_info < (3, 8):
        console.print("❌ Python 3.8+ required", style="bold red")
        sys.exit(1)

    # Check required directories
    required_dirs = ["core", "llm", "config", "logs", "sessions"]
    for dir_name in required_dirs:
        dir_path = PROJECT_ROOT / dir_name
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)

    # Check if config file exists, create if not

    # Check if api.env exists
    env_file = PROJECT_ROOT / "config" / "api.env"
    if not env_file.exists():
        env_template = """# DRAKBEN LLM Configuration
# Copy this file and edit with your API keys

# OpenRouter (Recommended - Free models available)
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct:free

# OpenAI (Alternative)
# OPENAI_API_KEY=your_key_here
# OPENAI_MODEL=gpt-4o-mini

# Ollama (Local LLM - Free)
# LOCAL_LLM_URL=http://localhost:11434
# LOCAL_LLM_MODEL=llama3.1

# Note: DRAKBEN works offline without any API key!
# AI features will use fallback mode.
"""
        with open(env_file, "w", encoding="utf-8") as f:
            f.write(env_template)


def show_startup_info():
    """Show startup information - Dracula Theme"""
    # Startup panel removed - now combined in agent.py
    pass


def main():
    """Main entry point - Interactive Menu System"""
    # Windows UTF-8 support
    if os.name == "nt":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    try:
        logger.info("DRAKBEN starting...")
        
        # Show banner (Handled by Menu now)
        # show_banner()

        # Check environment
        check_environment()

        # Initialize configuration
        config_manager = ConfigManager()
        config_manager.prompt_llm_setup_if_needed()

        # Show startup info
        show_startup_info()

        # Boot log
        console = Console()
        logger.info("DRAKBEN initialized successfully")

        # Start interactive menu system
        from core.menu import DrakbenMenu

        menu = DrakbenMenu(config_manager)
        menu.run()

    except KeyboardInterrupt:
        logger.info("DRAKBEN interrupted by user")
        console = Console()
        console.print("\n\n👋 Interrupted. Goodbye!", style="yellow")
        sys.exit(0)

    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        console = Console()
        console.print(f"\n❌ Fatal error: {e}", style="bold red")
        import traceback

        console.print(traceback.format_exc(), style="dim red")
        sys.exit(1)


if __name__ == "__main__":
    main()
