#!/usr/bin/env python3
# drakben.py
# DRAKBEN - Autonomous Pentesting Agent
# Dracula Theme Edition

import logging
import os
import signal
import sys
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console

from core.config import ConfigManager
from core.logging_config import get_logger, setup_logging

# Add project root to path
PROJECT_ROOT: Path = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Anti-Forensics: Prevent creation of .pyc files
sys.dont_write_bytecode = True

# Load environment variables from config/api.env
env_file: Path = PROJECT_ROOT / "config" / "api.env"
if env_file.exists():
    load_dotenv(env_file)

# Initialize logging
# Initialize logging
setup_logging(
    level="INFO",
    log_dir="logs",
    log_to_file=True,
    log_to_console=False,  # Rich handles console output
    use_colors=True,
)
logger: logging.Logger = get_logger("main")


def global_exception_handler(exc_type, exc_value, exc_traceback) -> None:
    """# noqa: RUF001Global exception handler to capture unhandled exceptions (Crash Reporter).
    Prevents 'Silent Death' by generating a detailed crash dump.
    """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    import traceback
    from datetime import datetime

    from rich.console import Console
    from rich.panel import Panel

    check_console = Console()

    # Generate crash ID
    crash_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    crash_id = f"crash_{crash_time}.log"
    log_dir = PROJECT_ROOT / "logs" / "crash_reports"
    log_dir.mkdir(parents=True, exist_ok=True)
    crash_file = log_dir / crash_id

    # Format traceback
    tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))

    # Write to file
    with open(crash_file, "w", encoding="utf-8") as f:
        f.write(f"DRAKBEN CRASH REPORT - {crash_time}\n")
        f.write("=" * 50 + "\n")
        f.write(f"Type: {exc_type.__name__}\n")
        f.write(f"Message: {exc_value!s}\n")
        f.write("-" * 50 + "\n")
        f.write(tb_text)
        f.write("=" * 50 + "\n")
        f.write("System Information:\n")
        import platform

        f.write(f"OS: {platform.system()} {platform.release()}\n")
        f.write(f"Python: {sys.version}\n")

    # Notify user
    logger.critical(
        f"Unhandled exception caught! Crash dump saved to {crash_file}",
        exc_info=(exc_type, exc_value, exc_traceback),
    )

    check_console.print(
        Panel(
            f"[bold red]CRITICAL SYSTEM FAILURE[/bold red]\n\n"
            f"An unhandled exception occurred and the agent must terminate.\n"
            f"Crash dump written to: [yellow]{crash_file}[/yellow]\n\n"
            f"Error: {exc_type.__name__}: {exc_value!s}",
            title="💀 DRAKBEN CRASH REPORTER",
            border_style="red",
        ),
    )
    sys.exit(1)


# Install exception hook
sys.excepthook = global_exception_handler


def cleanup_resources(signum=None, frame=None) -> None:
    """Gracefully cleanup resources on shutdown.
    Closes DB connections and active threads.
    """
    try:
        logger.info("Shutdown signal received. Cleaning up...")

        # Close Database (if initialized)
        try:
            # Dynamically close DB instances if accessible via core
            # We can't access specific instances easily unless tracked,
            # but we can try to hint GC or rely on connection timeouts.
            # For a cleaner approach, main components register cleanup hooks.
            pass
        except Exception as e:
            logger.debug(f"Cleanup error (non-critical): {e}")

        # Flush logs
        logging.shutdown()

        if signum:
            from rich.console import Console

            Console().print("\n[yellow]Graceful Shutdown Complete. Goodbye![/yellow]")
            sys.exit(0)

    except Exception:
        sys.exit(1)


# Register Signal Handlers
signal.signal(signal.SIGINT, cleanup_resources)
signal.signal(signal.SIGTERM, cleanup_resources)


def clear_screen() -> None:
    """Clear terminal screen."""
    os.system("clear" if os.name != "nt" else "cls")


def show_banner() -> None:
    """Show DRAKBEN ASCII banner - Dracula Theme."""
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
        "    [*] DRAKBEN - Autonomous Pentest Framework",
        style="bold #BD93F9",
    )  # Dracula purple
    console.print("    [*] Kali Linux | AI-Powered | Auto-Exploit", style="#F8F8F2")
    console.print()


def check_environment() -> None:
    """Check basic environment requirements."""
    Console()

    # Check Python version

    # Check required directories
    required_dirs = ["core", "llm", "config", "logs", "sessions"]
    for dir_name in required_dirs:
        dir_path: Path = PROJECT_ROOT / dir_name
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)

    # Check if config file exists, create if not

    # Check if api.env exists
    env_file: Path = PROJECT_ROOT / "config" / "api.env"
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


def show_startup_info() -> None:
    """Show startup information - Dracula Theme."""
    # Startup panel removed - now combined in agent.py


def main() -> None:
    """Main entry point - Interactive Menu System."""
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

        # Initialize Plugins
        from core.plugin_loader import PluginLoader

        plugin_loader = PluginLoader("plugins")
        console.print(
            f"[dim]Plugins directory: {plugin_loader.plugin_dir.absolute()}[/dim]",
        )

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
