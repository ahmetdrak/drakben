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

# Add project root to path (must precede local imports)
PROJECT_ROOT: Path = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.config import ConfigManager  # noqa: E402
from core.logging_config import get_logger, setup_logging  # noqa: E402

# Anti-Forensics: Prevent creation of .pyc files
sys.dont_write_bytecode = True

# Load environment variables from config/api.env
env_file: Path = PROJECT_ROOT / "config" / "api.env"
if env_file.exists():
    load_dotenv(env_file, override=True)

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
    """Global exception handler to capture unhandled exceptions (Crash Reporter).
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
    cleanup_resources()
    sys.exit(1)


# Install exception hook
sys.excepthook = global_exception_handler


def cleanup_resources(_signum: int | None = None, _frame: object = None) -> None:
    """Gracefully cleanup resources on shutdown.
    Closes DB connections and active threads.
    """
    try:
        logger.info("Shutdown signal received. Cleaning up...")

        # GLOBAL STOP - Terminate all active processes
        try:
            from core.stop_controller import stop_controller

            stop_controller.stop()
        except ImportError:
            pass

        # Close Database (if initialized)
        try:
            # Dynamically close DB instances if accessible via core
            # We can't access specific instances easily unless tracked,
            # but we can try to hint GC or rely on connection timeouts.
            # For a cleaner approach, main components register cleanup hooks.
            pass
        except Exception as e:
            logger.debug("Cleanup error (non-critical): %s", e)

        # Flush logs
        logging.shutdown()

        if _signum:
            from rich.console import Console

            Console().print("\n[yellow]Graceful Shutdown Complete. Goodbye![/yellow]")
            sys.exit(0)

    except Exception as e:
        logger.debug("Cleanup error (non-critical): %s", e)
        sys.exit(1)


# Register Signal Handlers
signal.signal(signal.SIGINT, cleanup_resources)
signal.signal(signal.SIGTERM, cleanup_resources)


def check_environment() -> None:
    """Check basic environment requirements."""
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
# Edit with your API keys or use /llm command in DRAKBEN

# OpenRouter (Recommended - Free models available)
OPENROUTER_API_KEY=
OPENROUTER_MODEL=meta-llama/llama-3.1-8b-instruct:free

# OpenAI (Alternative)
# OPENAI_API_KEY=
# OPENAI_MODEL=gpt-4o-mini

# Ollama (Local LLM - Free)
# LOCAL_LLM_URL=http://localhost:11434
# LOCAL_LLM_MODEL=llama3.1

# Note: DRAKBEN works offline without any API key!
# AI features will use fallback mode.
"""
        with open(env_file, "w", encoding="utf-8") as f:
            f.write(env_template)


def main() -> None:
    """Main entry point - Interactive Menu System."""
    # Windows UTF-8 support
    if os.name == "nt":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    try:
        logger.info("DRAKBEN starting...")

        # Check environment
        check_environment()

        # Initialize configuration
        config_manager = ConfigManager()
        config_manager.prompt_llm_setup_if_needed()

        # Boot log
        logger.info("DRAKBEN initialized successfully")

        # Start interactive menu system (menu loads plugins internally)
        from core.ui.menu import DrakbenMenu

        menu = DrakbenMenu(config_manager)
        menu.run()

    except KeyboardInterrupt:
        logger.info("DRAKBEN interrupted by user")
        console = Console()
        console.print("\n\n👋 Interrupted. Goodbye!", style="yellow")
        sys.exit(0)

    except Exception as e:
        logger.exception("Fatal error: %s", e)
        console = Console()
        console.print(f"\n❌ Fatal error: {e}", style="bold red")
        import traceback

        console.print(traceback.format_exc(), style="dim red")
        sys.exit(1)


if __name__ == "__main__":
    main()
