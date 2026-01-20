#!/usr/bin/env python3
# drakben.py
# DRAKBEN v2.0 - GPT-5 Level Autonomous Pentesting Agent
# Dracula Theme Edition

import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from core.refactored_agent import RefactoredDrakbenAgent
from core.config import ConfigManager


def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')


def show_banner():
    """Show DRAKBEN ASCII banner - Dracula Theme"""
    clear_screen()
    
    banner = r"""
    ██████╗ ██████╗  █████╗ ██╗  ██╗██████╗ ███████╗███╗   ██╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔════╝████╗  ██║
    ██║  ██║██████╔╝███████║█████╔╝ ██████╔╝█████╗  ██╔██╗ ██║
    ██║  ██║██╔══██╗██╔══██║██╔═██╗ ██╔══██╗██╔══╝  ██║╚██╗██║
    ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝███████╗██║ ╚████║
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
    """
    
    console = Console()
    console.print(banner, style="bold #FF5555")  # Dracula red
    console.print("    🧛 DRAKBEN - Autonomous Pentest Framework", style="bold #BD93F9")  # Dracula purple
    console.print("    🩸 Kali Linux | AI-Powered | Auto-Exploit", style="#F8F8F2")
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
    config_file = PROJECT_ROOT / "config" / "settings.json"
    
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
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(env_template)


def show_startup_info():
    """Show startup information - Dracula Theme"""
    # Startup panel removed - now combined in agent.py
    pass


def main():
    """Main entry point"""
    try:
        # Show banner
        show_banner()
        
        # Check environment
        check_environment()
        
        # Initialize configuration
        config_manager = ConfigManager()
        config_manager.prompt_llm_setup_if_needed()
        
        # Show startup info
        show_startup_info()
        
        # Initialize and run agent (refactored single-loop)
        agent = RefactoredDrakbenAgent(config_manager)
        agent.initialize(target=config_manager.config.target or "")

        # BOOT proof log
        console = Console()
        console.print("BOOT: RefactoredDrakbenAgent live", style="bold green")

        # Runtime check: ensure no other top-level while loops or async-for agent loops exist outside refactored agent
        def _detect_other_agent_loops(root_dir=PROJECT_ROOT):
            """Detect truly agent-like loops while avoiding false-positives.

            Strategy:
            - Skip virtualenvs, site-packages, tests and docs.
            - Ignore the approved `core/refactored_agent.py` file.
            - For each `while` / `async for` match, examine a small context window
              and only mark it if the context contains agent-like keywords
              (llm, tool, select_tool, plan, prompt, generate, think, decide,
              run_autonomous_loop, max_iterations, brain, agentic).
            - Treat common queue/state/event loops as benign (queue, output_queue,
              visited, hosts, state, .empty(), hop <, self.running) to reduce false-positives.
            """
            import re
            bad = []
            pattern_while = re.compile(r'^\s*while\b')
            pattern_async_for = re.compile(r'^\s*async\s+for\b')

            agenty_keywords = re.compile(r"\b(llm|tool|tool_selector|select_tool|plan|prompt|generate|think|decide|observe|action|max_iteration|max_iterations|run_autonomous_loop|brain|agentic)\b", re.I)
            benign_indicators = re.compile(r"\b(queue|output_queue|visited|hosts|state|self\.running|\.empty\(|len\(|hop\s*<|for\s+.+in)\b", re.I)

            skip_parts = ('.venv', 'venv', 'site-packages', 'tests', 'docs', 'node_modules')

            for p in root_dir.rglob('*.py'):
                sp = str(p)
                if any(skip in sp for skip in skip_parts):
                    continue

                # allow the approved single agent loop file
                rel = p.relative_to(root_dir)
                if str(rel) == str(root_dir.name + '/core/refactored_agent.py') or str(rel) == 'core/refactored_agent.py':
                    continue

                try:
                    text = p.read_text(encoding='utf-8')
                except Exception:
                    continue

                lines = text.splitlines()
                for i, line in enumerate(lines, start=1):
                    if pattern_while.match(line) or pattern_async_for.search(line):
                        # context window around the loop line
                        start = max(0, i - 5)
                        end = min(len(lines), i + 8)
                        context = "\n".join(lines[start:end])

                        # If context contains agent-like keywords, flag it
                        if agenty_keywords.search(context):
                            bad.append(f"{rel}:{i}: {line.strip()}")
                            continue

                        # If context shows benign event/queue/state loop, ignore
                        if benign_indicators.search(context):
                            continue

                        # Conservative rule reduced: only flag core files whose names
                        # indicate they may contain legacy agent logic (agent, brain, executor)
                        suspicious_core_names = re.compile(r"\b(agent|brain|autonom|executor)\b", re.I)
                        if str(rel).startswith('core/') and suspicious_core_names.search(str(rel)):
                            bad.append(f"{rel}:{i}: {line.strip()}")

            return bad

        loop_issues = _detect_other_agent_loops()
        if loop_issues:
            console.print("❌ Execution-path guard failed: unexpected agent-like loops found:", style="bold red")
            for item in loop_issues:
                console.print(item, style="red")
            raise SystemExit(2)

        agent.run_autonomous_loop()
        
    except KeyboardInterrupt:
        console = Console()
        console.print("\n\n👋 Interrupted. Goodbye!", style="yellow")
        sys.exit(0)
    
    except Exception as e:
        console = Console()
        console.print(f"\n❌ Fatal error: {e}", style="bold red")
        import traceback
        console.print(traceback.format_exc(), style="dim red")
        sys.exit(1)


if __name__ == "__main__":
    main()
