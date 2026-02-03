"""Script to update all imports after restructuring."""
import os

REPLACEMENTS = {
    "from core.agent.brain import": "from core.agent.brain import",
    "from core.intelligence.coder import": "from core.intelligence.coder import",
    "from core.intelligence.code_review import": "from core.intelligence.code_review import",
    "from core.agent.state import": "from core.agent.state import",
    "from core.agent.planner import": "from core.agent.planner import",
    "from core.agent.refactored_agent import": "from core.agent.refactored_agent import",
    "from core.execution.execution_engine import": "from core.execution.execution_engine import",
    "from core.execution.interpreter import": "from core.execution.interpreter import",
    "from core.execution.sandbox_manager import": "from core.execution.sandbox_manager import",
    "from core.execution.tool_selector import": "from core.execution.tool_selector import",
    "from core.ui.menu import": "from core.ui.menu import",
    "from core.ui.interactive_shell import": "from core.ui.interactive_shell import",
    "from core.ui.prompt_utils import": "from core.ui.prompt_utils import",
    "from core.ui.visualizer import": "from core.ui.visualizer import",
    "from core.ui.i18n import": "from core.ui.i18n import",
    "from core.intelligence.self_refining_engine import": "from core.intelligence.self_refining_engine import",
    "from core.intelligence.evolution_memory import": "from core.intelligence.evolution_memory import",
    "from core.intelligence.universal_adapter import": "from core.intelligence.universal_adapter import",
    "from core.security.ghost_protocol import": "from core.security.ghost_protocol import",
    "from core.security.security_utils import": "from core.security.security_utils import",
    "from core.security.kali_detector import": "from core.security.kali_detector import",
    "from core.tools.tool_parsers import": "from core.tools.tool_parsers import",
    "from core.tools.computer import": "from core.tools.computer import",
    "from core.storage.database_manager import": "from core.storage.database_manager import",
    "from core.storage.vector_store import": "from core.storage.vector_store import",
    "from core.storage.llm_cache import": "from core.storage.llm_cache import",
    "from core.storage.structured_logger import": "from core.storage.structured_logger import",
    "from core.network.distributed_state import": "from core.network.distributed_state import",
    "from core.network.daemon_service import": "from core.network.daemon_service import",
    "from core.network.web_researcher import": "from core.network.web_researcher import",
}

def update_file(filepath):
    """Update imports in a single file."""
    with open(filepath, encoding="utf-8") as f:
        content = f.read()

    original = content
    for old, new in REPLACEMENTS.items():
        content = content.replace(old, new)

    if content != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated: {filepath}")
        return True
    return False

def main():
    """Update all Python files."""
    base_dir = r"c:\Users\E-YAZILIM\Desktop\drakben\drakbendosyalar"
    total = 0

    for root, dirs, files in os.walk(base_dir):
        # Skip __pycache__ and .venv
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".venv", ".git")]

        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                if update_file(filepath):
                    total += 1

    print(f"\nTotal files updated: {total}")

if __name__ == "__main__":
    main()
