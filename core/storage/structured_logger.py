import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console


class DrakbenLogger:
    """Structured Logger for Drakben Agent decisions and actions.
    Saves logs in JSONL format for easy parsing and analysis.
    NOW with console output for user visibility!
    """

    def __init__(self, log_dir: str = "logs", verbose: bool = True) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Current session log file
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"drakben_session_{self.session_id}.jsonl"

        self.logger = logging.getLogger("DrakbenStructured")
        self.console = Console()
        self.verbose = verbose  # Show LLM decisions on console

    def log_action(
        self,
        tool: str,
        args: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Log a tool execution action and result."""
        # Clean result to avoid storing massive outputs
        cleaned_result = result.copy()
        if "stdout" in cleaned_result and isinstance(cleaned_result["stdout"], str):
            if len(cleaned_result["stdout"]) > 500:
                cleaned_result["stdout"] = cleaned_result["stdout"][:500] + "... (truncated)"
        if "stderr" in cleaned_result and isinstance(cleaned_result["stderr"], str):
            if len(cleaned_result["stderr"]) > 500:
                cleaned_result["stderr"] = cleaned_result["stderr"][:500] + "... (truncated)"

        entry = {
            "timestamp": datetime.fromtimestamp(time.time()).isoformat(),
            "type": "ACTION",
            "tool": tool,
            "args": args,
            "result": cleaned_result,
        }
        self._write(entry)

        # Show action result to user
        if self.verbose:
            success = result.get("success", False)
            if success:
                self.console.print(f"   ✅ {tool} başarılı", style="green")
            else:
                error = result.get("error", result.get("stderr", ""))[:100]
                self.console.print(f"   ❌ {tool} başarısız: {error}", style="red")

    def _write(self, data: dict[str, Any]) -> None:
        """Write entry to JSONL file."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            # Fallback to standard logging if file write fails
            self.logger.exception("Failed to write structured log: %s", e)
