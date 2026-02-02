import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any


class DrakbenLogger:
    """Structured Logger for Drakben Agent decisions and actions.
    Saves logs in JSONL format for easy parsing and analysis.
    """

    def __init__(self, log_dir: str = "logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Current session log file
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"drakben_session_{self.session_id}.jsonl"

        self.logger = logging.getLogger("DrakbenStructured")

    def log_decision(
        self,
        step_id: str,
        phase: str,
        context: dict[str, Any],
        decision: dict[str, Any],
        reasoning: str = "",
    ) -> None:
        """Log an AI decision point."""
        entry = {
            "timestamp": datetime.fromtimestamp(time.time()).isoformat(),
            "type": "DECISION",
            "step_id": step_id,
            "phase": phase,
            "context_snapshot": context,
            "decision": decision,
            "reasoning": reasoning,
        }
        self._write(entry)

    def log_action(
        self, tool: str, args: dict[str, Any], result: dict[str, Any],
    ) -> None:
        """Log a tool execution action and result."""
        # Clean result to avoid storing massive outputs
        cleaned_result = result.copy()
        if "stdout" in cleaned_result:
            cleaned_result["stdout"] = (
                cleaned_result["stdout"][:500] + "... (truncated)"
            )
        if "stderr" in cleaned_result:
            cleaned_result["stderr"] = (
                cleaned_result["stderr"][:500] + "... (truncated)"
            )

        entry = {
            "timestamp": datetime.fromtimestamp(time.time()).isoformat(),
            "type": "ACTION",
            "tool": tool,
            "args": args,
            "result": cleaned_result,
        }
        self._write(entry)

    def log_error(self, message: str, traceback: str = "") -> None:
        """Log a critical error."""
        entry = {
            "timestamp": datetime.fromtimestamp(time.time()).isoformat(),
            "type": "ERROR",
            "message": message,
            "traceback": traceback,
        }
        self._write(entry)

    def _write(self, data: dict[str, Any]) -> None:
        """Write entry to JSONL file."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            # Fallback to standard logging if file write fails
            self.logger.exception("Failed to write structured log: %s", e)
