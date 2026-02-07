"""Refactored Agent — Tool Recovery Mixin.

Provides comprehensive self-healing for tool execution failures,
including auto-install, permission fixes, connection retry,
and LLM-assisted error diagnosis.

Extracted from refactored_agent.py for maintainability.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from re import Match

    from core.execution.execution_engine import ExecutionResult

logger = logging.getLogger(__name__)


class RAToolRecoveryMixin:
    """Mixin providing tool failure recovery for RefactoredDrakbenAgent.

    Expects the host class to provide:
    - self.console, self.tool_selector, self.healer, self.brain, self.executor
    - self.MAX_SELF_HEAL_PER_TOOL (int constant)
    - self._diagnose_error() (from ErrorDiagnosticsMixin)
    - self._format_tool_result() (from main class)
    """

    def _handle_tool_failure(
        self,
        tool_name: str,
        command: str,
        result: ExecutionResult,
        args: dict,
    ) -> dict:
        """Handle tool failure with comprehensive self-healing.

        Error Types Handled:
        1. Missing tool → Auto-install
        2. Permission denied → Suggest sudo / elevate
        3. Connection refused → Network check / retry
        4. Timeout → Increase timeout / retry
        5. Python module missing → pip install
        6. Unknown → LLM-assisted diagnosis

        LOOP PROTECTION:
        - Maximum 2 self-heal attempts per tool per session
        - Prevents infinite retry loops
        """
        # Initialize tracking dict if needed
        if not hasattr(self, "_self_heal_attempts") or self._self_heal_attempts is None:
            self._self_heal_attempts: dict[str, int] = {}

        # Check if we've exceeded self-heal limit for this tool
        heal_key: str = f"{tool_name}:{command[:50]}"
        current_attempts: int = self._self_heal_attempts.get(heal_key, 0)

        if current_attempts >= self.MAX_SELF_HEAL_PER_TOOL:
            self.console.print(
                f"⚠️ {tool_name} için self-heal limiti aşıldı ({current_attempts}/{self.MAX_SELF_HEAL_PER_TOOL})",
                style="yellow",
            )
            self.tool_selector.record_tool_failure(tool_name)
            return self._format_tool_result(result, args)

        stdout_str = result.stdout or ""
        stderr_str = result.stderr or ""
        combined_output: str = f"{stdout_str}\n{stderr_str}".lower()

        # Diagnose error type
        error_diagnosis = self._diagnose_error(combined_output, result.exit_code)

        if error_diagnosis["type"] != "unknown":
            self.console.print(
                f"🔍 Hata teşhisi: {error_diagnosis['type_tr']}",
                style="yellow",
            )

        # Increment self-heal attempt counter
        self._self_heal_attempts[heal_key] = current_attempts + 1
        self.console.print(
            f"🔧 Self-heal denemesi: {current_attempts + 1}/{self.MAX_SELF_HEAL_PER_TOOL}",
            style="dim",
        )

        # Apply self-healing based on error type
        healed, retry_result = self._apply_error_specific_healing(
            error_diagnosis,
            tool_name,
            command,
            combined_output,
        )

        return self._finalize_healing_result(
            healed,
            retry_result,
            result,
            tool_name,
            args,
        )

    def _apply_error_specific_healing(
        self,
        error_diagnosis: dict[str, Any],
        tool_name: str,
        command: str,
        combined_output: str,
    ) -> tuple[bool, Any | None]:
        """Apply error-specific healing strategies using SelfHealer."""
        # Delegate to SelfHealer for known error types
        healed, result = self.healer.apply_healing(error_diagnosis, tool_name, command)
        if healed:
            return healed, result

        # For unknown errors, try LLM-assisted fix
        error_type = error_diagnosis.get("type", "unknown")
        if error_type == "unknown" and self.brain:
            return self._llm_assisted_error_fix(tool_name, command, combined_output)

        return False, None

    def _finalize_healing_result(
        self,
        healed: bool,
        retry_result: Any | None,
        result: Any,
        tool_name: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        """Finalize healing result and return formatted output."""
        if healed and retry_result:
            self.console.print("✅ Hata otomatik olarak düzeltildi!", style="green")
            return self._format_tool_result(retry_result, args)

        if result.exit_code != 0:
            self.tool_selector.record_tool_failure(tool_name)

        # FIX: Return formatted result instead of recursive call
        return self._format_tool_result(result, args)

    def _llm_assisted_error_fix(
        self,
        tool_name: str,
        command: str,
        error_output: str,
    ) -> tuple:
        """Use LLM to diagnose unknown errors and suggest fixes.
        Returns (healed: bool, retry_result).
        """
        try:
            self.console.print("🤖 LLM ile hata analizi yapılıyor...", style="dim")

            prompt: str = f"""Analyze this command execution error and suggest a fix:

Command: {command}
Tool: {tool_name}
Error Output: {error_output[:1000]}

Respond in JSON:
{{
    "error_type": "brief error classification",
    "root_cause": "what caused this error",
    "fix_command": "shell command to fix (or null if not fixable)",
    "should_retry": true,
    "explanation": "brief explanation in Turkish"
}}"""

            result = self.brain.llm_client.query(prompt, timeout=15)

            # Try to parse JSON response
            import json
            import re

            json_match: Match[str] | None = re.search(r"\{.*\}", result, re.DOTALL)
            if json_match:
                fix_data = json.loads(json_match.group())

                self.console.print(
                    f"🔍 LLM Analizi: {fix_data.get('explanation', 'Analiz tamamlandı')}",
                    style="dim",
                )

                # Apply fix command if provided
                fix_cmd = fix_data.get("fix_command")
                if fix_cmd and fix_cmd != "null":
                    self.console.print(
                        f"🔧 Düzeltme uygulanıyor: {fix_cmd}",
                        style="yellow",
                    )
                    fix_result: ExecutionResult = self.executor.terminal.execute(
                        fix_cmd,
                        timeout=120,
                    )

                    if fix_result.exit_code == 0 and fix_data.get(
                        "should_retry",
                        False,
                    ):
                        self.console.print(
                            "🔄 Düzeltme başarılı, orijinal komut yeniden deneniyor...",
                            style="cyan",
                        )
                        retry_result: ExecutionResult = self.executor.terminal.execute(
                            command,
                            timeout=300,
                        )
                        return (retry_result.exit_code == 0, retry_result)

        except Exception as e:
            logger.warning("LLM-assisted error fix failed: %s", e)

        return (False, None)
