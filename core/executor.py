from core.terminal import TerminalExecutor

class Executor:
    """Compatibility wrapper over TerminalExecutor."""

    def __init__(self, log_dir: str = "logs", auto_approve: bool = False):
        self.terminal = TerminalExecutor(log_dir=log_dir, auto_approve=auto_approve)

    def run(self, command: str) -> str:
        """Tek komut çalıştırır ve çıktıyı döndürür."""
        try:
            result = self.terminal.run_command(command)
            output = "\n".join([part for part in [result.output, result.error] if part]).strip()
            return output
        except Exception as e:
            return f"[Executor Error] {e}"

    def execute(self, command: str) -> str:
        """Backwards-compatible alias for run()."""
        return self.run(command)

    def run_chain(self, chain: list) -> list:
        """Zincir boyunca komutları sırayla çalıştırır."""
        outputs = []
        for step in chain:
            try:
                # Hem "suggestion" hem "command" key'ini destekle
                command_text = step.get("suggestion") or step.get("command")
                if not command_text:
                    outputs.append({
                        "step": step.get("step"),
                        "command": "[ERROR] Komut bulunamadı",
                        "output": "Adımda 'suggestion' veya 'command' anahtarı yok"
                    })
                    continue

                result = self.terminal.run_command(command_text)
                output = "\n".join([part for part in [result.output, result.error] if part]).strip()
                outputs.append({
                    "step": step.get("step"),
                    "command": command_text,
                    "output": output
                })
            except Exception as e:
                outputs.append({
                    "step": step.get("step"),
                    "command": step.get("suggestion") or step.get("command"),
                    "output": f"[Executor Error] {e}"
                })
        return outputs
