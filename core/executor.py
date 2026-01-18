import subprocess
import datetime
import os

class Executor:
    def run(self, command: str) -> str:
        """Tek komut çalıştırır ve çıktıyı döndürür."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )
            output = (result.stdout + result.stderr).strip()
            self.log_output(command, output)
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
                    
                result = subprocess.run(
                    command_text,
                    shell=True,
                    capture_output=True,
                    text=True
                )
                output = (result.stdout + result.stderr).strip()
                self.log_output(command_text, output)
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

    def log_output(self, command: str, output: str):
        """Komut çıktısını logs/ klasörüne kaydeder."""
        try:
            if not os.path.exists("logs"):
                os.makedirs("logs")
            ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"logs/{ts}.log"
            with open(filename, "w") as f:
                f.write(f"Command: {command}\n\n{output}")
        except Exception as e:
            print(f"[Log Error] {e}")
