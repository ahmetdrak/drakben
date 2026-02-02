import subprocess
import sys
import time


def run_command(command) -> bool | None:
    start_time = time.time()
    try:
        # Running via subprocess to ensure clean environment
        process = subprocess.run(
            command,
            shell=True,
            check=False,
        )
        time.time() - start_time

        return process.returncode == 0
    except Exception:
        return False


def main() -> None:
    # 1. Check Dependencies
    # This assumes pip packages are installed.
    # In a real pipeline we might check 'pip list' but let's assume valid env for now.

    # 2. Run Unit Tests with Coverage
    # Use python -m pytest to ensure path is picked up correctly if installed in site-packages or just use python context
    # -v for verbose
    success = run_command("python -m pytest tests/ -v")

    # 3. Summary
    if success:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
