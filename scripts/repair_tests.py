import re
from pathlib import Path


def repair_tests_syntax(content):
    """Fixes the missing colon and comment placement in if-not blocks."""
    # Pattern: if not expression # comment
    # Should be: if not expression: # comment
    pattern = r"(if not .*?)(\s*)(#.*)"

    # Only apply if it doesn't already have a colon before the comment
    def sub_func(match):
        base = match.group(1).rstrip()
        if base.endswith(":"):
            return match.group(0)
        return f"{base}:{match.group(2)}{match.group(3)}"

    return re.sub(pattern, sub_func, content)

def main() -> None:
    test_files = list(Path("tests").rglob("*.py"))
    _fixed_count = 0
    for test_file in test_files:
        try:
            with open(test_file, encoding="utf-8") as f:
                content = f.read()

            new_content = repair_tests_syntax(content)

            if new_content != content:
                with open(test_file, "w", encoding="utf-8") as f:
                    f.write(new_content)
                _fixed_count += 1
        except Exception:
            pass


if __name__ == "__main__":
    main()
