import re
from pathlib import Path


def revert_broken_asserts(content):
    """Reverts the broken if-not blocks back to standard asserts."""
    # Complex regex to catch the mess and restore the assert
    pattern = r'if not (.*?), \(:\s+raise AssertionError\(.*?\), \(\'\s+"(.*?)"\s+\)'
    replacement = r'assert \1, "\2"'

    # This specifically addresses the pattern found in our failed tests
    content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

    # Also catch many variations: if not condition: \n raise Error('condition')
    pattern_simple = r"if not (.*?):\s+raise AssertionError\(\'(.*?)\'\)"
    replacement_simple = r"assert \1"
    return re.sub(pattern_simple, replacement_simple, content)


def main() -> None:
    # Target only tests/ and maybe other files if needed
    targets = ["tests"]
    fixed_count = 0
    for target in targets:
        for py_file in Path(target).rglob("*.py"):
            try:
                with open(py_file, encoding="utf-8") as f:
                    content = f.read()

                new_content = revert_broken_asserts(content)

                if new_content != content:
                    with open(py_file, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    fixed_count += 1
            except Exception:
                pass


if __name__ == "__main__":
    main()
