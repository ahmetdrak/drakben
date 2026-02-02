import re
from pathlib import Path


def fix_assert_colons(content):
    """Removes trailing colons from assert statements."""
    # Pattern: assert expression: # comment
    # Should be: assert expression # comment
    return re.sub(r"assert (.*):(\s*)(#.*|$)", r"assert \1\2\3", content)

def main() -> None:
    test_files = list(Path("tests").rglob("*.py"))
    _fixed_count = 0
    for test_file in test_files:
        try:
            with open(test_file, encoding="utf-8") as f:
                content = f.read()

            new_content = fix_assert_colons(content)

            if new_content != content:
                with open(test_file, "w", encoding="utf-8") as f:
                    f.write(new_content)
                _fixed_count += 1
        except Exception:
            pass


if __name__ == "__main__":
    main()
