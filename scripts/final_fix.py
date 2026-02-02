import re
from pathlib import Path


def final_syntax_cleanup(content):
    """Deep cleanup for syntax errors introduced by the refactoring scripts."""
    # Fix 1: if not condition, "msg": -> if not condition:
    # This was a major failure in my assert-to-if conversion
    pattern1 = r"if not (.*),\s*['\"](.*)['\"]:"
    replacement1 = r"if not \1:\n    raise AssertionError('\2')"
    content = re.sub(pattern1, replacement1, content)

    # Fix 2: Double colons or other weird remnants
    content = content.replace("::", ":")

    # Fix 3: Remove any docstrings accidentally injected into the middle of expressions
    lines = content.splitlines()
    fixed_lines = []
    for line in lines:
        if '"""Auto-generated docstring for' in line and not line.strip().startswith('"""'):
            # This is likely inside an expression or template, drop it
            continue
        fixed_lines.append(line)

    return "\n".join(fixed_lines)

def main() -> None:
    targets = ["core", "modules", "tests", "drakben.py"]
    fixed_count = 0
    for target in targets:
        path = Path(target)
        files = [path] if path.is_file() else path.rglob("*.py")
        for py_file in files:
            try:
                with open(py_file, encoding="utf-8") as f:
                    content = f.read()

                new_content = final_syntax_cleanup(content)

                if new_content != content:
                    with open(py_file, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    fixed_count += 1
            except Exception:
                pass


if __name__ == "__main__":
    main()
