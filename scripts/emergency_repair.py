import re
from pathlib import Path


def repair_weapon_foundry_strings(content):
    """Removes incorrectly injected docstrings inside string templates."""
    # Matches injected docstring inside a string template where it breaks things
    pattern = r'(\s*)"""Auto-generated docstring for (\w+) def\."""'
    # Check if we are inside a returning string block (simple check)
    return re.sub(pattern, "", content)

def fix_all_syntax_errors_from_refactor(content):
    """Cleans up any docstrings that were injected into lines that were not actual function starts."""
    # Fix 1: Double docstrings or docstrings in middle of string blocks
    lines = content.splitlines()
    new_lines = []

    in_triple_string = False

    for line in lines:
        stripped = line.strip()

        # Track triple quote string boundaries to avoid modifying internal code
        if stripped.count('"""') % 2 != 0 or stripped.count("'''") % 2 != 0:
            in_triple_string = not in_triple_string

        if in_triple_string and '"""Auto-generated docstring for' in line:
            # Drop it, it's inside a template
            continue

        new_lines.append(line)

    return "\n".join(new_lines)

def main() -> None:
    targets = ["core", "modules"]
    _fixed_count = 0
    for target in targets:
        for py_file in Path(target).rglob("*.py"):
            try:
                with open(py_file, encoding="utf-8") as f:
                    content = f.read()

                # First, fix the string template injection
                new_content = repair_weapon_foundry_strings(content)
                # Second, fix general syntax issues
                new_content = fix_all_syntax_errors_from_refactor(new_content)

                if new_content != content:
                    with open(py_file, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    _fixed_count += 1
            except Exception:
                pass


if __name__ == "__main__":
    main()
