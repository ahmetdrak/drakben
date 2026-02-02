from pathlib import Path


def repair_indentation(content):
    """Specifically repairs indentation for the if-raise-AssertionError pattern."""
    lines = content.splitlines()
    fixed_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        fixed_lines.append(line)

        # If we find our problematic pattern: if not condition: \n raise Error
        # We need to make sure the NEXT line is correctly indented if it was part of the original block
        if "if not " in line and line.strip().endswith(":") and "raise AssertionError" in (lines[i+1] if i+1 < len(lines) else ""):
            # We already have the raise correctly indented in our latest scripts (hopefully)
            # But let's check
            indent = len(line) - len(line.lstrip())

            # The next line (the raise)
            if i + 1 < len(lines):
                next_line = lines[i+1]
                if "raise AssertionError" in next_line and len(next_line) - len(next_line.lstrip()) <= indent:
                    # Fix the raise indentation
                    fixed_lines.pop() # Remove original line
                    fixed_lines.append(line)
                    lines[i+1] = " " * (indent + 4) + next_line.lstrip()
                    # We don't append it here, the loop will handle it in the next step
        i += 1
    return "\n".join(fixed_lines)

def main() -> None:
    targets = ["core", "modules", "tests"]
    _fixed_count = 0
    for target in targets:
        for py_file in Path(target).rglob("*.py"):
            try:
                with open(py_file, encoding="utf-8") as f:
                    content = f.read()

                new_content = repair_indentation(content)

                if new_content != content:
                    with open(py_file, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    _fixed_count += 1
            except Exception:
                pass


if __name__ == "__main__":
    main()
