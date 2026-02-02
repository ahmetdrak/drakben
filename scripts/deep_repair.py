import re
from pathlib import Path


def repair_broken_assert_conversion(content):
    """Specifically targets the broken pattern:
    if not condition, (:
        raise AssertionError('condition'), ('
        "message"
    ).

    Transforms it to:
    if not condition:
        raise AssertionError("message")
    """
    # Combined regex to catch this specific multi-line mess
    # Pattern: if not (condition), (: \s+ raise AssertionError('...'), (' \s+ "message" \s+ )
    pattern = r'if not (.*?), \(:\s+raise AssertionError\(.*?\), \(\'\s+"(.*?)"\s+\)'

    def replacement(match) -> str:
        condition = match.group(1).strip()
        msg = match.group(2).strip()
        # Ensure we don't have trailing commas or weird parens in condition
        if condition.endswith(")"):
            pass # Good
        return f'if not {condition}:\n        raise AssertionError("{msg}")'

    return re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)

def main() -> None:
    targets = ["tests"]
    _fixed_count = 0
    for target in targets:
        for py_file in Path(target).rglob("*.py"):
            try:
                with open(py_file, encoding="utf-8") as f:
                    content = f.read()

                new_content = repair_broken_assert_conversion(content)

                if new_content != content:
                    with open(py_file, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    _fixed_count += 1
            except Exception:
                pass


if __name__ == "__main__":
    main()
