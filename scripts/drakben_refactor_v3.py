import re
from pathlib import Path


def fix_logging_fstrings(content):
    """G004: Convert logging f-strings to standard %s format."""
    # Matches: logger.info(f"msg {var}") or logging.debug(f"msg {var}")
    pattern = r'(logger|logging)\.(debug|info|warning|error|exception|critical)\(f"([^"]*)\{(.*?)\}([^"]*)"\)'

    def replacement(match) -> str:
        log_obj = match.group(1)
        level = match.group(2)
        prefix = match.group(3)
        variable = match.group(4)
        suffix = match.group(5)
        return f'{log_obj}.{level}("{prefix}%s{suffix}", {variable})'

    return re.sub(pattern, replacement, content)


def fix_docstring_format(content):
    """D205, D400: Ensure docstring starts with capital and ends with dot."""
    pattern = r'"""(auto-generated docstring for \w+ \w+)"""'

    def replacement(match) -> str:
        text = match.group(1).capitalize()
        return f'"""{text}."""'

    return re.sub(pattern, replacement, content)


def process_file(filepath) -> bool:
    try:
        with open(filepath, encoding="utf-8") as f:
            content = f.read()

        original = content

        # Apply fixes
        content = fix_logging_fstrings(content)
        content = fix_docstring_format(content)

        if content != original:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            return True
    except Exception:
        pass
    return False


def main() -> None:
    targets = ["core", "modules"]
    fixed_count = 0
    total_files = 0

    for target in targets:
        path = Path(target)
        if path.exists():
            for py_file in path.rglob("*.py"):
                total_files += 1
                if process_file(py_file):
                    fixed_count += 1



if __name__ == "__main__":
    main()
