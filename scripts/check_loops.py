from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

pattern_while = re.compile(r'^\s*while\b')
pattern_async_for = re.compile(r'^\s*async\s+for\b')
agenty_keywords = re.compile(r"\b(llm|tool|tool_selector|select_tool|plan|prompt|generate|think|decide|observe|action|max_iteration|max_iterations|run_autonomous_loop|brain|agentic)\b", re.I)
benign_indicators = re.compile(r"\b(queue|output_queue|visited|hosts|state|self\.running|\.empty\(|len\(|hop\s*<|for\s+.+in)\b", re.I)
skip_parts = ('.venv', 'venv', 'site-packages', 'tests', 'docs', 'node_modules')

issues = []
for p in ROOT.rglob('*.py'):
    sp = str(p)
    if any(skip in sp for skip in skip_parts):
        continue
    rel = p.relative_to(ROOT)
    if str(rel) == 'core/refactored_agent.py':
        continue
    try:
        text = p.read_text(encoding='utf-8')
    except Exception:
        continue
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if pattern_while.match(line) or pattern_async_for.search(line):
            start = max(0, i - 5)
            end = min(len(lines), i + 8)
            context = "\n".join(lines[start:end])
            if agenty_keywords.search(context):
                issues.append(f"{rel}:{i}: {line.strip()}")
                continue
            if benign_indicators.search(context):
                continue
            if str(rel).startswith('core/'):
                issues.append(f"{rel}:{i}: {line.strip()}")

print('Detected potential agent-like loops:')
for it in issues:
    print(it)
print('\nSummary: {} potential issues'.format(len(issues)))
