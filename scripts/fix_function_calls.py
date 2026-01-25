#!/usr/bin/env python3
"""
Script to find all call sites of a function when signature changes.
Usage: python scripts/fix_function_calls.py <function_name> <file_path>
"""

import re
import sys
from pathlib import Path

def find_function_calls(function_name: str, file_path: str) -> list:
    """Find all call sites of a function"""
    file_content = Path(file_path).read_text(encoding='utf-8')
    lines = file_content.split('\n')
    
    # Pattern to match function calls: function_name(...)
    pattern = rf'\b{re.escape(function_name)}\s*\('
    
    call_sites = []
    for i, line in enumerate(lines, 1):
        if re.search(pattern, line):
            call_sites.append((i, line.strip()))
    
    return call_sites

def find_all_call_sites(function_name: str, project_root: str = '.') -> dict:
    """Find all call sites across the project"""
    project_path = Path(project_root)
    results = {}
    
    # Search in Python files
    for py_file in project_path.rglob('*.py'):
        if 'venv' in str(py_file) or '__pycache__' in str(py_file):
            continue
        
        calls = find_function_calls(function_name, str(py_file))
        if calls:
            results[str(py_file)] = calls
    
    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python scripts/fix_function_calls.py <function_name> [project_root]")
        sys.exit(1)
    
    function_name = sys.argv[1]
    project_root = sys.argv[2] if len(sys.argv) > 2 else '.'
    
    print(f"Searching for calls to '{function_name}'...")
    results = find_all_call_sites(function_name, project_root)
    
    if not results:
        print(f"No calls to '{function_name}' found.")
    else:
        print(f"\nFound {sum(len(calls) for calls in results.values())} call(s):\n")
        for file_path, calls in results.items():
            print(f"{file_path}:")
            for line_num, line in calls:
                print(f"  L{line_num}: {line}")
            print()
