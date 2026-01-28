
import sys
from importlib.metadata import distributions
import importlib
import ast
import os
from pathlib import Path

def get_imports_from_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
    except Exception: # SONARQUBE FIX: Avoid bare except
        return set()
    
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                imports.add(n.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split('.')[0])
    return imports

def _get_import_status(imp, installed, mapping):
    """Helper to determine status of a single import"""
    # 1. Standard Lib
    # The list of common standard library modules is extensive.
    # We'll rely on sys.builtin_module_names and a few common ones not always in builtin_module_names
    # but are part of the standard library and don't need explicit installation.
    # The original code had a very long list, which is redundant if sys.builtin_module_names is used.
    # For simplicity and to avoid maintaining a huge list, we'll check against sys.builtin_module_names
    # and assume if it's not installed and not in builtin_module_names, it's missing.
    # The original code's "Built-in/System Module (Imported successfully)" message for non-installed
    # but importable modules is implicitly covered by the standard library check or if it's truly
    # a system-wide installed package not detected by `distributions()`.
    if imp in sys.builtin_module_names:
        return "std", None
        
    # 2. Local Module
    if os.path.isdir(imp) or os.path.isfile(f"{imp}.py"):
        return "local", None

    # 3. Installed Package
    pkg_name = mapping.get(imp, imp)
    if pkg_name and pkg_name.lower() in installed:
        return "installed", f"{pkg_name} (v{installed[pkg_name.lower()]})"
    
    # 4. Missing
    return "missing", None

def check_integration():
    print("🔍 INTEGRATION & DEPENDENCY PROOF SCAN")
    print("="*60)
    
    # 1. Get Installed Packages
    installed = {dist.metadata['Name'].lower(): dist.version for dist in distributions()}
    print(f"📦 Installed Packages Detected: {len(installed)}")
    
    # 2. Get Used Imports
    root = Path(os.getcwd())
    all_imports = set()
    for py_file in root.rglob("*.py"):
        if "env" in str(py_file) or "venv" in str(py_file) or "site-packages" in str(py_file): continue
        all_imports.update(get_imports_from_file(py_file))

    # 3. Verify
    print("\n🔬 Verifying Imports vs. Installed Packages:")
    # Mapping common imports to package names
    mapping = {
        "cv2": "opencv-python",
        "PIL": "pillow",
        "bs4": "beautifulsoup4",
        "dotenv": "python-dotenv",
        "yaml": "PyYAML",
        "msgpack": "msgpack",
        "rich": "rich",
        # Removed stdlib entries as they are handled by sys.builtin_module_names
    }

    missing_count = 0
    
    for imp in sorted(all_imports):
        status, info = _get_import_status(imp, installed, mapping)
        
        if status == "std":
            # For standard library modules, we can assume they are importable.
            # The original code had a `try-except ImportError` for this, but for stdlib, it's redundant.
            print(f"  ⚠️ {imp:<15} -> Standard Library Module - OK")
        elif status == "local":
             print(f"  📂 {imp:<15} -> Local Project Module - OK")
        elif status == "installed":
            print(f"  ✅ {imp:<15} -> {info} - OK")
        else: # status == "missing"
            # As a final fallback, try to import it. Some modules might be system-installed
            # but not reported by `distributions()` (e.g., some OS-level Python packages).
            try:
                importlib.import_module(imp)
                print(f"  ⚠️ {imp:<15} -> System-wide/Implicitly Available Module - OK")
            except ImportError:
                print(f"  ❌ {imp:<15} -> MISSING IN ENVIRONMENT!")
                missing_count += 1

    print("-" * 60)
    if missing_count == 0:
        print("✅ PROJECT INTEGRATION VERIFIED: 100% MATCH")
        sys.exit(0)
    else:
        print(f"❌ FAILED: {missing_count} missing dependencies found.")
        sys.exit(1)

if __name__ == "__main__":
    check_integration()
