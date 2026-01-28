
import sys
from importlib.metadata import distributions
import importlib
import ast
import os
from pathlib import Path

def get_imports_from_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read())
        except:
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
        if "venv" in str(py_file) or "site-packages" in str(py_file): continue
        all_imports.update(get_imports_from_file(py_file))
    
    # Filter standard lib (approximate)
    std_lib = sys.builtin_module_names
    # Mapping common imports to package names
    mapping = {
        "bs4": "beautifulsoup4",
        "yaml": "pyyaml",
        "dotenv": "python-dotenv",
        "PIL": "pillow",
        "cv2": "opencv-python",
        "sklearn": "scikit-learn",
        "typing": None, "os": None, "sys": None, "json": None, "re": None # stdlib
    }
    
    missing = []
    
    print("\n🔬 Verifying Imports vs. Installed Packages:")
    for imp in sorted(all_imports):
        if imp in sys.builtin_module_names or imp in ["sys", "os", "time", "json", "logging", "asyncio", "threading", "subprocess", "ast", "abc", "argparse", "base64", "collections", "contextlib", "copy", "csv", "dataclasses", "datetime", "difflib", "enum", "functools", "glob", "hashlib", "importlib", "inspect", "io", "itertools", "math", "multiprocessing", "operator", "pathlib", "pickle", "platform", "queue", "random", "shlex", "shutil", "signal", "socket", "sqlite3", "string", "struct", "tempfile", "textwrap", "traceback", "types", "unittest", "urllib", "uuid", "warnings", "weakref", "zipfile"]:
            continue # Standard Lib
            
        # Check if local module
        if os.path.isdir(imp) or os.path.isfile(f"{imp}.py"):
             print(f"  📂 {imp:<15} -> Local Project Module - OK")
             continue
            
        pkg_name = mapping.get(imp, imp)
        if pkg_name is None: continue
        
        if pkg_name.lower() in installed:
            print(f"  ✅ {imp:<15} -> {pkg_name:<15} (v{installed[pkg_name.lower()]}) - OK")
        else:
            # Try verification by import
            try:
                importlib.import_module(imp)
                print(f"  ⚠️ {imp:<15} -> Built-in/System Module (Imported successfully)")
            except ImportError:
                print(f"  ❌ {imp:<15} -> MISSING IN ENVIRONMENT!")
                missing.append(imp)
    
    print("-" * 60)
    if missing:
        print(f"❌ FAILED: {len(missing)} missing dependencies found.")
        sys.exit(1)
    else:
        print("✅ SUCCESS: All imports are satisfied by installed packages or standard library.")
        sys.exit(0)

if __name__ == "__main__":
    check_integration()
