
import importlib
import sys
import os
from pathlib import Path

def check_circular_imports(directory):
    print(f"Checking for circular imports in {directory}...")
    core_path = Path(directory)
    python_files = list(core_path.glob("*.py"))
    
    sys.path.append(str(core_path.parent))
    
    failure_count = 0
    for file in python_files:
        module_name = f"core.{file.stem}"
        try:
            # Unload if already loaded to force a fresh check
            if module_name in sys.modules:
                del sys.modules[module_name]
            importlib.import_module(module_name)
        except ImportError as e:
            if "circular import" in str(e).lower():
                print(f"❌ CIRCULAR IMPORT DETECTED: {module_name} -> {e}")
                failure_count += 1
            else:
                # Other import errors are also bad
                print(f"❌ IMPORT ERROR in {module_name}: {e}")
                failure_count += 1
        except Exception as e:
            # Syntax errors or runtime module errors
            print(f"❌ CRITICAL ERROR importing {module_name}: {e}")
            failure_count += 1
            
    if failure_count == 0:
        print("✅ No circular imports or basic import errors detected.")
    else:
        print(f"❌ Found {failure_count} import-related issues.")

if __name__ == "__main__":
    check_circular_imports("core")
