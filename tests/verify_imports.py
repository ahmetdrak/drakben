
import unittest
import importlib
import pkgutil
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestImports(unittest.TestCase):
    def test_import_modules(self):
        """Attempts to import all modules in core and modules directories."""
        packages = ['core', 'modules']
        failed_imports = []
        
        for package in packages:
             # Manually walk since pkgutil.walk_packages might skip some if __init__ is missing
             package_path = os.path.join(os.path.dirname(__file__), '..', package)
             if not os.path.exists(package_path):
                 print(f"Package path not found: {package_path}")
                 continue
                 
             for root, dirs, files in os.walk(package_path):
                for file in files:
                    if file.endswith('.py') and not file == '__init__.py':
                        # Construct module name
                        rel_path = os.path.relpath(os.path.join(root, file), os.path.join(os.path.dirname(__file__), '..'))
                        module_name = rel_path.replace(os.path.sep, '.')[:-3]
                        
                        try:
                            importlib.import_module(module_name)
                            print(f"✅ Imported: {module_name}")
                        except Exception as e:
                            print(f"❌ Failed: {module_name} -> {e}")
                            failed_imports.append((module_name, str(e)))

        if failed_imports:
            self.fail(f"Import failures found: {failed_imports}")

if __name__ == '__main__':
    unittest.main()
