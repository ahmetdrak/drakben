
import unittest
import importlib
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestImports(unittest.TestCase):
    def _test_module_import(self, module_name):
        """Helper to test a single module import"""
        try:
            importlib.import_module(module_name)
            print(f"✅ Imported: {module_name}")
            return None
        except Exception as e:
            print(f"❌ Failed: {module_name} -> {e}")
            return (module_name, str(e))

    def _get_modules_to_test(self, package):
        """Helper to collect module names from a package"""
        modules = []
        package_path = os.path.join(os.path.dirname(__file__), '..', package)
        if not os.path.exists(package_path):
            print(f"Package path not found: {package_path}")
            return modules

        for root, _, files in os.walk(package_path):
            for file in files:
                if file.endswith('.py') and file != '__init__.py':
                    rel_path = os.path.relpath(os.path.join(root, file), os.path.join(os.path.dirname(__file__), '..'))
                    module_name = rel_path.replace(os.path.sep, '.')[:-3]
                    modules.append(module_name)
        return modules

    def test_import_modules(self):
        """Attempts to import all modules in core and modules directories."""
        packages = ['core', 'modules']
        failed_imports = []
        
        for package in packages:
            modules = self._get_modules_to_test(package)
            for module_name in modules:
                failure = self._test_module_import(module_name)
                if failure:
                    failed_imports.append(failure)

        if failed_imports:
            self.fail(f"Import failures found: {failed_imports}")

if __name__ == '__main__':
    unittest.main()
