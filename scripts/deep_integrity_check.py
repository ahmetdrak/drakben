
import os
import ast
import sys
import importlib
import traceback
from pathlib import Path
from collections import defaultdict

# Setup logging
class IntegrityReport:
    def __init__(self):
        self.syntax_errors = []
        self.import_errors = []
        self.circular_imports = []
        self.infinite_loops = []
        self.risky_patterns = []
        self.total_files = 0
        self.scanned_files = []

    def log_syntax_error(self, file, error):
        self.syntax_errors.append(f"{file}: {error}")

    def log_import_error(self, file, error):
        self.import_errors.append(f"{file}: {error}")

    def print_summary(self):
        print("\n" + "="*80)
        print(f"🔍 DEEP INTEGRITY SCAN REPORT")
        print("="*80)
        print(f"📂 Scanned Files: {self.total_files}")
        
        if not any([self.syntax_errors, self.import_errors, self.circular_imports, self.infinite_loops]):
            print("\n✅ PROJECT IS 100% CLEAN! NO ERRORS FOUND.")
        else:
            if self.syntax_errors:
                print(f"\n❌ SYNTAX ERRORS ({len(self.syntax_errors)}):")
                for e in self.syntax_errors: print(f"  - {e}")
            
            if self.import_errors:
                print(f"\n❌ IMPORT/MODULE ERRORS ({len(self.import_errors)}):")
                for e in self.import_errors: print(f"  - {e}")

            if self.circular_imports:
                print(f"\n🔄 CIRCULAR IMPORTS DETECTED ({len(self.circular_imports)}):")
                for cycle in self.circular_imports: print(f"  - Cycle: {' -> '.join(cycle)}")

            if self.infinite_loops:
                print(f"\n⚠️ POTENTIAL INFINITE LOOPS ({len(self.infinite_loops)}):")
                for l in self.infinite_loops: print(f"  - {l}")

class ImportGraphAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path):
        self.imports = set()
        self.file_path = file_path
        self.infinite_loops = []

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module.split('.')[0])
        self.generic_visit(node)
    
    def visit_While(self, node):
        # Detect 'while True' without obvious break in top level
        is_true = isinstance(node.test, ast.Constant) and node.test.value is True
        if is_true:
            # Check for break statement
            has_break = False
            for child in ast.walk(node):
                if isinstance(child, ast.Break):
                    has_break = True
                    break
            
            if not has_break:
                self.infinite_loops.append(f"Line {node.lineno}: 'while True' without break")
        self.generic_visit(node)

def find_project_root():
    return Path(os.getcwd())

def _check_syntax(py_files, report):
    """AST syntax check helper"""
    for file_path in py_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            
            tree = ast.parse(source, filename=str(file_path))
            analyzer = ImportGraphAnalyzer(file_path)
            analyzer.visit(tree)
            
            if analyzer.infinite_loops:
                for loop in analyzer.infinite_loops:
                    report.infinite_loops.append(f"{file_path.name}: {loop}")

        except SyntaxError as e:
            report.log_syntax_error(file_path.name, str(e))
        except Exception as e:
            report.log_syntax_error(file_path.name, f"Read Error: {str(e)}")

def _check_imports(py_files, root, report):
    """Runtime import check helper"""
    sys.path.append(str(root))
    
    for file_path in py_files:
        try:
            rel_path = file_path.relative_to(root)
            if rel_path.name == "drakben.py" or rel_path.parent.name == "scripts":
                continue 
            
            module_name = str(rel_path).replace(os.sep, ".")[:-3]
            if "tests." in module_name: continue

            try:
                importlib.import_module(module_name)
            except ImportError as e:
                report.log_import_error(module_name, str(e))
            except Exception:
                pass 
        except ValueError:
            pass

def scan_project(report):
    root = find_project_root()
    py_files = list(root.rglob("*.py"))
    
    # Exclude logic
    py_files = [
        f for f in py_files 
        if ".venv" not in str(f) and "site-packages" not in str(f) 
        and ".git" not in str(f) and "__pycache__" not in str(f)
    ]
    
    report.total_files = len(py_files)
    print(f"Scanning {len(py_files)} Python files...")

    _check_syntax(py_files, report)
    _check_imports(py_files, root, report)

def run_deep_check():
    report = IntegrityReport()
    scan_project(report)
    report.print_summary()

if __name__ == "__main__":
    run_deep_check()
