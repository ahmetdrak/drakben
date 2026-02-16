"""DRAKBEN Research - Target Analyzer
Author: @drak_ben
Description: Static analysis and LLM-guided target selection for fuzzing.
"""

import ast
import logging

logger = logging.getLogger(__name__)


class TargetAnalyzer:
    """Analyzes source code to find promising fuzzing targets."""

    def __init__(self) -> None:
        self.dangerous_functions = {
            "eval": 10,
            "exec": 10,
            "os.system": 9,
            "subprocess.call": 8,
            "subprocess.run": 8,
            "pickle.loads": 9,
            "yaml.load": 7,
            "input": 5,
        }
        logger.info("Target Analyzer initialized")

    def analyze_file(self, file_path: str) -> list[dict]:
        """Analyze a single Python file for dangerous function calls.

        Args:
            file_path: Path to the Python source file.

        Returns:
            List of findings, each with 'function', 'line', 'score', 'context'.
        """
        import ast

        findings: list[dict] = []
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                source = f.read()
            tree = ast.parse(source, filename=file_path)
        except (SyntaxError, OSError) as e:
            logger.warning("Could not parse %s: %s", file_path, e)
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name and func_name in self.dangerous_functions:
                    findings.append(
                        {
                            "function": func_name,
                            "line": getattr(node, "lineno", 0),
                            "score": self.dangerous_functions[func_name],
                            "file": file_path,
                            "context": ast.get_source_segment(source, node) or "",
                        }
                    )

        return sorted(findings, key=lambda x: x["score"], reverse=True)

    def analyze_directory(self, directory: str, pattern: str = "**/*.py") -> list[dict]:
        """Recursively analyze all Python files in a directory.

        Args:
            directory: Root directory to scan.
            pattern: Glob pattern for file matching.

        Returns:
            Aggregated findings sorted by risk score.
        """
        from pathlib import Path

        all_findings: list[dict] = []
        root = Path(directory)
        for py_file in root.glob(pattern):
            all_findings.extend(self.analyze_file(str(py_file)))

        return sorted(all_findings, key=lambda x: x["score"], reverse=True)

    def get_top_targets(self, directory: str, limit: int = 10) -> list[dict]:
        """Get the top N most promising fuzzing targets.

        Args:
            directory: Root directory to analyze.
            limit: Maximum number of targets to return.

        Returns:
            Top findings by risk score.
        """
        return self.analyze_directory(directory)[:limit]

    @staticmethod
    def _get_func_name(node: ast.Call) -> str | None:
        """Extract function name from AST Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            # Handle module.function pattern (e.g. os.system)
            parts = []
            current: ast.expr = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None
