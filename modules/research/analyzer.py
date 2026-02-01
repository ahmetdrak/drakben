"""
DRAKBEN Research - Target Analyzer
Author: @drak_ben
Description: Static analysis and LLM-guided target selection for fuzzing.
"""

import ast
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CodeHotspot:
    file_path: str
    line_number: int
    function_name: str
    risk_score: int
    reason: str


class TargetAnalyzer:
    """
    Analyzes source code to find promising fuzzing targets.
    """

    def __init__(self):
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

    def analyze_file(self, file_path: str) -> list[CodeHotspot]:
        """
        Parse file AST and find dangerous sinks.
        """
        hotspots = []
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = self._get_func_name(node)
                    if func_name in self.dangerous_functions:
                        hotspots.append(
                            CodeHotspot(
                                file_path=file_path,
                                line_number=node.lineno,
                                function_name=func_name,
                                risk_score=self.dangerous_functions[func_name],
                                reason=f"Usage of dangerous function '{func_name}'",
                            )
                        )

        except Exception as e:
            logger.error(f"Analysis failed for {file_path}: {e}")

        return sorted(hotspots, key=lambda x: x.risk_score, reverse=True)

    def _get_func_name(self, node: ast.Call) -> str:
        """Helper to extract function name from AST node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Try to get module.function
            try:
                base = node.func.value.id
                return f"{base}.{node.func.attr}"
            except Exception:
                return node.func.attr
        return ""

    def suggest_fuzz_vectors(self, hotspot: CodeHotspot) -> list[str]:
        """
        Suggest initial seed inputs based on the sink type.
        """
        if "exec" in hotspot.function_name or "eval" in hotspot.function_name:
            return ["import os; os.system('id')", "__import__('os').system('sh')"]
        elif "system" in hotspot.function_name:
            return ["; id", "| id", "`id`", "$(id)"]
        elif "pickle" in hotspot.function_name:
            # Dangerous pickle payload placeholder
            return [b"\x80\x03cposix\nsystem\n..."]
        return ["A" * 500]
