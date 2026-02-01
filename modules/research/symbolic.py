"""
DRAKBEN Research - Symbolic Executor
Author: @drak_ben
Description: Mathematical code path analysis using constraint solving.
"""

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PathConstraint:
    """Represents a condition on an execution path"""

    variable: str
    operator: str  # ==, !=, <, >, <=, >=
    value: Any


@dataclass
class ExecutionPath:
    """A possible execution path through code"""

    path_id: int
    constraints: list[PathConstraint]
    reaches_sink: bool
    sink_name: str = ""


class SymbolicExecutor:
    """
    Performs symbolic execution for vulnerability discovery.
    Uses constraint solving to find inputs that reach dangerous sinks.
    """

    def __init__(self):
        self.z3_available = self._check_z3()
        logger.info(
            f"Symbolic Executor initialized (Z3: {'Available' if self.z3_available else 'Fallback Mode'})"
        )

    @staticmethod
    def _check_z3() -> bool:
        """Check if Z3 solver is available"""
        try:
            import importlib.util

            if not importlib.util.find_spec("z3"):
                raise ImportError

            return True
        except ImportError:
            logger.warning("Z3 not installed. Using heuristic fallback.")
            return False

    def analyze_function(
        self, source_code: str, target_func: str
    ) -> list[ExecutionPath]:
        """
        Symbolically execute a function to find all paths to dangerous sinks.
        """
        import ast

        paths = []

        try:
            tree = ast.parse(source_code)

            # Find target function
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == target_func:
                    paths = self._explore_paths(node)
                    break

        except Exception as e:
            logger.error(f"Symbolic analysis failed: {e}")

        return paths

    def _explore_paths(self, func_node) -> list[ExecutionPath]:
        """Extract execution paths from function AST (Recursive)"""
        import ast

        path_id = 0

        # Expanded list of dangerous sinks
        dangerous_sinks = {
            "eval",
            "exec",
            "system",
            "popen",
            "subprocess.call",
            "subprocess.run",
            "os.system",
            "pickle.loads",
            "yaml.load",
        }

        # Recursive visitor
        class PathVisitor(ast.NodeVisitor):
            def __init__(self, parent_constraints=None):
                self.current_constraints = parent_constraints or []
                self.found_paths = []

            def visit_If(self, node):
                # Branch TRUE
                constraint_true = SymbolicExecutor._extract_constraint(node.test)
                if constraint_true:
                    # Explore TRUE branch
                    visitor_true = PathVisitor(
                        self.current_constraints + [constraint_true]
                    )
                    for child in node.body:
                        visitor_true.visit(child)
                    self.found_paths.extend(visitor_true.found_paths)

                    # Explore FALSE branch (Else)
                    # Note: Inverting constraints is complex without Z3, simplifying for now
                    if node.orelse:
                        visitor_false = PathVisitor(
                            self.current_constraints
                        )  # Omitted inversion for brevity
                        for child in node.orelse:
                            visitor_false.visit(child)
                        self.found_paths.extend(visitor_false.found_paths)

            def visit_Call(self, node):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # Check for qualified names (e.g. os.system)
                # ... simple check for now ...

                if func_name in dangerous_sinks:
                    nonlocal path_id
                    path_id += 1
                    self.found_paths.append(
                        ExecutionPath(
                            path_id=path_id,
                            constraints=self.current_constraints,
                            reaches_sink=True,
                            sink_name=func_name,
                        )
                    )
                self.generic_visit(node)

        visitor = PathVisitor()
        visitor.visit(func_node)
        return visitor.found_paths

    @staticmethod
    def _extract_constraint(test_node) -> PathConstraint | None:
        """Extract constraint from AST comparison node"""
        import ast

        if isinstance(test_node, ast.Compare):
            try:
                left = test_node.left
                var_name = left.id if isinstance(left, ast.Name) else "unknown"

                op = test_node.ops[0]
                op_str = {
                    ast.Eq: "==",
                    ast.NotEq: "!=",
                    ast.Lt: "<",
                    ast.Gt: ">",
                    ast.LtE: "<=",
                    ast.GtE: ">=",
                }.get(type(op), "?")

                right = test_node.comparators[0]
                value = right.value if isinstance(right, ast.Constant) else "?"

                return PathConstraint(var_name, op_str, value)
            except Exception as e:
                logger.debug(f"Failed to extract constraint: {e}")

        return None

    def solve_constraints(self, path: ExecutionPath) -> dict[str, Any] | None:
        """
        Use Z3 to find concrete inputs satisfying path constraints.
        """
        if not self.z3_available:
            # Heuristic fallback
            return self._heuristic_solve(path)

        try:
            import z3

            solver = z3.Solver()
            variables = {}

            for constraint in path.constraints:
                # Type inference: Detect if variable should be BitVec (binary) or Int
                if constraint.variable not in variables:
                    # Defaulting to 64-bit BitVec for binary analysis simulations
                    variables[constraint.variable] = z3.BitVec(constraint.variable, 64)

                var = variables[constraint.variable]
                val = constraint.value

                # Ensure value is compatible
                if isinstance(val, int):
                    z3_val = z3.BitVecVal(val, 64)
                elif isinstance(val, str):
                    # Simple string to int conversion for basic symbolic exec
                    z3_val = z3.BitVecVal(int.from_bytes(val.encode(), "big"), 64)
                else:
                    z3_val = z3.BitVecVal(0, 64)

                if constraint.operator == "==":
                    solver.add(var == z3_val)
                elif constraint.operator == "!=":
                    solver.add(var != z3_val)
                elif constraint.operator == "<":
                    solver.add(z3.ULT(var, z3_val))  # Unsigned Less Than
                elif constraint.operator == ">":
                    solver.add(z3.UGT(var, z3_val))  # Unsigned Greater Than

            if solver.check() == z3.sat:
                model = solver.model()
                return {str(v): model[variables[v]].as_long() for v in variables}

        except Exception as e:
            logger.error(f"Z3 solving failed: {e}")

        return None

    @staticmethod
    def _heuristic_solve(path: ExecutionPath) -> dict[str, Any]:
        """Fallback solver without Z3"""
        result = {}
        for c in path.constraints:
            if c.operator == "==":
                result[c.variable] = c.value
            elif c.operator == ">":
                result[c.variable] = c.value + 1
            elif c.operator == "<":
                result[c.variable] = c.value - 1
            else:
                result[c.variable] = 0
        return result
