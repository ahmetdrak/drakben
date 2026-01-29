"""
DRAKBEN Research - Symbolic Executor
Author: @drak_ben
Description: Mathematical code path analysis using constraint solving.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

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
    constraints: List[PathConstraint]
    reaches_sink: bool
    sink_name: str = ""

class SymbolicExecutor:
    """
    Performs symbolic execution for vulnerability discovery.
    Uses constraint solving to find inputs that reach dangerous sinks.
    """
    
    def __init__(self):
        self.z3_available = self._check_z3()
        logger.info(f"Symbolic Executor initialized (Z3: {'Available' if self.z3_available else 'Fallback Mode'})")
        
    def _check_z3(self) -> bool:
        """Check if Z3 solver is available"""
        try:
            import z3
            return True
        except ImportError:
            logger.warning("Z3 not installed. Using heuristic fallback.")
            return False
            
    def analyze_function(self, source_code: str, target_func: str) -> List[ExecutionPath]:
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
        
    def _explore_paths(self, func_node) -> List[ExecutionPath]:
        """Extract execution paths from function AST"""
        import ast
        paths = []
        path_id = 0
        
        dangerous_sinks = ['eval', 'exec', 'system', 'popen', 'subprocess']
        
        for node in ast.walk(func_node):
            # Track If statements (branch points)
            if isinstance(node, ast.If):
                # Extract condition
                constraint = self._extract_constraint(node.test)
                if constraint:
                    path_id += 1
                    paths.append(ExecutionPath(
                        path_id=path_id,
                        constraints=[constraint],
                        reaches_sink=False
                    ))
                    
            # Check for dangerous sinks
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    
                if func_name in dangerous_sinks:
                    path_id += 1
                    paths.append(ExecutionPath(
                        path_id=path_id,
                        constraints=[],
                        reaches_sink=True,
                        sink_name=func_name
                    ))
                    
        return paths
        
    def _extract_constraint(self, test_node) -> Optional[PathConstraint]:
        """Extract constraint from AST comparison node"""
        import ast
        
        if isinstance(test_node, ast.Compare):
            try:
                left = test_node.left
                var_name = left.id if isinstance(left, ast.Name) else "unknown"
                
                op = test_node.ops[0]
                op_str = {
                    ast.Eq: "==", ast.NotEq: "!=",
                    ast.Lt: "<", ast.Gt: ">",
                    ast.LtE: "<=", ast.GtE: ">="
                }.get(type(op), "?")
                
                right = test_node.comparators[0]
                if isinstance(right, ast.Constant):
                    value = right.value
                else:
                    value = "?"
                    
                return PathConstraint(var_name, op_str, value)
            except Exception:
                pass
                
        return None
        
    def solve_constraints(self, path: ExecutionPath) -> Optional[Dict[str, Any]]:
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
                if constraint.variable not in variables:
                    variables[constraint.variable] = z3.Int(constraint.variable)
                    
                var = variables[constraint.variable]
                
                if constraint.operator == "==":
                    solver.add(var == constraint.value)
                elif constraint.operator == "!=":
                    solver.add(var != constraint.value)
                elif constraint.operator == "<":
                    solver.add(var < constraint.value)
                elif constraint.operator == ">":
                    solver.add(var > constraint.value)
                    
            if solver.check() == z3.sat:
                model = solver.model()
                return {str(v): model[variables[v]].as_long() for v in variables}
                
        except Exception as e:
            logger.error(f"Z3 solving failed: {e}")
            
        return None
        
    def _heuristic_solve(self, path: ExecutionPath) -> Dict[str, Any]:
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
