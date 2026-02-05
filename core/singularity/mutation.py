"""DRAKBEN Singularity - Mutation Engine
Author: @drak_ben
Description: Polymorphic code rewriting logic for evasion (AV/WAF Bypass).
"""

import ast
import hashlib
import logging
import secrets
from typing import Any

from .base import IMutationEngine, MutationResult

# Late imports inside methods to prevent circular dependency
# from core.security.ghost_protocol import get_ghost_protocol

logger = logging.getLogger(__name__)


class MutationEngine(IMutationEngine):
    """Applies genetic mutation strategies to code payloads.
    Goal: Change the signature (Hash/AST) while preserving functionality.

    Strategies:
    - variable_renaming: Rename all variables to random names
    - dead_code_injection: Insert no-op code blocks
    - junk_loops: Add loops that do nothing
    - string_encryption: XOR encode strings with runtime decode
    - instruction_substitution: Replace operations with equivalents
    """

    def __init__(self) -> None:
        self.strategies = [
            "variable_renaming",
            "dead_code_injection",
            "junk_loops",
            "string_encryption",
            "instruction_substitution",
        ]
        self._var_counter = 0
        logger.info("Mutation Engine initialized with %s strategies", len(self.strategies))

    def mutate(self, payload: str, strategies: list[str] | None = None) -> MutationResult:
        """Apply mutation strategies to transform code.

        Args:
            payload: Original source code
            strategies: Specific strategies to apply (default: all)

        Returns:
            MutationResult with mutated code and metadata

        """
        try:
            # Calculate original hash
            orig_hash = hashlib.sha256(payload.encode()).hexdigest()

            # Select strategies
            selected_strategies = strategies or self._select_strategies()
            logger.debug("Applying strategies: %s", selected_strategies)

            mutated_code = payload
            applied_mutations: list[str] = []

            # Apply selected strategies
            for strategy in selected_strategies:
                try:
                    mutated_code = self._apply_strategy(mutated_code, strategy)
                    applied_mutations.append(strategy)
                except Exception as e:
                    logger.debug("Strategy %s failed: %s", strategy, e)

            # Also apply Ghost Protocol obfuscation if available
            try:
                from core.security.ghost_protocol import get_ghost_protocol
                ghost = get_ghost_protocol()
                mutated_code = ghost.obfuscate_code(mutated_code)
                applied_mutations.append("ghost_protocol")
            except ImportError:
                logger.debug("Ghost Protocol not available")
            except Exception as e:
                logger.debug("Ghost Protocol obfuscation failed: %s", e)

            # Calculate new hash
            new_hash = hashlib.sha256(mutated_code.encode()).hexdigest()

            return MutationResult(
                original_hash=orig_hash,
                new_hash=new_hash,
                success=orig_hash != new_hash,  # Success if hash changed
                bypassed_engines=self._estimate_bypassed_engines(applied_mutations),
                mutated_code=mutated_code,  # Store actual mutated code
                applied_strategies=applied_mutations,
            )

        except Exception as e:
            logger.exception("Mutation failed: %s", e)
            return MutationResult("", "", False, [], "", [])

    def _select_strategies(self) -> list[str]:
        """Randomly select 2-4 strategies to apply."""
        num_strategies = secrets.randbelow(3) + 2  # 2-4 strategies
        return secrets.SystemRandom().sample(self.strategies, min(num_strategies, len(self.strategies)))

    def _apply_strategy(self, code: str, strategy: str) -> str:
        """Apply a specific mutation strategy."""
        strategy_map = {
            "variable_renaming": self._rename_variables,
            "dead_code_injection": self._inject_dead_code,
            "junk_loops": self._inject_junk_loops,
            "string_encryption": self._encrypt_strings,
            "instruction_substitution": self._substitute_instructions,
        }

        handler = strategy_map.get(strategy)
        if handler:
            return handler(code)
        return code

    def _rename_variables(self, code: str) -> str:
        """Rename all local variables to random names."""
        try:
            tree = ast.parse(code)
            transformer = VariableRenamer()
            new_tree = transformer.visit(tree)
            ast.fix_missing_locations(new_tree)
            return ast.unparse(new_tree)
        except Exception:
            return code

    def _inject_dead_code(self, code: str) -> str:
        """Inject dead code blocks that never execute."""
        dead_code_templates = [
            "\nif False:\n    _unused = 'never runs'\n",
            "\n_dead_var_{id} = None\n",
            "\n# Checksum: {hash}\n",
        ]

        template = secrets.choice(dead_code_templates)
        dead_code = template.format(
            id=secrets.token_hex(4),
            hash=secrets.token_hex(16),
        )

        # Insert at random line
        lines = code.split('\n')
        if len(lines) > 1:
            insert_pos = secrets.randbelow(len(lines) - 1) + 1
            lines.insert(insert_pos, dead_code)
            return '\n'.join(lines)
        return code + dead_code

    def _inject_junk_loops(self, code: str) -> str:
        """Inject loops that do nothing meaningful."""
        junk_loop = f"""
_junk_{secrets.token_hex(4)} = 0
for _i_{secrets.token_hex(2)} in range(0):
    _junk_{secrets.token_hex(4)} += 1
"""
        # Insert after imports
        lines = code.split('\n')
        insert_pos = 0
        for i, line in enumerate(lines):
            if not line.startswith(('import ', 'from ', '#', '"""', "'''")):
                if line.strip():
                    insert_pos = i
                    break

        lines.insert(insert_pos, junk_loop)
        return '\n'.join(lines)

    def _encrypt_strings(self, code: str) -> str:
        """Replace string literals with XOR-encoded versions.

        WARNING: XOR encoding is NOT cryptographically secure.
        This is for signature evasion only, not data protection.
        """
        try:
            tree = ast.parse(code)
            transformer = StringEncryptor()
            new_tree = transformer.visit(tree)
            ast.fix_missing_locations(new_tree)

            # Add decryption helper at the start
            decryptor = '''
def _xd(s, k):
    """XOR decode - NOT secure, for signature evasion only."""
    return "".join(chr(ord(c) ^ k) for c in s)
'''
            return decryptor + ast.unparse(new_tree)
        except Exception:
            return code

    def _substitute_instructions(self, code: str) -> str:
        """Replace operations with equivalent alternatives."""
        substitutions = [
            # a + b -> a - (-b)
            (' + ', ' - (-'),
            # a == b -> not (a != b)
            (' == ', ' != '),
            # True -> (1 == 1)
            ('True', '(1 == 1)'),
            ('False', '(1 == 0)'),
        ]

        # Apply one random substitution
        if substitutions:
            old, new = secrets.choice(substitutions)
            if old in code:
                # Only replace first occurrence to avoid breaking code
                code = code.replace(old, new, 1)

        return code

    def _estimate_bypassed_engines(self, applied: list[str]) -> list[str]:
        """Estimate which detection engines might be bypassed."""
        bypassed = []

        if "variable_renaming" in applied or "ghost_protocol" in applied:
            bypassed.append("signature_check")
            bypassed.append("static_analysis")

        if "string_encryption" in applied:
            bypassed.append("string_matching")

        if "dead_code_injection" in applied or "junk_loops" in applied:
            bypassed.append("hash_matching")
            bypassed.append("ast_fingerprint")

        if "instruction_substitution" in applied:
            bypassed.append("pattern_matching")

        return bypassed

    def generate_variant(self, payload: str, iterations: int = 1) -> str:
        """Generate a variant by applying multiple mutation passes.

        Args:
            payload: Original code
            iterations: Number of mutation passes

        Returns:
            Mutated code after all iterations
        """
        current_code = payload
        for i in range(iterations):
            result = self.mutate(current_code)
            if result.success and result.mutated_code:
                current_code = result.mutated_code
                logger.debug("Iteration %s: hash changed from %s to %s",
                           i + 1, result.original_hash[:8], result.new_hash[:8])

        return current_code


class VariableRenamer(ast.NodeTransformer):
    """AST transformer that renames local variables."""

    def __init__(self) -> None:
        self.var_map: dict[str, str] = {}
        self.counter = 0
        # Don't rename these
        self.preserved = {'self', 'cls', 'args', 'kwargs', 'True', 'False', 'None'}

    def _get_new_name(self, old_name: str) -> str:
        """Generate a new random variable name."""
        if old_name in self.preserved:
            return old_name
        if old_name not in self.var_map:
            # Generate obfuscated name like _0x1a2b
            self.var_map[old_name] = f"_0x{secrets.token_hex(2)}"
        return self.var_map[old_name]

    def visit_Name(self, node: ast.Name) -> ast.Name:
        """Rename variable references."""
        if isinstance(node.ctx, ast.Store | ast.Load):
            node.id = self._get_new_name(node.id)
        return node

    def visit_arg(self, node: ast.arg) -> ast.arg:
        """Rename function arguments."""
        node.arg = self._get_new_name(node.arg)
        return node


class StringEncryptor(ast.NodeTransformer):
    """AST transformer that XOR-encodes string literals.

    WARNING: XOR encoding is NOT cryptographically secure.
    Used for signature evasion only.
    """

    def __init__(self) -> None:
        self.key = secrets.randbelow(200) + 50  # Random key 50-249

    def visit_Constant(self, node: ast.Constant) -> Any:
        """Encrypt string constants."""
        if isinstance(node.value, str) and len(node.value) > 3:
            # XOR encode the string
            encoded = "".join(chr(ord(c) ^ self.key) for c in node.value)
            # Return call to decoder: _xd("encoded", key)
            return ast.Call(
                func=ast.Name(id='_xd', ctx=ast.Load()),
                args=[
                    ast.Constant(value=encoded),
                    ast.Constant(value=self.key),
                ],
                keywords=[],
            )
        return node
