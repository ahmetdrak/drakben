"""DRAKBEN Ghost Protocol - Polymorphic Engine & Anti-Detection
Author: @drak_ben
Description: Code obfuscation and evasion techniques for stealth operations.

This module provides:
- AST-based code transformation
- Variable name obfuscation
- Dead code injection
- String encryption
- Anti-signature techniques
"""

import ast
import base64
import logging
import os
import random
import secrets
import string
import threading
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

# Characters for obfuscated variable names
OBFUSCATION_CHARS = string.ascii_letters + "_"

# Reserved Python keywords that cannot be used as variable names
PYTHON_KEYWORDS = {
    "False",
    "None",
    "True",
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "finally",
    "for",
    "from",
    "global",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "nonlocal",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "try",
    "while",
    "with",
    "yield",
}

# Built-in names that should not be obfuscated
BUILTIN_NAMES = {
    "print",
    "len",
    "range",
    "str",
    "int",
    "float",
    "list",
    "dict",
    "set",
    "tuple",
    "bool",
    "open",
    "input",
    "type",
    "isinstance",
    "hasattr",
    "getattr",
    "setattr",
    "delattr",
    "enumerate",
    "zip",
    "map",
    "filter",
    "sorted",
    "reversed",
    "sum",
    "min",
    "max",
    "abs",
    "all",
    "any",
    "bin",
    "hex",
    "oct",
    "ord",
    "chr",
    "format",
    "repr",
    "hash",
    "id",
    "dir",
    "vars",
    "globals",
    "locals",
    "callable",
    "exec",
    "eval",
    "compile",
    "__import__",
    "Exception",
    "BaseException",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "AttributeError",
    "RuntimeError",
    "self",
    "cls",
    "args",
    "kwargs",
    "__name__",
    "__main__",
    "__init__",
    "__str__",
    "__repr__",
    "__call__",
    "__enter__",
    "__exit__",
}


# =============================================================================
# POLYMORPHIC TRANSFORMER
# =============================================================================


class PolymorphicTransformer(ast.NodeTransformer):
    """AST-based code transformer for polymorphic obfuscation.

    Transforms Python code to evade signature-based detection by:
    1. Renaming variables to random names
    2. Injecting dead code blocks
    3. Transforming loop structures
    4. Encrypting string literals

    Usage:
        transformer = PolymorphicTransformer()
        obfuscated_code = transformer.transform(original_code)
    """

    def __init__(
        self,
        obfuscate_names: bool = True,
        inject_dead_code: bool = True,
        encrypt_strings: bool = True,
        preserve_docstrings: bool = True,
    ) -> None:
        """Initialize transformer with configuration.

        Args:
            obfuscate_names: Rename variables to random names
            inject_dead_code: Add non-executing code blocks
            encrypt_strings: Encode string literals
            preserve_docstrings: Keep docstrings readable

        """
        super().__init__()
        self.obfuscate_names = obfuscate_names
        self.inject_dead_code = inject_dead_code
        self.encrypt_strings = encrypt_strings
        self.preserve_docstrings = preserve_docstrings

        # Mapping of original names to obfuscated names
        self.name_mapping: dict[str, str] = {}

        # Track function/class definitions
        self.defined_names: set[str] = set()

        # Track imported names — these must NOT be obfuscated
        self._protected_names: set[str] = set()

        # Counter for unique name generation
        self._name_counter = 0

        # Seed for reproducible obfuscation (optional)
        self._seed = int.from_bytes(secrets.token_bytes(4), "big")
        self._rng = random.Random(self._seed)  # Use local RNG to avoid global state pollution

    def transform(self, code: str) -> str:
        """Transform Python code with polymorphic obfuscation.

        Args:
            code: Original Python source code

        Returns:
            Obfuscated Python source code

        """
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            logger.exception("Syntax error in input code: %s", e)
            return code

        # First pass: collect all defined names
        self._collect_defined_names(tree)

        # Second pass: apply transformations
        transformed_tree = self.visit(tree)

        # Inject `import base64 as _b64` if string encryption is used
        if self.encrypt_strings and isinstance(transformed_tree, ast.Module):
            b64_import = ast.Import(names=[ast.alias(name="base64", asname="_b64")])
            transformed_tree.body.insert(0, b64_import)

        # Third pass: inject dead code if enabled
        if self.inject_dead_code:
            transformed_tree = self._inject_dead_code_blocks(transformed_tree)

        # Fix missing locations
        ast.fix_missing_locations(transformed_tree)

        try:
            return ast.unparse(transformed_tree)
        except Exception as e:
            logger.exception("Failed to unparse transformed AST: %s", e)
            return code

    def _collect_import_names(self, node: ast.Import | ast.ImportFrom) -> None:
        """Protect imported module/alias names from obfuscation."""
        for alias in node.names:
            name_to_protect = alias.asname or alias.name
            self._protected_names.add(name_to_protect)

    def _collect_function_names(self, node: ast.FunctionDef) -> None:
        """Collect function and argument names."""
        self.defined_names.add(node.name)
        for arg in node.args.args:
            self.defined_names.add(arg.arg)

    def _collect_defined_names(self, tree: ast.AST) -> None:
        """Collect and PROTECT imported names to prevent breakage."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                self._collect_import_names(node)
            elif isinstance(node, ast.FunctionDef):
                self._collect_function_names(node)
            elif isinstance(node, ast.ClassDef):
                self.defined_names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if node.id not in BUILTIN_NAMES:
                    self.defined_names.add(node.id)
            elif isinstance(node, ast.arg):
                self.defined_names.add(node.arg)

    def _generate_obfuscated_name(self) -> str:
        """Generate a random obfuscated variable name."""
        self._name_counter += 1

        # Generate a name like _x7a3b2c1_ (underscore prefixed and suffixed)
        random_part = "".join(secrets.choice(OBFUSCATION_CHARS) for _ in range(8))
        name = f"_{random_part}{self._name_counter}_"

        # Ensure it's not a keyword
        while name in PYTHON_KEYWORDS:
            random_part = "".join(secrets.choice(OBFUSCATION_CHARS) for _ in range(8))
            name = f"_{random_part}{self._name_counter}_"

        return name

    def _get_obfuscated_name(self, original: str) -> str:
        """Get or create obfuscated name for an original name."""
        if original in PYTHON_KEYWORDS or original in BUILTIN_NAMES:
            return original

        if original in self._protected_names:
            return original  # Never rename imported module names

        if original.startswith("__") and original.endswith("__"):
            return original  # Preserve dunder methods

        if original not in self.name_mapping:
            self.name_mapping[original] = self._generate_obfuscated_name()

        return self.name_mapping[original]

    def visit_Name(self, node: ast.Name) -> ast.AST:  # pylint: disable=invalid-name
        """Transform variable names."""
        if self.obfuscate_names and node.id in self.defined_names:
            node.id = self._get_obfuscated_name(node.id)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:  # pylint: disable=invalid-name
        """Transform function definitions."""
        has_docstring = (
            self.preserve_docstrings
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        )

        saved_docstring = None
        if has_docstring:
            saved_docstring = node.body[0]
            node.body = node.body[1:]

        self._obfuscate_func_name(node)
        self._obfuscate_func_args(node)

        node = self.generic_visit(node)  # type: ignore[assignment]

        if saved_docstring is not None:
            node.body.insert(0, saved_docstring)

        return node  # type: ignore[return-value]

    def _obfuscate_func_name(self, node: ast.FunctionDef) -> None:
        """Obfuscate function name if applicable."""
        if self.obfuscate_names and not node.name.startswith("__") and node.name not in ("main", "run"):
            node.name = self._get_obfuscated_name(node.name)

    def _obfuscate_func_args(self, node: ast.FunctionDef) -> None:
        """Obfuscate function argument names."""
        if self.obfuscate_names:
            for arg in node.args.args:
                if arg.arg not in ("self", "cls"):
                    arg.arg = self._get_obfuscated_name(arg.arg)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:  # pylint: disable=invalid-name
        """Transform class definitions."""
        # Obfuscate class name
        if self.obfuscate_names and not node.name.startswith("_"):
            node.name = self._get_obfuscated_name(node.name)

        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_Constant(self, node: ast.Constant) -> ast.AST:  # pylint: disable=invalid-name
        """Transform string constants (encryption) - Python 3.8+."""
        if (
            self.encrypt_strings
            and isinstance(node.value, str)
            and len(node.value) > 3
            and not node.value.startswith("__")
        ):
            # Skip docstrings (handled separately)
            return self._create_encrypted_string(node.value)

        return node

    def _create_encrypted_string(self, value: str) -> ast.Call:
        """Create an encrypted string expression."""
        # Base64 encode the string
        encoded = base64.b64encode(value.encode()).decode()

        # H-2 FIX: Use pre-imported base64 reference instead of __import__
        # Create: _b64.b64decode('encoded').decode()
        return ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="_b64", ctx=ast.Load()),
                        attr="b64decode",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value=encoded)],
                    keywords=[],
                ),
                attr="decode",
                ctx=ast.Load(),
            ),
            args=[],
            keywords=[],
        )

    def _generate_dynamic_dead_code(self) -> ast.If:
        """LOGIC FIX: Generate a random, unique dead code block to avoid signatures."""
        var_name = self._generate_obfuscated_name()
        val1 = secrets.randbelow(1000)
        val2 = val1 + secrets.randbelow(1000) + 1  # val2 is always > val1

        # if val1 > val2: (Always False)
        return ast.If(
            test=ast.Compare(
                left=ast.Constant(value=val1),
                ops=[ast.Gt()],
                comparators=[ast.Constant(value=val2)],
            ),
            body=[
                ast.Assign(
                    targets=[ast.Name(id=var_name, ctx=ast.Store())],
                    value=ast.Constant(value=secrets.randbelow(9999)),
                ),
                ast.Pass(),
            ],
            orelse=[],
        )

    def _inject_dead_code_blocks(self, tree: ast.Module) -> ast.Module:
        """Inject random dead code blocks at random positions."""
        new_body = []
        for i, node in enumerate(tree.body):
            new_body.append(node)
            # M-2 FIX: Skip injection before decorated functions/classes
            next_node = tree.body[i + 1] if i + 1 < len(tree.body) else None
            has_decorators = (
                next_node is not None
                and isinstance(next_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and getattr(next_node, "decorator_list", [])
            )
            # LOGIC FIX: 20% chance to inject a COMPLETELY UNIQUE dead code block
            if not has_decorators and secrets.randbelow(100) < 20:
                new_body.append(self._generate_dynamic_dead_code())

        tree.body = new_body
        return tree


# =============================================================================
# STRING ENCRYPTION UTILITIES
# =============================================================================


class StringEncryptor:
    """Utility class for string encryption/decryption.

    Provides multiple encoding methods for evading string-based signatures.
    WARNING: These are ENCODING methods, not cryptographically secure encryption.
    Use AES-GCM from CredentialStore for real encryption needs.
    """

    @staticmethod
    def xor_encode(text: str, key: str = "drakben") -> str:
        """XOR encode a string for obfuscation (NOT cryptographically secure).

        WARNING: This is simple obfuscation, not encryption.
        Do NOT use for protecting sensitive data.
        For real encryption, use CredentialStore with AES-GCM.
        """
        result = []
        for i, char in enumerate(text):
            result.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return base64.b64encode("".join(result).encode("latin-1")).decode()

    # Alias for backward compatibility
    xor_encrypt = xor_encode

    @staticmethod
    def xor_decode(encoded: str, key: str = "drakben") -> str:
        """XOR decode a string (NOT cryptographically secure)."""
        try:
            decoded = base64.b64decode(encoded).decode("latin-1")
            result = []
            for i, char in enumerate(decoded):
                result.append(chr(ord(char) ^ ord(key[i % len(key)])))
            return "".join(result)
        except ValueError as e:
            logger.debug("XOR decode failed: %s", e)
            return encoded

    # Alias for backward compatibility
    xor_decrypt = xor_decode

    @staticmethod
    def rot13(text: str) -> str:
        """Apply ROT13 encoding (simple obfuscation, NOT encryption)."""
        return text.translate(
            str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            ),
        )

    @staticmethod
    def chunk_and_join(text: str) -> tuple[list[str], str]:
        """Split string into chunks for concatenation."""
        chunk_size = secrets.randbelow(4) + 2  # Generates 2, 3, 4, 5
        chunks = [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]
        var_names = [f"_s{i}_" for i in range(len(chunks))]
        return chunks, " + ".join(var_names)


# =============================================================================
# SECURE MEMORY & ANTI-FORENSICS
# =============================================================================


class SecureCleanup:
    """Secure deletion and anti-forensics utilities.

    Provides methods for:
    - Secure file deletion (DoD 5220.22-M standard)
    - Memory wiping
    - Timestamp manipulation
    """

    @staticmethod
    def secure_delete(filepath: str, passes: int = 3) -> bool:
        """Securely delete a file with multiple overwrite passes.

        Args:
            filepath: Path to file to delete
            passes: Number of overwrite passes (default: 3)

        Returns:
            True if successfully deleted

        """
        if not os.path.exists(filepath):
            return True

        try:
            file_size = os.path.getsize(filepath)

            with open(filepath, "r+b") as f:
                for pass_num in range(passes):
                    f.seek(0)
                    if pass_num % 3 == 0:
                        # Pass 1: All zeros
                        f.write(b"\x00" * file_size)
                    elif pass_num % 3 == 1:
                        # Pass 2: All ones
                        f.write(b"\xff" * file_size)
                    else:
                        # Pass 3: Random data
                        f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            os.remove(filepath)
            logger.debug("Securely deleted: %s", filepath)
            return True

        except OSError:
            logger.exception("Secure delete failed for %s", filepath)
            return False


# =============================================================================
# GHOST PROTOCOL MANAGER
# =============================================================================


class GhostProtocol:
    """Main interface for Ghost Protocol features.

    Combines polymorphic transformation, encryption, and anti-forensics
    into a single easy-to-use interface.

    Usage:
        ghost = GhostProtocol()
        stealthy_code = ghost.obfuscate_code(original_code)
        ghost.secure_cleanup("temp_file.py")
    """

    def __init__(
        self,
        enable_obfuscation: bool = True,
        enable_encryption: bool = True,
        enable_dead_code: bool = True,
    ) -> None:
        """Initialize Ghost Protocol.

        Args:
            enable_obfuscation: Enable name obfuscation
            enable_encryption: Enable string encryption
            enable_dead_code: Enable dead code injection

        """
        self.transformer = PolymorphicTransformer(
            obfuscate_names=enable_obfuscation,
            encrypt_strings=enable_encryption,
            inject_dead_code=enable_dead_code,
        )
        self.encryptor = StringEncryptor()
        self.cleanup = SecureCleanup()

        logger.info("Ghost Protocol initialized")

    def obfuscate_code(self, code: str) -> str:
        """Apply full obfuscation pipeline to code.

        Args:
            code: Original Python source code

        Returns:
            Obfuscated code

        """
        return self.transformer.transform(code)

    def encrypt_string(self, text: str, method: str = "xor") -> str:
        """Encrypt a string using specified method.

        Args:
            text: String to encrypt
            method: Encryption method ("xor", "base64", "rot13")

        Returns:
            Encrypted string

        """
        if method == "xor":
            return self.encryptor.xor_encrypt(text)
        if method == "base64":
            return base64.b64encode(text.encode()).decode()
        if method == "rot13":
            return self.encryptor.rot13(text)
        return text

    def decrypt_string(self, text: str, method: str = "xor") -> str:
        """Decrypt a string using specified method.

        Args:
            text: Encrypted string
            method: Decryption method

        Returns:
            Decrypted string

        """
        if method == "xor":
            return self.encryptor.xor_decrypt(text)
        if method == "base64":
            try:
                return base64.b64decode(text).decode()
            except ValueError:
                return text
        elif method == "rot13":
            return self.encryptor.rot13(text)  # ROT13 is self-inverse
        else:
            return text

    def secure_delete_file(self, filepath: str) -> bool:
        """Securely delete a file."""
        return self.cleanup.secure_delete(filepath)

    def cleanup_session(self, files: list[str]) -> int:
        """Clean up all session files securely.

        Args:
            files: List of file paths to delete

        Returns:
            Number of files successfully deleted

        """
        deleted = 0
        for filepath in files:
            if self.secure_delete_file(filepath):
                deleted += 1
        return deleted


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================


def obfuscate(code: str) -> str:
    """Quick-access function to obfuscate code.

    Args:
        code: Python source code

    Returns:
        Obfuscated code

    """
    transformer = PolymorphicTransformer()
    return transformer.transform(code)


# Singleton with thread safety
_ghost_protocol = None  # pylint: disable=invalid-name
_ghost_protocol_lock = threading.Lock()


def get_ghost_protocol() -> GhostProtocol:
    """Get singleton GhostProtocol instance (thread-safe).

    Returns:
        GhostProtocol instance

    """
    global _ghost_protocol  # pylint: disable=global-statement
    if _ghost_protocol is None:
        with _ghost_protocol_lock:
            if _ghost_protocol is None:
                _ghost_protocol = GhostProtocol()
    return _ghost_protocol


class SecureMemory:
    """Secure memory handling and cleanup.

    Provides:
    - Secure variable wiping
    - Memory buffer overwriting
    - Python object cleanup
    - Garbage collection forcing
    """

    @staticmethod
    def secure_wipe_bytes(data: bytearray) -> None:
        """Securely wipe a bytearray in place.

        Args:
            data: Bytearray to wipe

        """
        for i in range(len(data)):
            data[i] = 0

    @staticmethod
    def secure_wipe_string_buffer(buffer_id: int, length: int) -> bool:
        """Attempt to wipe a string buffer at given memory address.

        .. warning:: **SECURITY LIMITATION — NOT RELIABLE**

            Python strings are *immutable*. The interpreter may have already
            copied the content to other memory locations (interning, GC
            compaction, OS page cache). ``ctypes.memset`` only overwrites the
            *original* buffer — copies persist. This method provides **defense
            in depth** but MUST NOT be relied upon as the sole protection for
            secrets. Use ``bytearray`` + ``secure_wipe_bytes()`` for sensitive
            data that truly needs to be scrubbed.

        Args:
            buffer_id: Memory address (from id())
            length: Length of buffer

        Returns:
            True if wipe attempted (NOT a guarantee of erasure)

        """
        try:
            import ctypes
            import sys as _sys

            # Compute CPython string object header size dynamically
            # Use the difference between sizes of 1-char and 0-char strings
            # to validate our header size estimate
            header_size = _sys.getsizeof("")
            if header_size < 32 or header_size > 128:
                header_size = 49  # Common CPython 3.12+ compact ASCII header

            # Safety check: don't write beyond reasonable bounds
            if length <= 0 or length > 10_000_000:
                return False

            ctypes.memset(buffer_id + header_size, 0, length)
            return True
        except (OSError, ValueError, TypeError) as e:
            logger.debug("Memory wipe failed: %s", e)
            return False

    @staticmethod
    def clear_dict_secure(d: dict[str, Any]) -> None:
        """Securely clear a dictionary by overwriting values first.

        Args:
            d: Dictionary to clear

        """
        for key in list(d.keys()):
            if isinstance(d[key], str | bytes | bytearray):
                # Overwrite value
                d[key] = None
            del d[key]


# =============================================================================
# SECURE MEMORY - RAM Cleanup Module (Stateful Extension)
# =============================================================================


class RAMCleaner:
    """Stateful memory manager for trakcing and wiping sensitive data.
    Works alongside the static SecureMemory utilities.
    """

    def __init__(self) -> None:
        self._sensitive_refs: list[bytearray] = []
        logger.info("RAMCleaner initialized")

    def register_sensitive(self, data: str) -> None:
        """Register sensitive string for later wiping.
        Converts string to mutable bytearray and tracks it.
        """
        if not data:
            return
        # Create a mutable bytearray copy of the data
        ba = bytearray(data.encode("utf-8"))
        self._sensitive_refs.append(ba)

    def wipe_all(self) -> int:
        """Wipe all registered sensitive data from memory.

        Returns:
            Number of buffers wiped.
        """
        count = 0
        for ba in self._sensitive_refs:
            for i in range(len(ba)):
                ba[i] = 0
            count += 1
        self._sensitive_refs.clear()
        # Force garbage collection to help reclaim memory
        import gc

        gc.collect()
        logger.info("RAMCleaner: Wiped %d sensitive buffers", count)
        return count

    def __del__(self) -> None:
        """Wipe on destruction."""
        try:
            self.wipe_all()
        except (OSError, RuntimeError):
            pass  # Destructor: logger may be unavailable during GC


# Singleton
_ram_cleaner = None  # pylint: disable=invalid-name
_ram_cleaner_lock = threading.Lock()


def get_ram_cleaner() -> RAMCleaner:
    """Get singleton RAMCleaner instance."""
    global _ram_cleaner  # pylint: disable=global-statement
    if _ram_cleaner is None:
        with _ram_cleaner_lock:
            if _ram_cleaner is None:
                _ram_cleaner = RAMCleaner()
    return _ram_cleaner
